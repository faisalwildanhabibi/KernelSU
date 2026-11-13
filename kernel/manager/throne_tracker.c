#include "ksu.h"
#include "linux/cred.h"
#include "linux/namei.h"
#include "util.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "policy/allowlist.h"
#include "manager/apk_sign.h"
#include "feature/dynamic_manager.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"

static DEFINE_MUTEX(throne_tracker_mutex);

#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk
#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list"

struct uid_data {
    struct list_head list;
    u32 uid;
    char package[KSU_MAX_PACKAGE_NAME];
};

static void crown_manager(const char *apk, struct list_head *uid_data, u8 sig_index)
{
    struct list_head *list = (struct list_head *)uid_data;
    struct uid_data *np;
    char pkg[KSU_MAX_PACKAGE_NAME];

    if (get_pkg_from_apk_path(pkg, apk) < 0 && get_pkg_from_apk_dir_path(pkg, apk) < 0) {
        pr_err("Failed to get package name from apk dir path: %s\n", apk);
        return;
    }

    list_for_each_entry (np, list, list) {
        if (strncmp(np->package, pkg, KSU_MAX_PACKAGE_NAME) == 0) {
            pr_info("Crowning manager: %s uid=%d, sig_index=%d\n", pkg, np->uid, sig_index);
            ksu_register_manager(np->uid, sig_index);
            break;
        }
    }
}

struct data_path {
    char dirpath[DATA_PATH_LEN];
    int depth;
    struct list_head list;
};

struct my_dir_context {
    struct dir_context ctx;
    struct list_head *data_path_list;
    char *parent_dir;
    void *private_data;
    int depth;
};

// https://docs.kernel.org/filesystems/porting.html
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

static FILLDIR_RETURN_TYPE my_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino,
                                    unsigned int d_type)
{
    struct my_dir_context *my_ctx = container_of(ctx, struct my_dir_context, ctx);

    // we put the apk path we collected here
    char *candidate_path = (char *)my_ctx->private_data;

    char dirpath[DATA_PATH_LEN];

    if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
        return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

    if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) && !strncmp(name + namelen - 4, ".tmp", 4)) {
        pr_info("Skipping directory: %.*s\n", namelen, name);
        return FILLDIR_ACTOR_CONTINUE; // Skip staging package
    }

    if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen, name) >= DATA_PATH_LEN) {
        pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen, name);
        return FILLDIR_ACTOR_CONTINUE;
    }

    if (d_type == DT_DIR && my_ctx->depth > 0) {
        struct data_path *data = kzalloc(sizeof(struct data_path), GFP_KERNEL);

        if (!data) {
            pr_err("Failed to allocate memory for %s\n", dirpath);
            return FILLDIR_ACTOR_CONTINUE;
        }

        strscpy(data->dirpath, dirpath, DATA_PATH_LEN);
        data->depth = my_ctx->depth - 1;
        list_add_tail(&data->list, my_ctx->data_path_list);

        return FILLDIR_ACTOR_CONTINUE;
    }

    // now put this on candidate_path
    if (d_type == DT_REG && namelen == 8 && !memcmp(name, "base.apk", 8)) {
        snprintf(candidate_path, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen, name);
    }

    return FILLDIR_ACTOR_CONTINUE;
}

static void search_manager(const char *path, int depth, struct list_head *uid_data)
{
    int i;
    struct list_head data_path_list;
    INIT_LIST_HEAD(&data_path_list);
    unsigned long data_app_magic = 0;

    // First depth
    struct data_path data;
    strscpy(data.dirpath, path, DATA_PATH_LEN);
    data.depth = depth;
    list_add_tail(&data.list, &data_path_list);

    // we put the apk path we collected here
    char candidate_path[DATA_PATH_LEN];

    for (i = depth; i >= 0; i--) {
        struct data_path *pos, *n;

        list_for_each_entry_safe (pos, n, &data_path_list, list) {
            candidate_path[0] = 0;
            struct my_dir_context ctx = { .ctx.actor = my_actor,
                                          .data_path_list = &data_path_list,
                                          .parent_dir = pos->dirpath,
                                          .private_data = candidate_path,
                                          .depth = pos->depth };
            struct file *file = ksu_filp_open_nonotify(pos->dirpath, O_RDONLY | O_NOFOLLOW | O_NOATIME | O_DIRECTORY);
            if (IS_ERR(file)) {
                pr_err("Failed to open directory: %s, err: %ld\n", pos->dirpath, PTR_ERR(file));
                goto skip_iterate;
            }

            // grab magic on first folder, which is /data/app
            if (!data_app_magic) {
                if (file->f_inode->i_sb->s_magic) {
                    data_app_magic = file->f_inode->i_sb->s_magic;
                    pr_info("%s: dir: %s got magic! 0x%lx\n", __func__, pos->dirpath, data_app_magic);
                } else {
                    filp_close(file, NULL);
                    goto skip_iterate;
                }
            }

            if (file->f_inode->i_sb->s_magic != data_app_magic) {
                pr_info("%s: skip: %s magic: 0x%lx expected: 0x%lx\n", __func__, pos->dirpath,
                        file->f_inode->i_sb->s_magic, data_app_magic);
                filp_close(file, NULL);
                goto skip_iterate;
            }

            iterate_dir(file, &ctx.ctx);
            filp_close(file, NULL);

            if (!candidate_path[0])
                goto skip_iterate;

            u8 sig_index = 0;
            bool is_mgr = is_manager_apk_with_sig(candidate_path, &sig_index);
            pr_info("Found manager base.apk at path: %s, is_manager: %d, sig_index: %d\n", candidate_path, is_mgr, sig_index);

            // Only crown if signature verification pass
            if (likely(!is_mgr)) {
                candidate_path[0] = 0;
                goto skip_iterate;
            }

            crown_manager(candidate_path, uid_data, sig_index);
            candidate_path[0] = 0;

        skip_iterate:
            list_del(&pos->list);
            if (pos != &data)
                kfree(pos);
        }
    }
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
    struct list_head *list = (struct list_head *)data;
    struct uid_data *np;

    bool exist = false;
    list_for_each_entry (np, list, list) {
        if (np->uid == uid % KSU_PER_USER_RANGE && strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
            exist = true;
            break;
        }
    }
    return exist;
}

void track_throne(bool prune_only)
{
    mutex_lock(&throne_tracker_mutex);

    struct file *fp = ksu_filp_open_nonotify(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY | O_NOATIME);
    if (IS_ERR(fp)) {
        pr_err("open %s failed: %ld\n", SYSTEM_PACKAGES_LIST_PATH, PTR_ERR(fp));
        mutex_unlock(&throne_tracker_mutex);
        return;
    }

    // override cred to init_cred to avoid sepolicy denial
    const struct cred *old_cred = override_creds(ksu_get_init_cred());

    // read packages.list
    char buf[128];
    loff_t pos = 0;
    loff_t line_start = 0;
    size_t count = 0;
    char chr = 0;

    struct list_head uid_list;
    INIT_LIST_HEAD(&uid_list);

    char *tmp;
    char *package;
    char *uid;
    const char *delim = " ";
    u32 res;
    struct uid_data *data;

    while (1) {
        count = kernel_read(fp, &chr, sizeof(chr), &pos);

        if (count != sizeof(chr))
            break;
        if (chr != '\n')
            continue;

        count = kernel_read(fp, buf, sizeof(buf) - 1, &line_start);
        if (count <= 0) {
            break;
        }
        buf[count] = '\0';

        data = kzalloc(sizeof(struct uid_data), GFP_KERNEL);
        if (!data) {
            filp_close(fp, 0);
            goto out;
        }

        tmp = buf;

        package = strsep(&tmp, delim);
        uid = strsep(&tmp, delim);
        if (!uid || !package) {
            pr_err("update_uid: package or uid is NULL!\n");
            kfree(data);
            break;
        }

        if (kstrtou32(uid, 10, &res)) {
            pr_err("update_uid: uid parse err\n");
            kfree(data);
            break;
        }
        data->uid = res;
        strncpy(data->package, package, KSU_MAX_PACKAGE_NAME);
        list_add_tail(&data->list, &uid_list);

        // reset line start
        line_start = pos;
    }

    filp_close(fp, 0);

    // now update uid list
    struct uid_data *np;
    struct uid_data *n;

    if (prune_only)
        goto prune;

    ksu_unregister_all_manager();
    pr_info("Searching for manager(s)...\n");
    search_manager("/data/app", 2, &uid_list);
    pr_info("Search manager finished\n");

prune:
    // then prune the allowlist
    ksu_prune_allowlist(is_uid_exist, &uid_list);
out:
    // free uid_list
    list_for_each_entry_safe (np, n, &uid_list, list) {
        list_del(&np->list);
        kfree(np);
    }
out_revert_cred:
    revert_creds(old_cred);
    mutex_unlock(&throne_tracker_mutex);
}

void __init ksu_throne_tracker_init(void)
{
    // nothing to do
}

void __exit ksu_throne_tracker_exit(void)
{
    // nothing to do
}
