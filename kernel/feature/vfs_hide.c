#include "vfs_hide.h"
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <asm/current.h>

#include "arch.h"
#include "ksu.h"
#include "klog.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "manager/manager_identity.h"

bool ksu_vfs_hide_enabled __read_mostly = true;

static int vfs_hide_feature_get(u64 *value)
{
    *value = ksu_vfs_hide_enabled ? 1 : 0;
    return 0;
}

static int vfs_hide_feature_set(u64 value)
{
    ksu_vfs_hide_enabled = (value != 0);
    pr_info("vfs_hide: set to %d\n", ksu_vfs_hide_enabled);
    return 0;
}

static const struct ksu_feature_handler vfs_hide_handler = {
    .feature_id = KSU_FEATURE_DUAL_WORLD_HIDE,
    .name = "dual_world_hide",
    .get_handler = vfs_hide_feature_get,
    .set_handler = vfs_hide_feature_set,
};

bool ksu_is_path_hidden(const char *path, uid_t caller_uid)
{
    char pkg_name[KSU_MAX_PACKAGE_NAME];
    const char *p;
    size_t i;

    if (caller_uid < FIRST_APPLICATION_UID)
        return false;

    if (ksu_is_manager_uid(caller_uid))
        return false;

    if (ksu_is_uid_granted_root(caller_uid))
        return false;

    if (!path || !path[0])
        return false;

    // 1. Cloak root infrastructure (/data/adb, /data/adb/ksu, /data/adb/modules etc.)
    if (!strncmp(path, "/data/adb", 9))
        return true;

    // 2. Cloak /data/data/<pkg>
    if (!strncmp(path, "/data/data/", 11)) {
        p = path + 11;
        goto parse_pkg;
    }

    // 3. Cloak /data/user/<id>/<pkg>
    if (!strncmp(path, "/data/user/", 11)) {
        p = path + 11;
        while (*p && *p != '/')
            p++;
        if (*p == '/')
            p++;
        goto parse_pkg;
    }

    // 4. Cloak /data/user_de/<id>/<pkg>
    if (!strncmp(path, "/data/user_de/", 14)) {
        p = path + 14;
        while (*p && *p != '/')
            p++;
        if (*p == '/')
            p++;
        goto parse_pkg;
    }

    // 5. Cloak /data/app/<pkg>...
    if (!strncmp(path, "/data/app/", 10)) {
        if (ksu_is_manager_package_in_path(path) || ksu_is_allowlist_package_in_path(path))
            return true;
        return false;
    }

    return false;

parse_pkg:
    i = 0;
    while (*p && *p != '/' && i < sizeof(pkg_name) - 1) {
        pkg_name[i++] = *p++;
    }
    pkg_name[i] = '\0';

    if (i == 0)
        return false;

    if (ksu_is_manager_package(pkg_name))
        return true;

    if (ksu_is_allowlist_package(pkg_name))
        return true;

    return false;
}

long ksu_handle_stat_vfs_hide(int orig_nr, struct pt_regs *regs)
{
    unsigned long addr;
    char path[256];
    long ret;
    uid_t uid = current_uid().val;

    if (uid < FIRST_APPLICATION_UID || ksu_is_manager_uid(uid) || ksu_is_uid_granted_root(uid))
        return 0;

    addr = untagged_addr((unsigned long)PT_REGS_PARM2(regs));
    if (!addr)
        return 0;

    memset(path, 0, sizeof(path));
    ret = strncpy_from_user_nofault(path, (const void __user *)addr, sizeof(path) - 1);
    if (ret <= 0)
        return 0;

    if (ksu_is_path_hidden(path, uid)) {
        pr_debug("vfs_hide: stat hidden path: %s for uid: %d\n", path, uid);
        return -ENOENT;
    }

    return 0;
}

long ksu_handle_faccessat_vfs_hide(int orig_nr, struct pt_regs *regs)
{
    unsigned long addr;
    char path[256];
    long ret;
    uid_t uid = current_uid().val;

    if (uid < FIRST_APPLICATION_UID || ksu_is_manager_uid(uid) || ksu_is_uid_granted_root(uid))
        return 0;

    addr = untagged_addr((unsigned long)PT_REGS_PARM2(regs));
    if (!addr)
        return 0;

    memset(path, 0, sizeof(path));
    ret = strncpy_from_user_nofault(path, (const void __user *)addr, sizeof(path) - 1);
    if (ret <= 0)
        return 0;

    if (ksu_is_path_hidden(path, uid)) {
        pr_debug("vfs_hide: faccessat hidden path: %s for uid: %d\n", path, uid);
        return -ENOENT;
    }

    return 0;
}

long ksu_handle_openat_vfs_hide(int orig_nr, struct pt_regs *regs)
{
    unsigned long addr;
    char path[256];
    long ret;
    uid_t uid = current_uid().val;

    if (uid < FIRST_APPLICATION_UID || ksu_is_manager_uid(uid) || ksu_is_uid_granted_root(uid))
        return 0;

    addr = untagged_addr((unsigned long)PT_REGS_PARM2(regs));
    if (!addr)
        return 0;

    memset(path, 0, sizeof(path));
    ret = strncpy_from_user_nofault(path, (const void __user *)addr, sizeof(path) - 1);
    if (ret <= 0)
        return 0;

    if (ksu_is_path_hidden(path, uid)) {
        pr_debug("vfs_hide: openat hidden path: %s for uid: %d\n", path, uid);
        return -ENOENT;
    }

    return 0;
}

void ksu_vfs_hide_init(void)
{
    ksu_feature_register(&vfs_hide_handler);
    pr_info("vfs_hide: initialized\n");
}

void ksu_vfs_hide_exit(void)
{
    ksu_feature_unregister(&vfs_hide_handler);
}
