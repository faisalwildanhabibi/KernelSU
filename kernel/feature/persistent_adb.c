#include <linux/cred.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/umh.h>
#include <linux/workqueue.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/timewait_sock.h>

#include "persistent_adb.h"
#include "hook/patch_memory.h"
#include "infra/symbol_resolver.h"
#include "klog.h"
#include "ksu.h"

u16 ksu_persistent_adb_port = DEFAULT_PERSISTENT_ADB_PORT;

static struct delayed_work persistent_adb_work;
static struct delayed_work persistent_adb_stealth_work;

static int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v) = NULL;
static int (*orig_tcp6_seq_show)(struct seq_file *seq, void *v) = NULL;

static void **tcp4_seq_show_slot = NULL;
static void **tcp6_seq_show_slot = NULL;

static int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    if (v != SEQ_START_TOKEN) {
        uid_t uid = current_uid().val;
        // Non-root Android app UIDs start at 10000
        if (uid >= 10000) {
            struct sock *sk = v;
            u16 srcp = 0;

            if (sk->sk_state == TCP_TIME_WAIT) {
                struct inet_timewait_sock *tw = (struct inet_timewait_sock *)sk;
                srcp = ntohs(tw->tw_sport);
            } else if (sk->sk_state != TCP_NEW_SYN_RECV) {
                struct inet_sock *inet = inet_sk(sk);
                srcp = ntohs(inet->inet_sport);
            }

            if (srcp == ksu_persistent_adb_port) {
                // Cloak ADB listening socket: suppress row from /proc/net/tcp
                return 0;
            }
        }
    }

    if (orig_tcp4_seq_show)
        return orig_tcp4_seq_show(seq, v);

    return 0;
}

static int hook_tcp6_seq_show(struct seq_file *seq, void *v)
{
    if (v != SEQ_START_TOKEN) {
        uid_t uid = current_uid().val;
        if (uid >= 10000) {
            struct sock *sk = v;
            u16 srcp = 0;

            if (sk->sk_state == TCP_TIME_WAIT) {
                struct inet_timewait_sock *tw = (struct inet_timewait_sock *)sk;
                srcp = ntohs(tw->tw_sport);
            } else if (sk->sk_state != TCP_NEW_SYN_RECV) {
                struct inet_sock *inet = inet_sk(sk);
                srcp = ntohs(inet->inet_sport);
            }

            if (srcp == ksu_persistent_adb_port) {
                // Cloak ADB listening socket: suppress row from /proc/net/tcp6
                return 0;
            }
        }
    }

    if (orig_tcp6_seq_show)
        return orig_tcp6_seq_show(seq, v);

    return 0;
}

static void hook_tcp_procfs_ops(void)
{
    struct seq_operations *tcp4_ops = (struct seq_operations *)find_kernel_symbol_exact("tcp4_seq_ops");
    if (tcp4_ops && tcp4_ops->show) {
        tcp4_seq_show_slot = (void **)&tcp4_ops->show;
        orig_tcp4_seq_show = tcp4_ops->show;
        ksu_patch_text(tcp4_seq_show_slot, &hook_tcp4_seq_show, sizeof(void *), KSU_PATCH_TEXT_FLUSH_DCACHE);
        pr_info("persistent_adb: hooked tcp4_seq_ops->show for procfs socket masking\n");
    } else {
        pr_warn("persistent_adb: tcp4_seq_ops not found, skipping tcp4 masking\n");
    }

    struct seq_operations *tcp6_ops = (struct seq_operations *)find_kernel_symbol_exact("tcp6_seq_ops");
    if (tcp6_ops && tcp6_ops->show) {
        tcp6_seq_show_slot = (void **)&tcp6_ops->show;
        orig_tcp6_seq_show = tcp6_ops->show;
        ksu_patch_text(tcp6_seq_show_slot, &hook_tcp6_seq_show, sizeof(void *), KSU_PATCH_TEXT_FLUSH_DCACHE);
        pr_info("persistent_adb: hooked tcp6_seq_ops->show for procfs socket masking\n");
    } else {
        pr_warn("persistent_adb: tcp6_seq_ops not found, skipping tcp6 masking\n");
    }
}

static void persistent_adb_stealth_work_fn(struct work_struct *work)
{
    // Cloak property: Reset service.adb.tcp.port to -1 in property area.
    // adbd has already opened and bound to 0.0.0.0:<port> so it stays listening,
    // but any app reading getprop sees -1 (disabled).
    char *argv_hide[] = { "/system/bin/setprop", "service.adb.tcp.port", "-1", NULL };
    char *envp[] = { "PATH=/system/bin:/system/xbin:/vendor/bin", NULL };

    call_usermodehelper(argv_hide[0], argv_hide, envp, UMH_WAIT_PROC);
    pr_info("persistent_adb: cloaked service.adb.tcp.port to -1\n");
}

static void persistent_adb_work_fn(struct work_struct *work)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", ksu_persistent_adb_port);

    char *argv_port[] = { "/system/bin/setprop", "service.adb.tcp.port", port_str, NULL };
    char *argv_restart[] = { "/system/bin/setprop", "ctl.restart", "adbd", NULL };
    char *envp[] = { "PATH=/system/bin:/system/xbin:/vendor/bin", NULL };

    pr_info("persistent_adb: setting wireless ADB to port %s...\n", port_str);
    call_usermodehelper(argv_port[0], argv_port, envp, UMH_WAIT_PROC);

    call_usermodehelper(argv_restart[0], argv_restart, envp, UMH_WAIT_PROC);
    pr_info("persistent_adb: restarted adbd daemon on port %s (Wi-Fi & Cellular active)\n", port_str);

    // Schedule property cloaking after 5 seconds to allow adbd socket binding
    schedule_delayed_work(&persistent_adb_stealth_work, msecs_to_jiffies(5000));
}

void ksu_persistent_adb_on_boot_completed(void)
{
#ifdef CONFIG_KSU_PERSISTENT_ADB
    pr_info("persistent_adb: boot completed detected, scheduling wireless adb setup\n");
    schedule_delayed_work(&persistent_adb_work, msecs_to_jiffies(1000));
#endif
}

void __init ksu_persistent_adb_init(void)
{
#ifdef CONFIG_KSU_PERSISTENT_ADB
    INIT_DELAYED_WORK(&persistent_adb_work, persistent_adb_work_fn);
    INIT_DELAYED_WORK(&persistent_adb_stealth_work, persistent_adb_stealth_work_fn);
    hook_tcp_procfs_ops();
    pr_info("persistent_adb: initialized on port %u\n", ksu_persistent_adb_port);
#endif
}

void __exit ksu_persistent_adb_exit(void)
{
#ifdef CONFIG_KSU_PERSISTENT_ADB
    cancel_delayed_work_sync(&persistent_adb_work);
    cancel_delayed_work_sync(&persistent_adb_stealth_work);

    if (tcp4_seq_show_slot && orig_tcp4_seq_show) {
        ksu_patch_text(tcp4_seq_show_slot, &orig_tcp4_seq_show, sizeof(void *), KSU_PATCH_TEXT_FLUSH_DCACHE);
    }
    if (tcp6_seq_show_slot && orig_tcp6_seq_show) {
        ksu_patch_text(tcp6_seq_show_slot, &orig_tcp6_seq_show, sizeof(void *), KSU_PATCH_TEXT_FLUSH_DCACHE);
    }
#endif
}
