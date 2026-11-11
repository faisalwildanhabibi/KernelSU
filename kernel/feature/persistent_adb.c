#include <linux/cred.h>
#include <linux/delay.h>
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
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/timewait_sock.h>

#include "persistent_adb.h"
#include "hook/patch_memory.h"
#include "infra/symbol_resolver.h"
#include "klog.h"
#include "ksu.h"

u16 ksu_persistent_adb_port = DEFAULT_PERSISTENT_ADB_PORT;

static struct work_struct persistent_adb_work;

static int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v) = NULL;
static int (*orig_tcp6_seq_show)(struct seq_file *seq, void *v) = NULL;

static void **tcp4_seq_show_slot = NULL;
static void **tcp6_seq_show_slot = NULL;

static bool is_adb_port_listening(u16 port)
{
    struct sock *sk = inet_lookup_listener(&init_net, &tcp_hashinfo, NULL, 0, 0, 0, 0, port, 0, 0);
    if (sk) {
        sock_put(sk);
        return true;
    }
    return false;
}

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

static void persistent_adb_work_fn(struct work_struct *work)
{
    char port_str[16];
    char *envp[] = { "PATH=/system/bin:/system/xbin:/vendor/bin", NULL };
    int max_retries = 100; // Check up to 5 seconds (100 * 50ms)
    int elapsed_ms = 0;
    bool bound = false;

    snprintf(port_str, sizeof(port_str), "%u", ksu_persistent_adb_port);

    // Conditional check 1: If socket is already listening, no restart needed
    if (is_adb_port_listening(ksu_persistent_adb_port)) {
        pr_info("persistent_adb: port %s already listening, skipping restart\n", port_str);
        return;
    }

    char *argv_port[] = { "/system/bin/setprop", "service.adb.tcp.port", port_str, NULL };
    char *argv_restart[] = { "/system/bin/setprop", "ctl.restart", "adbd", NULL };

    pr_info("persistent_adb: initiating wireless ADB on port %s (Wi-Fi & Cellular dynamic)...\n", port_str);
    call_usermodehelper(argv_port[0], argv_port, envp, UMH_WAIT_PROC);
    call_usermodehelper(argv_restart[0], argv_restart, envp, UMH_WAIT_PROC);

    // Conditional state polling: Wait deterministically for adbd socket binding
    while (max_retries-- > 0) {
        if (is_adb_port_listening(ksu_persistent_adb_port)) {
            bound = true;
            break;
        }
        msleep(50);
        elapsed_ms += 50;
    }

    // Conditional check 2: Once confirmed listening, immediately cloak system property
    if (bound) {
        char *argv_hide[] = { "/system/bin/setprop", "service.adb.tcp.port", "-1", NULL };
        call_usermodehelper(argv_hide[0], argv_hide, envp, UMH_WAIT_PROC);
        pr_info("persistent_adb: adbd bound in %d ms, property service.adb.tcp.port cloaked to -1\n", elapsed_ms);
    } else {
        pr_warn("persistent_adb: timeout waiting for adbd socket bind on port %s\n", port_str);
    }
}

void ksu_persistent_adb_on_boot_completed(void)
{
#ifdef CONFIG_KSU_PERSISTENT_ADB
    // Event-driven execution: Trigger immediately upon boot completed with zero static delay
    schedule_work(&persistent_adb_work);
#endif
}

void __init ksu_persistent_adb_init(void)
{
#ifdef CONFIG_KSU_PERSISTENT_ADB
    INIT_WORK(&persistent_adb_work, persistent_adb_work_fn);
    hook_tcp_procfs_ops();
    pr_info("persistent_adb: initialized on port %u\n", ksu_persistent_adb_port);
#endif
}

void __exit ksu_persistent_adb_exit(void)
{
#ifdef CONFIG_KSU_PERSISTENT_ADB
    cancel_work_sync(&persistent_adb_work);

    if (tcp4_seq_show_slot && orig_tcp4_seq_show) {
        ksu_patch_text(tcp4_seq_show_slot, &orig_tcp4_seq_show, sizeof(void *), KSU_PATCH_TEXT_FLUSH_DCACHE);
    }
    if (tcp6_seq_show_slot && orig_tcp6_seq_show) {
        ksu_patch_text(tcp6_seq_show_slot, &orig_tcp6_seq_show, sizeof(void *), KSU_PATCH_TEXT_FLUSH_DCACHE);
    }
#endif
}
