#ifndef __KSU_FEATURE_VFS_HIDE_H
#define __KSU_FEATURE_VFS_HIDE_H

#include <linux/types.h>
#include <linux/ptrace.h>

extern bool ksu_vfs_hide_enabled;

void ksu_vfs_hide_init(void);
void ksu_vfs_hide_exit(void);

bool ksu_is_path_hidden(const char *path, uid_t caller_uid);

long ksu_handle_stat_vfs_hide(int orig_nr, struct pt_regs *regs);
long ksu_handle_faccessat_vfs_hide(int orig_nr, struct pt_regs *regs);
long ksu_handle_openat_vfs_hide(int orig_nr, struct pt_regs *regs);

#endif
