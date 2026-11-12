#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

#include <linux/types.h>
#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline void ksu_throne_tracker_init()
{
}

static inline void ksu_throne_tracker_exit()
{
}

static inline void track_throne(bool prune_only)
{
    (void)prune_only;
}
#else
void ksu_throne_tracker_init();

void ksu_throne_tracker_exit();

void track_throne(bool prune_only);

struct ksu_get_managers_cmd;
int ksu_handle_get_managers_cmd(struct ksu_get_managers_cmd __user *arg, struct ksu_get_managers_cmd *cmd);
extern u8 ksu_manager_signature_index;
#endif

#endif
