#ifndef __KSU_H_DYNAMIC_MANAGER
#define __KSU_H_DYNAMIC_MANAGER

#include <linux/types.h>
#include "uapi/supercall.h"

struct dynamic_manager_config {
    unsigned int size;
    char hash[65];
    int is_set;
};

int ksu_handle_dynamic_manager(struct ksu_dynamic_manager_cmd *cmd);
bool ksu_is_dynamic_manager_enabled(void);
unsigned int ksu_get_dynamic_manager_size(void);
const char *ksu_get_dynamic_manager_hash(void);

#endif
