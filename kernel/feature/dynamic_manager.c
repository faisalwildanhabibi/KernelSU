#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "dynamic_manager.h"
#include "klog.h"
#include "ksu.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"

static struct dynamic_manager_config dynamic_manager = {
    .size = 0x300,
    .hash = "0000000000000000000000000000000000000000000000000000000000000000",
    .is_set = 0
};

bool ksu_is_dynamic_manager_enabled(void)
{
    return dynamic_manager.is_set != 0;
}

unsigned int ksu_get_dynamic_manager_size(void)
{
    return dynamic_manager.size;
}

const char *ksu_get_dynamic_manager_hash(void)
{
    return dynamic_manager.hash;
}

int ksu_handle_dynamic_manager(struct ksu_dynamic_manager_cmd *cmd)
{
    int i;

    if (!cmd)
        return -EINVAL;

    switch (cmd->operation) {
    case DYNAMIC_MANAGER_OP_SET:
    case DYNAMIC_MANAGER_OP_SET_SYNCHRONOUS:
        if (cmd->size < 0x100 || cmd->size > 0x1000) {
            pr_err("dynamic_manager: invalid certificate size: 0x%x\n", cmd->size);
            return -EINVAL;
        }

        // Validate hash hex characters
        for (i = 0; i < 64; i++) {
            char c = cmd->hash[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                pr_err("dynamic_manager: invalid hash character at position %d: %c\n", i, c);
                return -EINVAL;
            }
        }

        dynamic_manager.size = cmd->size;
        memcpy(dynamic_manager.hash, cmd->hash, 64);
        dynamic_manager.hash[64] = '\0';
        dynamic_manager.is_set = 1;

        ksu_set_manager_appid(KSU_INVALID_APPID);

        pr_info("dynamic_manager: updated size=0x%x, hash=%.16s...\n", cmd->size, cmd->hash);
        track_throne(false);
        break;

    case DYNAMIC_MANAGER_OP_GET:
        if (dynamic_manager.is_set) {
            cmd->size = dynamic_manager.size;
            memcpy(cmd->hash, dynamic_manager.hash, 64);
        } else {
            return -ENODATA;
        }
        break;

    case DYNAMIC_MANAGER_OP_WIPE:
        dynamic_manager.is_set = 0;
        memset(dynamic_manager.hash, 0, sizeof(dynamic_manager.hash));
        dynamic_manager.size = 0;
        ksu_set_manager_appid(KSU_INVALID_APPID);
        pr_info("dynamic_manager: settings reset to default\n");
        break;

    default:
        pr_err("dynamic_manager: invalid operation: %d\n", cmd->operation);
        return -EINVAL;
    }

    return 0;
}
