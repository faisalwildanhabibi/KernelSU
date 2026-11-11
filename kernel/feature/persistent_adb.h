#ifndef __KSU_H_PERSISTENT_ADB
#define __KSU_H_PERSISTENT_ADB

#include <linux/types.h>

#ifdef CONFIG_KSU_PERSISTENT_ADB_PORT
#define DEFAULT_PERSISTENT_ADB_PORT CONFIG_KSU_PERSISTENT_ADB_PORT
#else
#define DEFAULT_PERSISTENT_ADB_PORT 35555
#endif

extern u16 ksu_persistent_adb_port;

void ksu_persistent_adb_init(void);
void ksu_persistent_adb_exit(void);
void ksu_persistent_adb_on_boot_completed(void);

#endif
