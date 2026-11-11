#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

bool is_manager_apk(char *path);
bool is_manager_apk_with_sig(char *path, u8 *sig_index);
int get_pkg_from_apk_dir_path(char *pkg, const char *path);

#endif
