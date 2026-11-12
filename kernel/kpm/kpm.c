/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include "kpm.h"

int ksu_kpm_load_module_path(const char *path, const char *args, void *ptr)
{
    // KPM stub placeholder for external module loader
    return -ENOSYS;
}

int ksu_kpm_unload_module(const char *name, void *ptr)
{
    return -ENOSYS;
}

int ksu_kpm_num(void)
{
    return 0;
}

int ksu_kpm_info(const char *name, void __user *out)
{
    return -ENOSYS;
}

int ksu_kpm_list(void __user *out, unsigned int bufferSize)
{
    return -ENOSYS;
}

void ksu_kpm_print_list(void)
{
}

void ksu_kpm_version(void)
{
}

int ksu_handle_kpm(unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    if (arg3 == KSU_KPM_LOAD) {
        char kernel_load_path[256] = { 0 };
        char kernel_args_buffer[256] = { 0 };

        if (arg4 == 0)
            return -EINVAL;

        if (strncpy_from_user(kernel_load_path, (const char __user *)arg4, sizeof(kernel_load_path) - 1) < 0)
            return -EFAULT;

        if (arg5 != 0) {
            if (strncpy_from_user(kernel_args_buffer, (const char __user *)arg5, sizeof(kernel_args_buffer) - 1) < 0)
                return -EFAULT;
        }
        return ksu_kpm_load_module_path(kernel_load_path, kernel_args_buffer, NULL);
    } else if (arg3 == KSU_KPM_UNLOAD) {
        char kernel_name_buffer[256] = { 0 };

        if (arg4 == 0)
            return -EINVAL;

        if (strncpy_from_user(kernel_name_buffer, (const char __user *)arg4, sizeof(kernel_name_buffer) - 1) < 0)
            return -EFAULT;

        return ksu_kpm_unload_module(kernel_name_buffer, NULL);
    } else if (arg3 == KSU_KPM_NUM) {
        return ksu_kpm_num();
    } else if (arg3 == KSU_KPM_INFO) {
        char kernel_name_buffer[256] = { 0 };

        if (arg4 == 0 || arg5 == 0)
            return -EINVAL;

        if (strncpy_from_user(kernel_name_buffer, (const char __user *)arg4, sizeof(kernel_name_buffer) - 1) < 0)
            return -EFAULT;

        return ksu_kpm_info(kernel_name_buffer, (void __user *)arg5);
    } else if (arg3 == KSU_KPM_LIST) {
        return ksu_kpm_list((void __user *)arg4, (unsigned int)arg5);
    } else if (arg3 == KSU_KPM_PRINT) {
        ksu_kpm_print_list();
        return 0;
    }
    return -EINVAL;
}

int ksu_is_kpm_control_code(unsigned long arg2)
{
    return (arg2 >= CMD_KPM_CONTROL && arg2 <= CMD_KPM_CONTROL_MAX) ? 1 : 0;
}
