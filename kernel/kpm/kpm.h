/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ___KSU_KPM_H
#define ___KSU_KPM_H

int ksu_handle_kpm(unsigned long arg3, unsigned long arg4, unsigned long arg5);
int ksu_is_kpm_control_code(unsigned long arg2);

#define CMD_KPM_CONTROL 28
#define CMD_KPM_CONTROL_MAX 35

#define KSU_KPM_LOAD 28
#define KSU_KPM_UNLOAD 29
#define KSU_KPM_NUM 30
#define KSU_KPM_LIST 31
#define KSU_KPM_INFO 32
#define KSU_KPM_CONTROL 33
#define KSU_KPM_PRINT 34
#define KSU_KPM_VERSION 35

#endif
