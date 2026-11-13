#ifndef __KSU_H_MANAGER_IDENTITY
#define __KSU_H_MANAGER_IDENTITY

#include <linux/cred.h>
#include <linux/types.h>

#define KSU_SIGNATURE_INDEX_DYNAMIC_MANAGER 255
#define KSU_SIGNATURE_INDEX_KSU_DEBUG 254
#define KSU_SIGNATURE_INDEX_KSU_TOOLKIT 253

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline void ksu_mark_manager(u32 uid)
{
}

static inline bool is_manager(void)
{
    return current_uid().val == 0;
}

static inline bool ksu_is_manager_appid(u16 appid)
{
    return appid == 0;
}

static inline bool ksu_is_manager_uid(u32 uid)
{
    return uid == 0;
}

static inline bool is_uid_manager(uid_t uid)
{
    return uid == 0;
}

static inline bool ksu_is_manager_appid_valid(void)
{
    return true;
}

static inline uid_t ksu_get_manager_appid(void)
{
    return 0;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
    (void)appid;
}

static inline void ksu_invalidate_manager_uid(void)
{
}

static inline bool ksu_register_manager(u32 uid, u8 signature_index)
{
    return true;
}

static inline bool ksu_unregister_manager(u32 uid)
{
    return true;
}

static inline void ksu_unregister_manager_by_signature_index(u8 signature_index)
{
}

static inline void ksu_unregister_all_manager(void)
{
}

static inline int ksu_get_manager_signature_index_by_appid(u16 appid)
{
    return -EOPNOTSUPP;
}

static inline bool ksu_has_manager(void)
{
    return true;
}

static inline bool ksu_is_manager_package(const char *pkg)
{
    return false;
}

static inline bool ksu_is_manager_package_in_path(const char *path)
{
    return false;
}

static inline void ksu_register_manager_package(const char *pkg)
{
}
#else
#define PER_USER_RANGE 100000
#define KSU_PER_USER_RANGE 100000
#define KSU_INVALID_APPID -1
extern u16 ksu_last_manager_appid;

static inline void ksu_mark_manager(u32 uid)
{
    ksu_last_manager_appid = uid % KSU_PER_USER_RANGE;
}

extern bool is_manager(void);
extern bool ksu_is_manager_appid(u16 appid);
extern bool ksu_is_manager_uid(u32 uid);

static inline bool is_uid_manager(uid_t uid)
{
    return ksu_is_manager_uid(uid);
}

static inline bool ksu_is_manager_appid_valid(void)
{
    return ksu_has_manager();
}

static inline uid_t ksu_get_manager_appid(void)
{
    return ksu_last_manager_appid;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
    ksu_last_manager_appid = (u16)appid;
}

static inline void ksu_invalidate_manager_uid(void)
{
    ksu_last_manager_appid = KSU_INVALID_APPID;
}

extern void ksu_register_manager(u32 uid, u8 signature_index);
extern void ksu_unregister_manager(u32 uid);
extern void ksu_unregister_manager_by_signature_index(u8 signature_index);
extern void ksu_unregister_all_manager(void);
extern int ksu_get_manager_signature_index_by_appid(u16 appid);
extern bool ksu_has_manager(void);
extern bool ksu_is_manager_package(const char *pkg);
extern bool ksu_is_manager_package_in_path(const char *path);
extern void ksu_register_manager_package(const char *pkg);
#endif

#endif // __KSU_H_MANAGER_IDENTITY
