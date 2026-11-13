#pragma once

#include <jni.h>

#define ZYGISK_API_VERSION 2

namespace zygisk {

struct ApiTable;

class Api {
public:
    virtual bool connectCompanion() = 0;
    virtual int getCompanionSocket() = 0;
    virtual bool setOption(int opt) = 0;
    virtual void exemptFd(int fd) = 0;
};

struct AppSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &rlimits;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jboolean &is_child_zygote;
    jstring &instruction_set;
    jstring &app_data_dir;
    jboolean &is_top_app;
    jobjectArray &pkg_data_info_list;
    jobjectArray &whitelisted_data_info_list;
    jboolean &mount_data_dirs;
    jboolean &mount_storage_dirs;
};

struct ServerSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &rlimits;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;
};

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
};

using EntryPoint = void (*)(ApiTable *, JNIEnv *);

} // namespace zygisk

#define REGISTER_ZYGISK_MODULE(clazz)                                                          \
    extern "C" [[gnu::visibility("default")]] void zygisk_module_entry(                        \
        zygisk::ApiTable *table, JNIEnv *env) {                                                \
        static clazz module;                                                                   \
        /* Entry implementation delegated to Zygisk host */                                    \
    }
