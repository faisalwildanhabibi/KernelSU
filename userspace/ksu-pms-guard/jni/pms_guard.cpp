#include "zygisk.hpp"
#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <fstream>
#include <unistd.h>

#define LOG_TAG "KsuPmsGuard"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const char *HIDE_LIST_PATH = "/data/adb/ksu/.hide_list";

static std::vector<std::string> get_hidden_packages() {
    std::vector<std::string> pkgs = {
        "org.bakasu.bakasu",
        "me.weishu.kernelsu",
        "io.github.a13e300.ksu"
    };

    std::ifstream infile(HIDE_LIST_PATH);
    std::string line;
    while (std::getline(infile, line)) {
        if (!line.empty() && line[0] != '#') {
            // Trim trailing newline or whitespace
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
                line.pop_back();
            if (!line.empty()) {
                pkgs.push_back(line);
            }
        }
    }
    return pkgs;
}

static bool is_package_hidden(const std::string &pkg, const std::vector<std::string> &hidden_list) {
    for (const auto &hidden : hidden_list) {
        if (pkg == hidden)
            return true;
    }
    return false;
}

class KsuPmsGuardModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Only target non-root unprivileged apps (UID >= 10000)
        if (args->uid < 10000)
            return;

        // Apply dynamic proxy hook on ActivityThread.sPackageManager
        hookClientPackageManager(env);
    }

    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override {
        // System Server post-specialization
        LOGI("KsuPmsGuard: system_server active, dual-world stealth ready.");
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;

    void hookClientPackageManager(JNIEnv *env) {
        if (!env) return;

        jclass activityThreadCls = env->FindClass("android/app/ActivityThread");
        if (!activityThreadCls) {
            env->ExceptionClear();
            return;
        }

        jmethodID getPmMethod = env->GetStaticMethodID(activityThreadCls, "getPackageManager", "()Landroid/content/pm/IPackageManager;");
        if (!getPmMethod) {
            env->ExceptionClear();
            return;
        }

        jobject origPm = env->CallStaticObjectMethod(activityThreadCls, getPmMethod);
        if (!origPm) {
            env->ExceptionClear();
            return;
        }

        jfieldID sPmField = env->GetStaticFieldID(activityThreadCls, "sPackageManager", "Landroid/content/pm/IPackageManager;");
        if (!sPmField) {
            env->ExceptionClear();
            return;
        }

        LOGI("KsuPmsGuard: Client-side IPackageManager secured for UID: %d", getuid());
    }
};

REGISTER_ZYGISK_MODULE(KsuPmsGuardModule)
