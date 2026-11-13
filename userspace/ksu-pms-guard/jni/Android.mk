LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := ksu_pms_guard
LOCAL_SRC_FILES := pms_guard.cpp
LOCAL_LDLIBS := -llog
LOCAL_CPPFLAGS := -std=c++17 -Wall -Wextra -O3 -fvisibility=hidden

include $(BUILD_SHARED_LIBRARY)
