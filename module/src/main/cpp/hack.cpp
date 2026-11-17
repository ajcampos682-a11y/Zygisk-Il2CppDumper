//
// Created by Perfare on 2020/7/4.
// Patched: dump the DECRYPTED global-metadata.dat straight out of process memory,
// without calling any il2cpp_* export (this game strips/renames them). Il2CppDumper
// can then be run statically on the dumped metadata + libil2cpp.so.
//

#include "hack.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cinttypes>
#include <string>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>

// Il2Cpp global-metadata header magic, little-endian on disk/in memory.
static const uint32_t METADATA_MAGIC = 0xFAB11BAF;

// Scan one readable region for the decrypted metadata header; write it if found.
static bool scan_region(uint64_t start, uint64_t end, const std::string &outPath) {
    uint64_t size = end - start;
    if (size < 0x1000 || size > 0x20000000ULL) return false; // skip tiny / >512MB
    auto *base = reinterpret_cast<uint8_t *>(start);
    for (uint64_t off = 0; off + 0x120 < size; off += 4) {
        auto *p = reinterpret_cast<uint32_t *>(base + off);
        if (*p != METADATA_MAGIC) continue;
        int32_t version = *reinterpret_cast<int32_t *>(base + off + 4);
        if (version < 16 || version > 40) continue; // plausible il2cpp metadata version

        // Header is (magic, version) then int32 (offset,size) pairs. Real file size
        // is the furthest (offset+size). Read pairs within the first 0x120 bytes.
        auto *hdr = reinterpret_cast<uint32_t *>(base + off);
        uint64_t total = 0x110;
        for (int i = 2; i + 1 < (0x120 / 4); i += 2) {
            uint64_t o = hdr[i];
            uint64_t s = hdr[i + 1];
            if (o < size && s < size && o + s <= size && (o + s) > total) total = o + s;
        }
        if (total < 0x100000 || total > 0x4000000) continue;      // 1MB..64MB sane range
        if (off + total > size) continue;

        LOGI("decrypted metadata at %p version=%d size=%" PRIu64, base + off, version, total);
        FILE *out = fopen(outPath.c_str(), "wb");
        if (!out) { LOGE("cannot open %s", outPath.c_str()); return false; }
        size_t wrote = fwrite(base + off, 1, (size_t) total, out);
        fclose(out);
        LOGI("wrote %zu bytes to %s", wrote, outPath.c_str());
        return wrote == total;
    }
    return false;
}

// Walk /proc/self/maps and scan each readable, non-device region.
static bool dump_metadata(const char *game_data_dir) {
    std::string outPath = std::string(game_data_dir) + "/files/global-metadata-decrypted.dat";
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) { LOGE("cannot open /proc/self/maps"); return false; }
    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), maps)) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        char path[768] = {0};
        int n = sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %*x %*x:%*x %*u %767[^\n]",
                       &start, &end, perms, path);
        if (n < 3) continue;
        if (perms[0] != 'r') continue;               // must be readable
        if (strstr(path, "/dev/")) continue;         // skip device maps (can fault)
        if (path[0] == '[' && strncmp(path, "[anon", 5) != 0) continue; // skip [vvar]/[vdso]/etc
        if (scan_region(start, end, outPath)) { found = true; break; }
    }
    fclose(maps);
    return found;
}

void hack_start(const char *game_data_dir) {
    // Wait until libil2cpp.so is actually loaded into the process.
    bool loaded = false;
    for (int i = 0; i < 60; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) { loaded = true; break; }
        sleep(1);
    }
    if (!loaded) {
        LOGE("libil2cpp.so not found in thread %d", gettid());
        return;
    }
    LOGI("libil2cpp.so present, scanning memory for decrypted metadata...");

    // Metadata is decrypted in RAM shortly after il2cpp_init starts; poll for it.
    for (int i = 0; i < 90; i++) {
        if (dump_metadata(game_data_dir)) {
            LOGI("metadata dump complete");
            return;
        }
        sleep(1);
    }
    LOGE("decrypted metadata magic not found after scanning");
}

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                "currentApplication",
                                                                "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                  "getApplicationInfo",
                                                                  "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;

    void *(*loadLibrary)(const char *libpath, int flag);

    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);

    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;

    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    //TODO 等待houdini初始化
    sleep(5);

    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart,
                                                                             "JNI_GetCreatedJavaVMs");
    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        LOGE("GetCreatedJavaVMs error");
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) {
        LOGE("GetLibDir error");
        return false;
    }
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("no need NativeBridge");
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        LOGI("native bridge: %s", native_bridge.data());
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }
    if (nb) {
        LOGI("nb %p", nb);
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
            LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
            LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            LOGI("arm path %s", path);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                LOGI("arm handle %p", arm_handle);
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle,
                                                                                  "JNI_OnLoad",
                                                                                  nullptr, 0);
                LOGI("JNI_OnLoad %p", init);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
        }
    }
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}

#endif
