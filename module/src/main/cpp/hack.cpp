//
// Created by Perfare on 2020/7/4.
// Patched v2: dump the DECRYPTED global-metadata.dat from process memory, reading
// through /proc/self/mem with pread so a bad page returns an error instead of
// faulting the process. No il2cpp_* exports are called (this game strips them).
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
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>

static const uint32_t METADATA_MAGIC = 0xFAB11BAF;
static const uint64_t MAX_META = 0x4000000ULL; // 64MB ceiling for a sane metadata blob

// Read up to len bytes at virtual address addr via /proc/self/mem. Never faults.
static ssize_t safe_read(int fd, uint64_t addr, void *out, size_t len) {
    return pread(fd, out, len, (off_t) addr);
}

// Given a candidate header already in buf, compute the real metadata size.
static uint64_t compute_total(const uint8_t *hdr) {
    uint64_t total = 0x110;
    for (int i = 2; i + 1 < (0x120 / 4); i += 2) {
        uint32_t o, s;
        memcpy(&o, hdr + i * 4, 4);
        memcpy(&s, hdr + i * 4 + 4, 4);
        if (o < MAX_META && s < MAX_META && (uint64_t) o + s > total && (uint64_t) o + s < MAX_META)
            total = (uint64_t) o + s;
    }
    return total;
}

static bool write_metadata(int fd, uint64_t src, uint64_t total, const std::string &outPath) {
    FILE *out = fopen(outPath.c_str(), "wb");
    if (!out) { LOGE("cannot open %s", outPath.c_str()); return false; }
    std::vector<uint8_t> big(0x100000);
    uint64_t remaining = total, cur = src;
    while (remaining > 0) {
        size_t want = (size_t) std::min<uint64_t>(big.size(), remaining);
        ssize_t r = safe_read(fd, cur, big.data(), want);
        if (r <= 0) { fclose(out); LOGE("read failed at %" PRIx64, cur); return false; }
        fwrite(big.data(), 1, (size_t) r, out);
        remaining -= (uint64_t) r;
        cur += (uint64_t) r;
    }
    fclose(out);
    LOGI("wrote %" PRIu64 " bytes to %s", total, outPath.c_str());
    return true;
}

static bool scan_region(int fd, uint64_t start, uint64_t end, const std::string &outPath) {
    uint64_t size = end - start;
    if (size < 0x1000 || size > 0x20000000ULL) return false; // skip tiny / >512MB
    const size_t CHUNK = 0x100000;                           // 1MB window
    std::vector<uint8_t> buf(CHUNK + 0x120);
    for (uint64_t base = start; base < end; base += CHUNK) {
        size_t want = (size_t) std::min<uint64_t>(buf.size(), end - base);
        ssize_t got = safe_read(fd, base, buf.data(), want);
        if (got <= 0x120) continue;                          // unreadable chunk -> skip
        for (ssize_t off = 0; off + 0x120 < got; off += 4) {
            uint32_t magic;
            memcpy(&magic, buf.data() + off, 4);
            if (magic != METADATA_MAGIC) continue;
            int32_t version;
            memcpy(&version, buf.data() + off + 4, 4);
            if (version < 16 || version > 40) continue;
            uint64_t total = compute_total(buf.data() + off);
            if (total < 0x100000 || total > MAX_META) continue;
            LOGI("decrypted metadata at %" PRIx64 " version=%d size=%" PRIu64,
                 base + (uint64_t) off, version, total);
            if (write_metadata(fd, base + (uint64_t) off, total, outPath)) return true;
        }
    }
    return false;
}

static bool dump_metadata(const char *game_data_dir) {
    std::string outPath = std::string(game_data_dir) + "/files/global-metadata-decrypted.dat";
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { LOGE("cannot open /proc/self/mem"); return false; }
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) { LOGE("cannot open /proc/self/maps"); close(fd); return false; }
    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), maps)) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        char path[768] = {0};
        int n = sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %*x %*x:%*x %*u %767[^\n]",
                       &start, &end, perms, path);
        if (n < 3) continue;
        if (perms[0] != 'r') continue;
        if (strstr(path, "/dev/")) continue;
        if (path[0] == '[' && strncmp(path, "[anon", 5) != 0) continue;
        if (scan_region(fd, start, end, outPath)) { found = true; break; }
    }
    fclose(maps);
    close(fd);
    return found;
}

void hack_start(const char *game_data_dir) {
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
