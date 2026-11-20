/* Minimal libretro host for verifying a native build. */
#ifndef PSXRC_SMOKE_STATIC
#ifdef _WIN32
#include <windows.h>
#define core_open(path) LoadLibraryA(path)
#define core_symbol GetProcAddress
#define core_close FreeLibrary
typedef HMODULE core_handle;
#else
#include <dlfcn.h>
#define core_open(path) dlopen(path, RTLD_NOW | RTLD_LOCAL)
#define core_symbol dlsym
#define core_close dlclose
typedef void *core_handle;
#endif
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libretro.h"

static const char *system_directory;
static unsigned video_frames, changed_frames, previous_hash, direct_video;
static int direct_requested;

static void core_log(enum retro_log_level level, const char *format, ...)
{
    char message[640];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (strstr(message, "playing H.264 video directly"))
        ++direct_video;
    if (level >= RETRO_LOG_WARN || strstr(message, "PSXRC"))
        fputs(message, stderr);
}

static bool environment(unsigned command, void *data)
{
    switch (command) {
    case RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY:
    case RETRO_ENVIRONMENT_GET_SAVE_DIRECTORY:
        *(const char **)data = system_directory;
        return true;
    case RETRO_ENVIRONMENT_GET_LOG_INTERFACE:
        ((struct retro_log_callback *)data)->log = core_log;
        return true;
    case RETRO_ENVIRONMENT_GET_VARIABLE: {
        struct retro_variable *var = data;
        if (!strcmp(var->key, "pcsx_rearmed_bios"))
            var->value = "HLE";
        else if (!strcmp(var->key, "pcsx_rearmed_drc") ||
                 !strcmp(var->key, "pcsx_rearmed_gpu_thread_rendering"))
            var->value = "disabled";
        else if (direct_requested && !strcmp(var->key, "pcsx_rearmed_psxrc_direct_h264"))
            var->value = "enabled";
        else
            return false;
        return true;
    }
    case RETRO_ENVIRONMENT_GET_VARIABLE_UPDATE:
        *(bool *)data = false;
        return true;
    case RETRO_ENVIRONMENT_SET_PIXEL_FORMAT:
        return *(const enum retro_pixel_format *)data == RETRO_PIXEL_FORMAT_RGB565;
    case RETRO_ENVIRONMENT_SET_SUPPORT_NO_GAME:
    case RETRO_ENVIRONMENT_SET_DISK_CONTROL_INTERFACE:
    case RETRO_ENVIRONMENT_SET_DISK_CONTROL_EXT_INTERFACE:
        return true;
    default:
        return false;
    }
}

static void video(const void *pixels, unsigned width, unsigned height, size_t pitch)
{
    if (!pixels || width < 32 || height < 32)
        return;
    ++video_frames;
    unsigned hash = 2166136261u;
    for (unsigned y = height / 4; y < height * 3 / 4; y += 4) {
        const unsigned char *row = (const unsigned char *)pixels + y * pitch;
        for (unsigned x = width / 4; x < width * 3 / 4; x += 4)
            hash = (hash ^ row[x * 2]) * 16777619u;
    }
    if (hash != previous_hash)
        ++changed_frames;
    previous_hash = hash;
}

static void audio(int16_t left, int16_t right) { (void)left; (void)right; }
static size_t audio_batch(const int16_t *data, size_t count) { (void)data; return count; }
static void poll_input(void) {}
static int16_t input(unsigned port, unsigned device, unsigned index, unsigned id)
{
    (void)port; (void)device; (void)index; (void)id;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 6) {
        fprintf(stderr, "Usage: %s CORE IMAGE SYSTEM FRAMES [direct]\n", argv[0]);
        return 2;
    }
    system_directory = argv[3];
    direct_requested = argc == 6;
    if (direct_requested && strcmp(argv[5], "direct"))
        return 2;
    char *end;
    unsigned long frames = strtoul(argv[4], &end, 10);
    if (*end || !frames || frames > 60000)
        return 2;
#ifdef PSXRC_SMOKE_STATIC
#define CLOSE_CORE() ((void)0)
#define LOAD(symbol) __typeof__(&symbol) symbol##_fn = &symbol;
#else
    core_handle core = core_open(argv[1]);
    if (!core) {
#ifdef _WIN32
        fprintf(stderr, "Could not load %s (Windows error %lu)\n", argv[1], GetLastError());
#else
        fprintf(stderr, "%s\n", dlerror());
#endif
        return 1;
    }
#define CLOSE_CORE() core_close(core)
#define LOAD(symbol) \
    __typeof__(&symbol) symbol##_fn = (__typeof__(&symbol))core_symbol(core, #symbol); \
    if (!symbol##_fn) { fprintf(stderr, "Missing %s\n", #symbol); CLOSE_CORE(); return 1; }
#endif
    LOAD(retro_api_version)
    LOAD(retro_init)
    LOAD(retro_deinit)
    LOAD(retro_get_system_info)
    LOAD(retro_set_environment)
    LOAD(retro_set_video_refresh)
    LOAD(retro_set_audio_sample)
    LOAD(retro_set_audio_sample_batch)
    LOAD(retro_set_input_poll)
    LOAD(retro_set_input_state)
    LOAD(retro_load_game)
    LOAD(retro_unload_game)
    LOAD(retro_run)
#undef LOAD

    struct retro_system_info info = { 0 };
    retro_get_system_info_fn(&info);
    if (retro_api_version_fn() != RETRO_API_VERSION || !info.valid_extensions ||
        !strstr(info.valid_extensions, "psxrc")) {
        fputs("Unexpected API version or missing PSXRC support.\n", stderr);
        CLOSE_CORE();
        return 1;
    }
    retro_set_environment_fn(environment);
    retro_set_video_refresh_fn(video);
    retro_set_audio_sample_fn(audio);
    retro_set_audio_sample_batch_fn(audio_batch);
    retro_set_input_poll_fn(poll_input);
    retro_set_input_state_fn(input);
    retro_init_fn();
    struct retro_game_info disc = { .path = argv[2] };
    int loaded = retro_load_game_fn(&disc);
    if (loaded) {
        for (unsigned long i = 0; i < frames; ++i)
            retro_run_fn();
        retro_unload_game_fn();
    }
    retro_deinit_fn();
    CLOSE_CORE();
#undef CLOSE_CORE
    printf("Loaded %d, video callbacks %u, changed sampled frames %u, direct H.264 activation %u\n",
           loaded, video_frames, changed_frames, direct_video);
    return loaded && changed_frames >= 6 && (!!direct_video == direct_requested) ? 0 : 1;
}
