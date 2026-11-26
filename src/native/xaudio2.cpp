// XAudio2 2.3 (DirectX SDK November 2008) for the native host, on FAudio.
//
// The engine mixes everything itself (audio::XAudio2RendererDriver and its mixing thread) and only needs the
// engine object, one mastering voice and one streaming source voice, but the whole 2.3 COM surface is bridged so
// that nothing silently corrupts the guest stack: every method pops exactly its 2.3 argument count.
//
// Differences from the XAudio2 2.7/2.8 ABI that FAudio follows:
//   - voice vtables have no Set/GetOutputFilterParameters (17 IXAudio2Voice methods),
//   - XAUDIO2_VOICE_SENDS is {count, IXAudio2Voice**} instead of an array of send descriptors,
//   - XAUDIO2_VOICE_DETAILS has no ActiveFlags,
//   - the voice callback vtable starts with OnVoiceProcessingPassStart(BytesRequired).
// Guest objects are 16-byte blocks: [0] guest vtable (import thunks), [4] index into g_objects.
#include <FAudio.h>
#include <dlfcn.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "win.h"

namespace native {

// The game's initialized XAudio2 engine; Bink movies (bink.cpp) play their sound through it.
FAudio* g_engine_audio = nullptr;

namespace {

constexpr uint32_t kE_InvalidArg = 0x80070057u, kE_NoInterface = 0x80004002u, kE_Fail = 0x80004005u;

enum Kind { kEngine, kSource, kSubmix, kMastering };

struct Object;

// Host-side callback object handed to FAudio; forwards to the guest IXAudio2VoiceCallback.
struct VoiceCallback {
    FAudioVoiceCallback fa;  // must stay first: FAudio passes &fa back
    uint32_t guest;          // guest IXAudio2VoiceCallback*
};

struct EngineCallback {
    FAudioEngineCallback fa;
    uint32_t guest;
};

struct Object {
    explicit Object(Kind k, FAudio* a = nullptr, FAudioVoice* v = nullptr) : kind(k), audio(a), voice(v) {}
    Kind kind;
    FAudio* audio = nullptr;
    FAudioVoice* voice = nullptr;
    VoiceCallback* callback = nullptr;
    std::vector<EngineCallback*> engine_callbacks;
    uint32_t refs = 1;
};

std::recursive_mutex g_mutex;
std::vector<Object*> g_objects;
uint32_t g_vtables[4];

Object* Obj(uint32_t guest) {
    std::lock_guard<std::recursive_mutex> lock(g_mutex);
    return g_objects[R32(guest + 4)];
}

FAudioVoice* VoiceOf(uint32_t guest) { return guest ? Obj(guest)->voice : nullptr; }

uint32_t NewGuest(Object* o) {
    std::lock_guard<std::recursive_mutex> lock(g_mutex);
    uint32_t g = HeapAlloc(16);
    W32(g, g_vtables[o->kind]);
    W32(g + 4, uint32_t(g_objects.size()));
    g_objects.push_back(o);
    return g;
}

void Forget(uint32_t guest) {
    std::lock_guard<std::recursive_mutex> lock(g_mutex);
    g_objects[R32(guest + 4)] = nullptr;
    W32(guest, 0);
}

// ---- guest callbacks, called on FAudio's mixing thread ----
void EnsureGuestThread() {
    thread_local bool attached = false;
    if (!attached) {
        AttachThread(1u << 20);
        PerfHintAddThread(int(gettid()));  // FAudio's mixing thread runs the engine's audio callbacks
        attached = true;
    }
}

uint32_t Method(uint32_t obj, int index) { return R32(R32(obj) + 4 * uint32_t(index)); }

// Diagnostics (setting audio_stats; by default only when something starved): per 5 s, the mixing passes, the
// longest gap between passes, the time spent in guest callbacks (on FAudio's mixing thread, so it delays the
// device), the passes where the engine's source voice was short of data (BytesRequired > 0: audible as a dropout),
// and on Android the device reads that found FAudio's ring short (underruns: the mixer fell behind the device).
struct AudioStats {
    using Clock = std::chrono::steady_clock;
    int level = SettingInt("audio_stats", 1);  // 1: only windows where the engine's voice starved, 2: all, 0: off
    bool on = level != 0;
    Clock::time_point window = Clock::now(), last_pass{};
    uint32_t passes = 0, starved = 0, submits = 0;
    double max_gap_ms = 0, guest_ms = 0, max_guest_ms = 0;
};
AudioStats& Stats() {
    static AudioStats s;
    return s;
}
struct GuestTimer {
    AudioStats::Clock::time_point t0 = AudioStats::Clock::now();
    ~GuestTimer() {
        AudioStats& s = Stats();
        if (!s.on) return;
        double ms = std::chrono::duration<double, std::milli>(AudioStats::Clock::now() - t0).count();
        s.guest_ms += ms;
        if (ms > s.max_guest_ms) s.max_guest_ms = ms;
    }
};
// Device reads that found FAudio's paced ring short since the last call (android/patches/faudio-paced-mixer.patch).
uint32_t RingUnderruns() {
#ifdef __ANDROID__
    static auto take = reinterpret_cast<uint32_t (*)()>(dlsym(dlopen("libFAudio.so", RTLD_NOW | RTLD_NOLOAD),
                                                               "FAudio_PacedTakeUnderruns"));
    return take ? take() : 0;
#else
    return 0;
#endif
}

void StatsPass() {
    AudioStats& s = Stats();
    if (!s.on) return;
    auto now = AudioStats::Clock::now();
    if (s.passes++ && s.last_pass.time_since_epoch().count()) {
        double gap = std::chrono::duration<double, std::milli>(now - s.last_pass).count();
        if (gap > s.max_gap_ms) s.max_gap_ms = gap;
    }
    s.last_pass = now;
    if (now - s.window >= std::chrono::seconds(5)) {
        uint32_t underruns = RingUnderruns();
        if (s.level >= 2 || s.starved || underruns)
            Log("audio: %u passes, max gap %.1f ms, guest %.1f ms (max %.2f), starved %u, underruns %u, submits %u",
                s.passes, s.max_gap_ms, s.guest_ms, s.max_guest_ms, s.starved, underruns, s.submits);
        s.window = now;
        s.passes = s.starved = s.submits = 0;
        s.max_gap_ms = s.guest_ms = s.max_guest_ms = 0;
    }
}
uint32_t GuestPtr(void* p) { return Addr(p); }

VoiceCallback* Vcb(FAudioVoiceCallback* cb) { return reinterpret_cast<VoiceCallback*>(cb); }

void OnPassStart(FAudioVoiceCallback* cb, uint32_t bytes) {
    EnsureGuestThread();
    StatsPass();
    if (bytes) ++Stats().starved;
    GuestTimer t;
    GuestCall(Method(Vcb(cb)->guest, 0), {Vcb(cb)->guest, bytes});
}
void OnPassEnd(FAudioVoiceCallback* cb) {
    EnsureGuestThread();
    GuestTimer t;
    GuestCall(Method(Vcb(cb)->guest, 1), {Vcb(cb)->guest});
}
void OnStreamEnd(FAudioVoiceCallback* cb) {
    EnsureGuestThread();
    GuestCall(Method(Vcb(cb)->guest, 2), {Vcb(cb)->guest});
}
void OnBufferStart(FAudioVoiceCallback* cb, void* ctx) {
    EnsureGuestThread();
    GuestTimer t;
    GuestCall(Method(Vcb(cb)->guest, 3), {Vcb(cb)->guest, GuestPtr(ctx)});
}
void OnBufferEnd(FAudioVoiceCallback* cb, void* ctx) {
    EnsureGuestThread();
    GuestTimer t;
    GuestCall(Method(Vcb(cb)->guest, 4), {Vcb(cb)->guest, GuestPtr(ctx)});
}
void OnLoopEnd(FAudioVoiceCallback* cb, void* ctx) {
    EnsureGuestThread();
    GuestCall(Method(Vcb(cb)->guest, 5), {Vcb(cb)->guest, GuestPtr(ctx)});
}
void OnVoiceError(FAudioVoiceCallback* cb, void* ctx, uint32_t error) {
    EnsureGuestThread();
    GuestCall(Method(Vcb(cb)->guest, 6), {Vcb(cb)->guest, GuestPtr(ctx), error});
}

EngineCallback* Ecb(FAudioEngineCallback* cb) { return reinterpret_cast<EngineCallback*>(cb); }

void OnEnginePassStart(FAudioEngineCallback* cb) {
    EnsureGuestThread();
    GuestTimer t;
    GuestCall(Method(Ecb(cb)->guest, 0), {Ecb(cb)->guest});
}
void OnEnginePassEnd(FAudioEngineCallback* cb) {
    EnsureGuestThread();
    GuestTimer t;
    GuestCall(Method(Ecb(cb)->guest, 1), {Ecb(cb)->guest});
}
void OnCriticalError(FAudioEngineCallback* cb, uint32_t error) {
    EnsureGuestThread();
    GuestCall(Method(Ecb(cb)->guest, 2), {Ecb(cb)->guest, error});
}

// ---- argument conversion ----
// XAUDIO2_VOICE_SENDS (2.3): {UINT32 OutputCount; IXAudio2Voice** pOutputVoices}.
struct Sends {
    FAudioVoiceSends sends{};
    std::vector<FAudioSendDescriptor> list;
    FAudioVoiceSends* Get(uint32_t guest) {
        if (!guest) return nullptr;
        uint32_t n = R32(guest), voices = R32(guest + 4);
        list.resize(n);
        for (uint32_t i = 0; i < n; ++i) list[i] = {0, VoiceOf(R32(voices + 4 * i))};
        sends.SendCount = n;
        sends.pSends = list.data();
        return &sends;
    }
};

// XAUDIO2_EFFECT_CHAIN: the engine's driver never passes one; effects (XAPO objects) are not bridged.
FAudioEffectChain* Effects(uint32_t guest) {
    if (guest && R32(guest)) Log("xaudio2: effect chain with %u effects ignored", R32(guest));
    return nullptr;
}

// ---- IXAudio2 ----
#define M(name) void name(Ctx* c)

M(QueryInterface) {
    W32(Arg(c, 2), 0);
    Return(c, kE_NoInterface, 3);
}
M(AddRef) { Return(c, ++Obj(Arg(c, 0))->refs, 1); }
M(EngineRelease) {
    uint32_t g = Arg(c, 0);
    Object* o = Obj(g);
    uint32_t r = --o->refs;
    if (!r) {
        if (g_engine_audio == o->audio) g_engine_audio = nullptr;
        FAudio_Release(o->audio);
        for (EngineCallback* cb : o->engine_callbacks) delete cb;
        delete o;
        Forget(g);
    }
    Return(c, r, 1);
}
M(GetDeviceCount) {
    uint32_t n = 0;
    uint32_t hr = FAudio_GetDeviceCount(Obj(Arg(c, 0))->audio, &n);
    W32(Arg(c, 1), n);
    Return(c, hr, 2);
}
M(GetDeviceDetails) {
    FAudioDeviceDetails d;
    uint32_t hr = FAudio_GetDeviceDetails(Obj(Arg(c, 0))->audio, Arg(c, 1), &d);
    if (hr == 0) memcpy(Ptr<void>(Arg(c, 2)), &d, sizeof(d));  // same packed layout as XAUDIO2_DEVICE_DETAILS
    Return(c, hr, 3);
}
M(Initialize) {
    // A 21.33 ms mixing quantum instead of 10 ms: twice the slack for the engine's mixer thread before an underrun
    // (audible as stutter on phones), for a few ms more latency. Setting audio_quantum_1024.
#ifdef __ANDROID__
    const bool long_quantum = SettingInt("audio_quantum_1024", 1) != 0;
#else
    const bool long_quantum = SettingInt("audio_quantum_1024", 0) != 0;
#endif
    uint32_t flags = Arg(c, 1) | (long_quantum ? FAUDIO_1024_QUANTUM : 0);
    uint32_t hr = FAudio_Initialize(Obj(Arg(c, 0))->audio, flags, FAUDIO_DEFAULT_PROCESSOR);
    Log("xaudio2: Initialize(flags %x) -> %x", Arg(c, 1), hr);
    if (hr == 0) g_engine_audio = Obj(Arg(c, 0))->audio;
    Return(c, hr, 3);
}
M(RegisterForCallbacks) {
    Object* o = Obj(Arg(c, 0));
    auto* cb = new EngineCallback{{OnCriticalError, OnEnginePassEnd, OnEnginePassStart}, Arg(c, 1)};
    o->engine_callbacks.push_back(cb);
    Return(c, FAudio_RegisterForCallbacks(o->audio, &cb->fa), 2);
}
M(UnregisterForCallbacks) {
    Object* o = Obj(Arg(c, 0));
    for (size_t i = 0; i < o->engine_callbacks.size(); ++i) {
        if (o->engine_callbacks[i]->guest == Arg(c, 1)) {
            FAudio_UnregisterForCallbacks(o->audio, &o->engine_callbacks[i]->fa);
            delete o->engine_callbacks[i];
            o->engine_callbacks.erase(o->engine_callbacks.begin() + long(i));
            break;
        }
    }
    Return(c, 0, 2);
}
M(CreateSourceVoice) {
    // (this, ppSourceVoice, pSourceFormat, Flags, MaxFrequencyRatio, pCallback, pSendList, pEffectChain)
    Object* e = Obj(Arg(c, 0));
    auto* o = new Object(kSource);
    if (Arg(c, 5)) {
        o->callback = new VoiceCallback{{OnBufferEnd, OnBufferStart, OnLoopEnd, OnStreamEnd, OnVoiceError, OnPassEnd,
                                         OnPassStart},
                                        Arg(c, 5)};
    }
    Sends sends;
    FAudioSourceVoice* v = nullptr;
    const auto* fmt = Ptr<FAudioWaveFormatEx>(Arg(c, 2));
    uint32_t hr = FAudio_CreateSourceVoice(e->audio, &v, fmt, Arg(c, 3), ArgF(c, 4),
                                           o->callback ? &o->callback->fa : nullptr, sends.Get(Arg(c, 6)),
                                           Effects(Arg(c, 7)));
    Log("xaudio2: CreateSourceVoice(tag %u, %u ch, %u Hz, %u bit) -> %x", fmt->wFormatTag, fmt->nChannels,
        fmt->nSamplesPerSec, fmt->wBitsPerSample, hr);
    if (hr != 0) {
        delete o->callback;
        delete o;
        W32(Arg(c, 1), 0);
        Return(c, hr, 8);
        return;
    }
    o->voice = v;
    W32(Arg(c, 1), NewGuest(o));
    Return(c, 0, 8);
}
M(CreateSubmixVoice) {
    // (this, ppSubmixVoice, InputChannels, InputSampleRate, Flags, ProcessingStage, pSendList, pEffectChain)
    Object* e = Obj(Arg(c, 0));
    Sends sends;
    FAudioSubmixVoice* v = nullptr;
    uint32_t hr = FAudio_CreateSubmixVoice(e->audio, &v, Arg(c, 2), Arg(c, 3), Arg(c, 4), Arg(c, 5),
                                           sends.Get(Arg(c, 6)), Effects(Arg(c, 7)));
    W32(Arg(c, 1), hr == 0 ? NewGuest(new Object(kSubmix, nullptr, v)) : 0);
    Return(c, hr, 8);
}
M(CreateMasteringVoice) {
    // (this, ppMasteringVoice, InputChannels, InputSampleRate, Flags, DeviceIndex, pEffectChain)
    Object* e = Obj(Arg(c, 0));
    FAudioMasteringVoice* v = nullptr;
    uint32_t hr = FAudio_CreateMasteringVoice(e->audio, &v, Arg(c, 2), Arg(c, 3), Arg(c, 4), Arg(c, 5),
                                              Effects(Arg(c, 6)));
    Log("xaudio2: CreateMasteringVoice(%u ch, %u Hz, device %u) -> %x", Arg(c, 2), Arg(c, 3), Arg(c, 5), hr);
    W32(Arg(c, 1), hr == 0 ? NewGuest(new Object(kMastering, nullptr, v)) : 0);
    Return(c, hr, 7);
}
M(StartEngine) { Return(c, FAudio_StartEngine(Obj(Arg(c, 0))->audio), 1); }
M(StopEngine) {
    FAudio_StopEngine(Obj(Arg(c, 0))->audio);
    Return(c, 0, 1);
}
M(CommitChanges) { Return(c, FAudio_CommitOperationSet(Obj(Arg(c, 0))->audio, Arg(c, 1)), 2); }
M(GetPerformanceData) {
    memset(Ptr<void>(Arg(c, 1)), 0, 56);  // XAUDIO2_PERFORMANCE_DATA (2.3): counters are not reported
    Return(c, 0, 2);
}
M(SetDebugConfiguration) { Return(c, 0, 3); }

// ---- IXAudio2Voice (2.3) ----
M(GetVoiceDetails) {
    FAudioVoiceDetails d;
    FAudioVoice_GetVoiceDetails(VoiceOf(Arg(c, 0)), &d);
    uint32_t out = Arg(c, 1);
    W32(out, d.CreationFlags);
    W32(out + 4, d.InputChannels);
    W32(out + 8, d.InputSampleRate);
    Return(c, 0, 2);
}
M(SetOutputVoices) {
    Sends sends;
    Return(c, FAudioVoice_SetOutputVoices(VoiceOf(Arg(c, 0)), sends.Get(Arg(c, 1))), 2);
}
M(SetEffectChain) {
    Effects(Arg(c, 1));
    Return(c, 0, 2);
}
M(EnableEffect) { Return(c, 0, 3); }
M(DisableEffect) { Return(c, 0, 3); }
M(GetEffectState) {
    W32(Arg(c, 2), 0);
    Return(c, 0, 3);
}
M(SetEffectParameters) { Return(c, kE_InvalidArg, 5); }
M(GetEffectParameters) { Return(c, kE_InvalidArg, 4); }
M(SetFilterParameters) {
    Return(c, FAudioVoice_SetFilterParameters(VoiceOf(Arg(c, 0)), Ptr<FAudioFilterParameters>(Arg(c, 1)), Arg(c, 2)),
           3);
}
M(GetFilterParameters) {
    FAudioVoice_GetFilterParameters(VoiceOf(Arg(c, 0)), Ptr<FAudioFilterParameters>(Arg(c, 1)));
    Return(c, 0, 2);
}
M(SetVolume) { Return(c, FAudioVoice_SetVolume(VoiceOf(Arg(c, 0)), ArgF(c, 1), Arg(c, 2)), 3); }
M(GetVolume) {
    FAudioVoice_GetVolume(VoiceOf(Arg(c, 0)), Ptr<float>(Arg(c, 1)));
    Return(c, 0, 2);
}
M(SetChannelVolumes) {
    Return(c, FAudioVoice_SetChannelVolumes(VoiceOf(Arg(c, 0)), Arg(c, 1), Ptr<float>(Arg(c, 2)), Arg(c, 3)), 4);
}
M(GetChannelVolumes) {
    FAudioVoice_GetChannelVolumes(VoiceOf(Arg(c, 0)), Arg(c, 1), Ptr<float>(Arg(c, 2)));
    Return(c, 0, 3);
}
M(SetOutputMatrix) {
    Return(c, FAudioVoice_SetOutputMatrix(VoiceOf(Arg(c, 0)), VoiceOf(Arg(c, 1)), Arg(c, 2), Arg(c, 3),
                                          Ptr<float>(Arg(c, 4)), Arg(c, 5)),
           6);
}
M(GetOutputMatrix) {
    FAudioVoice_GetOutputMatrix(VoiceOf(Arg(c, 0)), VoiceOf(Arg(c, 1)), Arg(c, 2), Arg(c, 3), Ptr<float>(Arg(c, 4)));
    Return(c, 0, 5);
}
M(DestroyVoice) {
    uint32_t g = Arg(c, 0);
    Object* o = Obj(g);
    FAudioVoice_DestroyVoice(o->voice);  // waits for the mixing thread, so no callback runs afterwards
    delete o->callback;
    delete o;
    Forget(g);
    Return(c, 0, 1);
}

// ---- IXAudio2SourceVoice ----
M(Start) { Return(c, FAudioSourceVoice_Start(VoiceOf(Arg(c, 0)), Arg(c, 1), Arg(c, 2)), 3); }
M(Stop) { Return(c, FAudioSourceVoice_Stop(VoiceOf(Arg(c, 0)), Arg(c, 1), Arg(c, 2)), 3); }
M(SubmitSourceBuffer) {
    // XAUDIO2_BUFFER: Flags, AudioBytes, pAudioData, PlayBegin, PlayLength, LoopBegin, LoopLength, LoopCount, pContext
    uint32_t b = Arg(c, 1);
    FAudioBuffer buf;
    buf.Flags = R32(b);
    buf.AudioBytes = R32(b + 4);
    buf.pAudioData = Ptr<uint8_t>(R32(b + 8));
    buf.PlayBegin = R32(b + 12);
    buf.PlayLength = R32(b + 16);
    buf.LoopBegin = R32(b + 20);
    buf.LoopLength = R32(b + 24);
    buf.LoopCount = R32(b + 28);
    buf.pContext = Ptr<void>(R32(b + 32));
    FAudioBufferWMA wma, *pwma = nullptr;
    if (uint32_t w = Arg(c, 2)) {
        wma.pDecodedPacketCumulativeBytes = Ptr<uint32_t>(R32(w));
        wma.PacketCount = R32(w + 4);
        pwma = &wma;
    }
    ++Stats().submits;
    Return(c, FAudioSourceVoice_SubmitSourceBuffer(VoiceOf(Arg(c, 0)), &buf, pwma), 3);
}
M(FlushSourceBuffers) { Return(c, FAudioSourceVoice_FlushSourceBuffers(VoiceOf(Arg(c, 0))), 1); }
M(Discontinuity) { Return(c, FAudioSourceVoice_Discontinuity(VoiceOf(Arg(c, 0))), 1); }
M(ExitLoop) { Return(c, FAudioSourceVoice_ExitLoop(VoiceOf(Arg(c, 0)), Arg(c, 1)), 2); }
M(GetState) {
    FAudioVoiceState s;
    FAudioSourceVoice_GetState(VoiceOf(Arg(c, 0)), &s, 0);
    uint32_t out = Arg(c, 1);  // {pCurrentBufferContext, BuffersQueued, UINT64 SamplesPlayed}, packed
    W32(out, GuestPtr(s.pCurrentBufferContext));
    W32(out + 4, s.BuffersQueued);
    W32(out + 8, uint32_t(s.SamplesPlayed));
    W32(out + 12, uint32_t(s.SamplesPlayed >> 32));
    Return(c, 0, 2);
}
M(SetFrequencyRatio) { Return(c, FAudioSourceVoice_SetFrequencyRatio(VoiceOf(Arg(c, 0)), ArgF(c, 1), Arg(c, 2)), 3); }
M(GetFrequencyRatio) {
    FAudioSourceVoice_GetFrequencyRatio(VoiceOf(Arg(c, 0)), Ptr<float>(Arg(c, 1)));
    Return(c, 0, 2);
}

#undef M

const ImportFn kEngineMethods[] = {
    QueryInterface, AddRef, EngineRelease, GetDeviceCount, GetDeviceDetails, Initialize, RegisterForCallbacks,
    UnregisterForCallbacks, CreateSourceVoice, CreateSubmixVoice, CreateMasteringVoice, StartEngine, StopEngine,
    CommitChanges, GetPerformanceData, SetDebugConfiguration,
};
const ImportFn kVoiceMethods[] = {
    GetVoiceDetails, SetOutputVoices, SetEffectChain, EnableEffect, DisableEffect, GetEffectState,
    SetEffectParameters, GetEffectParameters, SetFilterParameters, GetFilterParameters, SetVolume, GetVolume,
    SetChannelVolumes, GetChannelVolumes, SetOutputMatrix, GetOutputMatrix, DestroyVoice,
};
const ImportFn kSourceMethods[] = {
    Start, Stop, SubmitSourceBuffer, FlushSourceBuffers, Discontinuity, ExitLoop, GetState, SetFrequencyRatio,
    GetFrequencyRatio,
};

// Vtables are built from import thunks registered under the pseudo-DLL "xaudio2.com".
std::vector<ImportDef> g_defs;
std::vector<std::string> g_names;

uint32_t BuildVtable(const char* prefix, std::initializer_list<std::pair<const ImportFn*, size_t>> parts) {
    size_t n = 0;
    for (auto& p : parts) n += p.second;
    uint32_t vt = HeapAlloc(uint32_t(4 * n));
    size_t k = 0;
    for (auto& p : parts) {
        for (size_t i = 0; i < p.second; ++i, ++k) {
            std::string name = std::string(prefix) + "#" + std::to_string(k);
            g_defs.push_back({"xaudio2.com", strdup(name.c_str()), p.first[i]});
            RegisterImports(&g_defs.back(), 1);
            W32(vt + uint32_t(4 * k), ImportThunk("xaudio2.com", g_defs.back().name));
        }
    }
    return vt;
}

void InitVtables() {
    static std::once_flag once;
    std::call_once(once, [] {
        constexpr size_t kE = sizeof(kEngineMethods) / sizeof(ImportFn);
        constexpr size_t kV = sizeof(kVoiceMethods) / sizeof(ImportFn);
        constexpr size_t kS = sizeof(kSourceMethods) / sizeof(ImportFn);
        g_defs.reserve(kE + 3 * kV + kS);  // ImportDef pointers must stay valid
        g_vtables[kEngine] = BuildVtable("IXAudio2", {{kEngineMethods, kE}});
        g_vtables[kSource] = BuildVtable("IXAudio2SourceVoice", {{kVoiceMethods, kV}, {kSourceMethods, kS}});
        g_vtables[kSubmix] = BuildVtable("IXAudio2SubmixVoice", {{kVoiceMethods, kV}});
        g_vtables[kMastering] = BuildVtable("IXAudio2MasteringVoice", {{kVoiceMethods, kV}});
    });
}

// {4c5e637a-16c7-4de3-9c46-5ed22181962d} CLSID_XAudio2 and {ef0aa05d-8075-4e5d-bead-45be0c3ccbb3}
// CLSID_XAudio2_Debug of XAudio2 2.3.
const uint8_t kClsidXAudio2[16] = {0x7a, 0x63, 0x5e, 0x4c, 0xc7, 0x16, 0xe3, 0x4d,
                                   0x9c, 0x46, 0x5e, 0xd2, 0x21, 0x81, 0x96, 0x2d};
const uint8_t kClsidXAudio2Debug[16] = {0x5d, 0xa0, 0x0a, 0xef, 0x75, 0x80, 0x5d, 0x4e,
                                        0xbe, 0xad, 0x45, 0xbe, 0x0c, 0x3c, 0xcb, 0xb3};

}  // namespace

// CoCreateInstance hook (misc.cpp): true when `clsid` is XAudio2 2.3; *hr and *out receive the result.
bool CreateXAudio2(uint32_t clsid, uint32_t out, uint32_t* hr) {
    if (memcmp(Ptr<void>(clsid), kClsidXAudio2, 16) != 0 && memcmp(Ptr<void>(clsid), kClsidXAudio2Debug, 16) != 0) {
        return false;
    }
    InitVtables();
    FAudio* audio = nullptr;
    if (FAudioCOMConstructEXT(&audio, 3) != 0) {
        *hr = kE_Fail;
        W32(out, 0);
        return true;
    }
    W32(out, NewGuest(new Object(kEngine, audio)));
    *hr = 0;
    return true;
}

}  // namespace native
