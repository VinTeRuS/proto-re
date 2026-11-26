// binkw32.dll for the native host: Bink 1 movies (intro logos, cutscenes, Web of Intrigue memories) decoded with
// FFmpeg's bink/binkaudio decoders. The engine uses the Bink 1.9 frame-buffer API: it creates one Y/Cr/Cb texture
// set per buffer, registers locked pointers to them (BinkRegisterFrameBuffers) and draws them with its own shader,
// so BinkDoFrame only writes the decoded planes there. Movies are read straight from the .rcf archives (or a loose
// file) instead of through the engine's BinkSetIO reader; sound goes to a source voice on the game's XAudio2 engine
// instead of the engine's Bink sound driver (BinkSetSoundSystem).
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <FAudio.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
}

#include "guest.h"

namespace native {

std::string HostPath(const char* win_path);  // kernel32.cpp
extern FAudio* g_engine_audio;               // xaudio2.cpp

namespace {

using Clock = std::chrono::steady_clock;
auto g_start = Clock::now();

// ---- .rcf lookup (tools/rcf.py has the format) ----

struct RcfEntry { uint32_t hash, offset, size; };
struct Rcf { std::string path; std::vector<RcfEntry> dir; };

uint32_t HashFileName(const char* s) {  // core::HashFileName, see tools/rcf.py name_hash
    if (*s == '\\') ++s;
    uint32_t h = 0;
    for (; *s; ++s) {
        int c = static_cast<signed char>(*s);
        if (c < 0x61) c += 0x20;
        h = h * 31 + uint32_t(c);
    }
    return h;
}

const std::vector<Rcf>& Archives() {
    static std::vector<Rcf> archives;
    static std::once_flag once;
    std::call_once(once, [] {
        DIR* d = opendir(g_game_dir);
        if (!d) return;
        while (dirent* e = readdir(d)) {
            std::string n = e->d_name;
            if (n.size() < 4 || strcasecmp(n.c_str() + n.size() - 4, ".rcf") != 0) continue;
            Rcf r{std::string(g_game_dir) + "/" + n, {}};
            int fd = open(r.path.c_str(), O_RDONLY);
            uint32_t head[7];
            if (fd >= 0 && pread(fd, head, sizeof(head), 0x24) == sizeof(head) && head[1] == head[6] * 12) {
                r.dir.resize(head[6]);
                if (pread(fd, r.dir.data(), head[1], head[0]) != ssize_t(head[1])) r.dir.clear();
            }
            if (fd >= 0) close(fd);
            if (!r.dir.empty()) archives.push_back(std::move(r));
        }
        closedir(d);
    });
    return archives;
}

struct Source { std::string path; uint64_t offset = 0, size = 0; };

bool FindMovie(const char* name, Source* out) {
    std::string host = HostPath(name);
    if (FILE* f = fopen(host.c_str(), "rb")) {
        fseek(f, 0, SEEK_END);
        *out = {host, 0, uint64_t(ftell(f))};
        fclose(f);
        return true;
    }
    // The name may carry a drive or directories in front of the archive path ("movies\woi\woi_ec1.bik"): try every
    // suffix that starts after a separator.
    std::string n = name;
    std::replace(n.begin(), n.end(), '/', '\\');
    for (size_t pos = 0; pos < n.size(); pos = n.find('\\', pos) + 1) {
        uint32_t h = HashFileName(n.c_str() + pos);
        for (const Rcf& r : Archives()) {
            auto it = std::lower_bound(r.dir.begin(), r.dir.end(), h,
                                       [](const RcfEntry& e, uint32_t v) { return e.hash < v; });
            if (it != r.dir.end() && it->hash == h) {
                *out = {r.path, it->offset, it->size};
                return true;
            }
        }
        if (n.find('\\', pos) == std::string::npos) break;
    }
    return false;
}

// ---- movie ----

// Guest layouts (Bink 1.9 bink.h).
enum : uint32_t { kWidth = 0x0, kHeight = 0x4, kFrames = 0x8, kFrameNum = 0xc, kLastFrameNum = 0x10,
                  kFrameRate = 0x14, kFrameRateDiv = 0x18, kOpenFlags = 0x20, kBinkSize = 0x200 };
// BINKFRAMEBUFFERS: TotalFrames, YA w/h, cRcB w/h, FrameNum, then per buffer {Y, cR, cB, A} planes of
// {Allocate, Buffer, BufferPitch}.
enum : uint32_t { kFbTotal = 0x0, kFbYW = 0x4, kFbYH = 0x8, kFbCW = 0xc, kFbCH = 0x10, kFbNum = 0x14, kFbSets = 0x18,
                  kFbSize = 0x18 + 0x30 };

struct Movie {
    int fd = -1;
    Source src;
    int64_t pos = 0;
    AVFormatContext* fmt = nullptr;
    AVCodecContext* vdec = nullptr;
    AVCodecContext* adec = nullptr;
    int vstream = -1, astream = -1;
    AVPacket* pkt = nullptr;
    AVFrame* frame = nullptr;
    uint32_t fb = 0;  // registered BINKFRAMEBUFFERS
    bool paused = false;
    Clock::duration interval{};
    Clock::time_point due{};
    // Sound: buffers stay alive until the voice is done with them (OnBufferEnd counts them).
    FAudioSourceVoice* voice = nullptr;
    FAudioVoiceCallback cb{};
    std::atomic<uint32_t> played{0};
    std::deque<std::vector<float>> queued;
    uint32_t freed = 0;
};

std::mutex g_mutex;
std::map<uint32_t, Movie*> g_movies;
uint32_t g_sound_track = 0;  // BinkSetSoundTrack: the track id to play (first of the list)

Movie* Get(uint32_t h) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_movies.find(h);
    return it == g_movies.end() ? nullptr : it->second;
}

int ReadPacket(void* opaque, uint8_t* buf, int size) {
    auto* m = static_cast<Movie*>(opaque);
    int64_t left = int64_t(m->src.size) - m->pos;
    if (left <= 0) return AVERROR_EOF;
    ssize_t r = pread(m->fd, buf, size_t(std::min<int64_t>(size, left)), off_t(m->src.offset + m->pos));
    if (r <= 0) return AVERROR_EOF;
    m->pos += r;
    return int(r);
}

int64_t SeekPacket(void* opaque, int64_t offset, int whence) {
    auto* m = static_cast<Movie*>(opaque);
    if (whence & AVSEEK_SIZE) return int64_t(m->src.size);
    whence &= ~AVSEEK_FORCE;
    int64_t p = whence == SEEK_SET ? offset : whence == SEEK_CUR ? m->pos + offset : int64_t(m->src.size) + offset;
    if (p < 0) return -1;
    m->pos = p;
    return p;
}

void FreeMovie(Movie* m) {
    if (m->voice) FAudioVoice_DestroyVoice(m->voice);
    avcodec_free_context(&m->vdec);
    avcodec_free_context(&m->adec);
    if (m->fmt) {
        AVIOContext* io = m->fmt->pb;
        avformat_close_input(&m->fmt);
        if (io) av_freep(&io->buffer);
        avio_context_free(&io);
    }
    av_packet_free(&m->pkt);
    av_frame_free(&m->frame);
    if (m->fd >= 0) close(m->fd);
    delete m;
}

AVCodecContext* OpenDecoder(AVStream* st) {
    const AVCodec* codec = avcodec_find_decoder(st->codecpar->codec_id);
    AVCodecContext* ctx = codec ? avcodec_alloc_context3(codec) : nullptr;
    if (ctx && (avcodec_parameters_to_context(ctx, st->codecpar) < 0 || avcodec_open2(ctx, codec, nullptr) < 0)) {
        avcodec_free_context(&ctx);
    }
    return ctx;
}

void OnBufferEnd(FAudioVoiceCallback*, void* movie) { static_cast<Movie*>(movie)->played++; }

void OpenSound(Movie* m) {
    if (!g_engine_audio || !m->adec || m->adec->sample_fmt != AV_SAMPLE_FMT_FLTP) return;
    FAudioWaveFormatEx wf{};
    wf.wFormatTag = FAUDIO_FORMAT_IEEE_FLOAT;
    wf.nChannels = uint16_t(m->adec->ch_layout.nb_channels);
    wf.nSamplesPerSec = uint32_t(m->adec->sample_rate);
    wf.wBitsPerSample = 32;
    wf.nBlockAlign = uint16_t(wf.nChannels * 4);
    wf.nAvgBytesPerSec = wf.nSamplesPerSec * wf.nBlockAlign;
    m->cb.OnBufferEnd = OnBufferEnd;
    if (FAudio_CreateSourceVoice(g_engine_audio, &m->voice, &wf, 0, 2.0f, &m->cb, nullptr, nullptr) != 0) {
        m->voice = nullptr;
        return;
    }
    FAudioSourceVoice_Start(m->voice, 0, FAUDIO_COMMIT_NOW);
}

void DecodeSound(Movie* m, AVPacket* pkt) {
    if (!m->adec || avcodec_send_packet(m->adec, pkt) < 0) return;
    while (avcodec_receive_frame(m->adec, m->frame) == 0) {
        if (!m->voice) continue;
        int ch = m->adec->ch_layout.nb_channels, n = m->frame->nb_samples;
        std::vector<float> pcm(size_t(ch) * size_t(n));
        for (int i = 0; i < n; ++i)
            for (int c = 0; c < ch; ++c) pcm[size_t(i * ch + c)] = reinterpret_cast<float*>(m->frame->extended_data[c])[i];
        m->queued.push_back(std::move(pcm));
        FAudioBuffer b{};
        b.AudioBytes = uint32_t(m->queued.back().size() * sizeof(float));
        b.pAudioData = reinterpret_cast<uint8_t*>(m->queued.back().data());
        b.pContext = m;
        FAudioSourceVoice_SubmitSourceBuffer(m->voice, &b, nullptr);
    }
    for (uint32_t done = m->played; m->freed < done && !m->queued.empty(); ++m->freed) m->queued.pop_front();
}

// Reads packets until the next video frame is decoded; sound packets on the way are played.
bool DecodeVideo(Movie* m) {
    for (;;) {
        int r = avcodec_receive_frame(m->vdec, m->frame);
        if (r == 0) return true;
        if (r != AVERROR(EAGAIN)) return false;
        if (av_read_frame(m->fmt, m->pkt) < 0) {
            avcodec_send_packet(m->vdec, nullptr);
            return avcodec_receive_frame(m->vdec, m->frame) == 0;
        }
        if (m->pkt->stream_index == m->vstream) avcodec_send_packet(m->vdec, m->pkt);
        else if (m->pkt->stream_index == m->astream) DecodeSound(m, m->pkt);
        av_packet_unref(m->pkt);
    }
}

void CopyPlane(const uint8_t* src, int src_pitch, uint32_t plane, int w, int h) {
    uint32_t buf = R32(plane + 4);
    int32_t pitch = int32_t(R32(plane + 8));
    if (!R32(plane) || !buf) return;
    for (int y = 0; y < h; ++y) memcpy(Ptr<uint8_t>(uint32_t(int64_t(buf) + int64_t(y) * pitch)), src + y * src_pitch, size_t(w));
}

Movie* Open(const char* name) {
    auto* m = new Movie;
    if (!FindMovie(name, &m->src) || (m->fd = open(m->src.path.c_str(), O_RDONLY)) < 0) {
        Log("bink: %s not found", name);
        FreeMovie(m);
        return nullptr;
    }
    const int kIoSize = 1 << 16;
    auto* iobuf = static_cast<uint8_t*>(av_malloc(kIoSize));
    AVIOContext* io = avio_alloc_context(iobuf, kIoSize, 0, m, ReadPacket, nullptr, SeekPacket);
    m->fmt = avformat_alloc_context();
    m->fmt->pb = io;
    if (avformat_open_input(&m->fmt, nullptr, nullptr, nullptr) < 0 || avformat_find_stream_info(m->fmt, nullptr) < 0) {
        Log("bink: %s: not a Bink file", name);
        if (!m->fmt) {  // avformat_open_input frees the context on failure, not our I/O context
            av_freep(&io->buffer);
            avio_context_free(&io);
        }
        FreeMovie(m);
        return nullptr;
    }
    for (unsigned i = 0; i < m->fmt->nb_streams; ++i) {
        AVStream* st = m->fmt->streams[i];
        if (st->codecpar->codec_type == AVMEDIA_TYPE_VIDEO && m->vstream < 0) m->vstream = int(i);
        if (st->codecpar->codec_type == AVMEDIA_TYPE_AUDIO &&
            (m->astream < 0 || uint32_t(st->id) == g_sound_track)) m->astream = int(i);
    }
    for (unsigned i = 0; i < m->fmt->nb_streams; ++i)
        if (int(i) != m->vstream && int(i) != m->astream) m->fmt->streams[i]->discard = AVDISCARD_ALL;
    if (m->vstream < 0 || !(m->vdec = OpenDecoder(m->fmt->streams[m->vstream]))) {
        Log("bink: %s: no video decoder", name);
        FreeMovie(m);
        return nullptr;
    }
    if (m->astream >= 0) m->adec = OpenDecoder(m->fmt->streams[m->astream]);
    m->pkt = av_packet_alloc();
    m->frame = av_frame_alloc();
    OpenSound(m);
    return m;
}

#define B(name) void b_##name(Ctx* c)

B(BinkSetMemory) { Return(c, 0, 2); }
B(BinkSetIO) { Return(c, 0, 1); }
B(BinkSetSoundSystem) { Return(c, 1, 2); }
B(BinkSetSoundTrack) {
    if (Arg(c, 0) && Arg(c, 1)) g_sound_track = R32(Arg(c, 1));
    Return(c, 0, 2);
}
B(BinkOpen) {
    const char* name = Arg(c, 0) ? Str(Arg(c, 0)) : "";
    Movie* m = Open(name);
    if (!m) {
        Return(c, 0, 2);
        return;
    }
    AVStream* st = m->fmt->streams[m->vstream];
    AVRational rate = st->avg_frame_rate.num ? st->avg_frame_rate : av_inv_q(st->time_base);
    uint32_t h = HeapAlloc(kBinkSize);
    memset(Ptr<void>(h), 0, kBinkSize);
    W32(h + kWidth, uint32_t(m->vdec->width));
    W32(h + kHeight, uint32_t(m->vdec->height));
    uint32_t frames = uint32_t(st->nb_frames > 0 ? st->nb_frames : st->duration);
    W32(h + kFrames, frames);
    W32(h + kFrameNum, 1);
    W32(h + kFrameRate, uint32_t(rate.num));
    W32(h + kFrameRateDiv, uint32_t(rate.den));
    W32(h + kOpenFlags, Arg(c, 1));
    m->interval = std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(av_q2d(av_inv_q(rate))));
    m->due = Clock::now();
    Log("bink: BinkOpen(%s) -> %ux%u, %u frames at %d/%d, sound %s", name, m->vdec->width, m->vdec->height,
        frames, rate.num, rate.den, m->voice ? "on" : "off");
    std::lock_guard<std::mutex> lock(g_mutex);
    g_movies[h] = m;
    Return(c, h, 2);
}
B(BinkClose) {
    uint32_t h = Arg(c, 0);
    Movie* m = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_movies.find(h);
        if (it != g_movies.end()) {
            m = it->second;
            g_movies.erase(it);
        }
    }
    if (m) {
        FreeMovie(m);
        HeapFree(h);
    }
    Return(c, 0, 1);
}
// 0 when the next frame is due.
B(BinkWait) {
    Movie* m = Get(Arg(c, 0));
    Return(c, m && (m->paused || Clock::now() < m->due) ? 1 : 0, 1);
}
B(BinkDoFrame) {
    uint32_t h = Arg(c, 0);
    Movie* m = Get(h);
    if (m && DecodeVideo(m)) {
        W32(h + kLastFrameNum, R32(h + kFrameNum));
        if (m->fb) {
            uint32_t set = m->fb + kFbSets + 0x30 * R32(m->fb + kFbNum);
            AVFrame* f = m->frame;
            int cw = (f->width + 1) / 2, ch = (f->height + 1) / 2;
            CopyPlane(f->data[0], f->linesize[0], set + 0x00, f->width, f->height);
            CopyPlane(f->data[2], f->linesize[2], set + 0x0c, cw, ch);  // cR = V
            CopyPlane(f->data[1], f->linesize[1], set + 0x18, cw, ch);  // cB = U
        }
    }
    Return(c, 0, 1);
}
B(BinkNextFrame) {
    uint32_t h = Arg(c, 0);
    if (Movie* m = Get(h)) {
        W32(h + kFrameNum, R32(h + kFrameNum) + 1);
        m->due += m->interval;
        if (Clock::now() - m->due > m->interval * 8) m->due = Clock::now();  // after a hitch, don't race to catch up
    }
    Return(c, 0, 1);
}
B(BinkPause) {
    uint32_t h = Arg(c, 0);
    Movie* m = Get(h);
    bool on = Arg(c, 1) != 0;
    if (m && on != m->paused) {
        m->paused = on;
        if (!on) m->due = Clock::now();
        if (m->voice) {
            if (on) FAudioSourceVoice_Stop(m->voice, 0, FAUDIO_COMMIT_NOW);
            else FAudioSourceVoice_Start(m->voice, 0, FAUDIO_COMMIT_NOW);
        }
    }
    Return(c, on, 2);
}
B(BinkGetFrameBuffersInfo) {
    uint32_t h = Arg(c, 0), fb = Arg(c, 1);
    uint32_t w = R32(h + kWidth), ht = R32(h + kHeight);
    memset(Ptr<void>(fb), 0, kFbSize);
    W32(fb + kFbTotal, 1);
    W32(fb + kFbYW, w);
    W32(fb + kFbYH, ht);
    W32(fb + kFbCW, (w + 1) / 2);
    W32(fb + kFbCH, (ht + 1) / 2);
    for (uint32_t p = 0; p < 3; ++p) W32(fb + kFbSets + 0xc * p, 1);  // Y, cR, cB; no alpha plane
    Return(c, 0, 2);
}
B(BinkRegisterFrameBuffers) {
    if (Movie* m = Get(Arg(c, 0))) m->fb = Arg(c, 1);
    Return(c, 0, 2);
}
// Volume 32768 = full.
B(BinkSetVolume) {
    if (Movie* m = Get(Arg(c, 0)); m && m->voice) FAudioVoice_SetVolume(m->voice, float(Arg(c, 2)) / 32768.0f, 0);
    Return(c, 0, 3);
}
B(BinkSetMixBins) { Return(c, 0, 4); }
B(BinkOpenTrack) { Return(c, 0, 2); }
B(BinkCloseTrack) { Return(c, 0, 1); }
B(RADTimerRead) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - g_start);
    Return(c, uint32_t(ms.count()), 0);
}

#undef B

#define E(name, args) {"binkw32.dll", "_" #name "@" #args, b_##name}
const ImportDef kBink[] = {
    E(BinkSetMemory, 8), E(BinkSetIO, 4), E(BinkSetSoundSystem, 8), E(BinkSetSoundTrack, 8), E(BinkOpen, 8),
    E(BinkClose, 4), E(BinkWait, 4), E(BinkDoFrame, 4), E(BinkNextFrame, 4), E(BinkPause, 8),
    E(BinkGetFrameBuffersInfo, 8), E(BinkRegisterFrameBuffers, 8), E(BinkSetVolume, 12), E(BinkSetMixBins, 16),
    E(BinkOpenTrack, 8), E(BinkCloseTrack, 4), E(RADTimerRead, 0),
};
#undef E
ImportRegistrar g_bink(kBink);

}  // namespace

}  // namespace native
