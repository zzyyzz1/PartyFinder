#include "PartyFinder.h"
#include <algorithm>
#include <cstring>
#include <ctime>
#include <intrin.h>
#include <psapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

namespace
{
    using recv_t = int (WSAAPI*)(SOCKET, char*, int, int);
    recv_t g_recv = nullptr;
    ULONG_PTR* g_recvSlot = nullptr;
    std::atomic<long> g_shutdown{0};
    std::atomic<long> g_inflight{0};
    std::atomic<bool> g_armed{false};

    constexpr size_t kSlotCount = 256;
    constexpr size_t kMaxPayload = 8192;
    struct CaptureSlot {
        std::atomic<long> ready{0};
        uint32_t len{};
        uint32_t tick{};
        std::array<uint8_t, kMaxPayload> data{};
    };
    std::array<CaptureSlot, kSlotCount> g_slots;
    std::atomic<uint32_t> g_write{0};
    std::atomic<uint32_t> g_read{0};
    std::atomic<uint32_t> g_dropped{0};

    struct HookGuard {
        HookGuard() { g_inflight.fetch_add(1, std::memory_order_acq_rel); }
        ~HookGuard() { g_inflight.fetch_sub(1, std::memory_order_acq_rel); }
    };

    static void QueueCapture(const char* buf, int len)
    {
        if (!g_armed.load(std::memory_order_acquire) || !buf || len <= 0) return;
        const uint32_t w = g_write.fetch_add(1, std::memory_order_acq_rel);
        CaptureSlot& s = g_slots[w % kSlotCount];
        if (s.ready.exchange(1, std::memory_order_acq_rel) != 0) {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        s.len = (uint32_t)std::min<int>(len, (int)kMaxPayload);
        s.tick = GetTickCount();
        std::memcpy(s.data.data(), buf, s.len);
        s.ready.store(2, std::memory_order_release);
    }

    static int WSAAPI HookRecv(SOCKET s, char* buf, int len, int flags)
    {
        recv_t original = g_recv;
        if (!original) return SOCKET_ERROR;
        HookGuard guard;
        const int ret = original(s, buf, len, flags);
        if (!g_shutdown.load(std::memory_order_acquire) && ret > 0)
            QueueCapture(buf, ret);
        return ret;
    }

    static bool ieq(const char* a, const char* b)
    {
        return a && b && _stricmp(a, b) == 0;
    }

    static bool InstallRecvHook()
    {
        HMODULE module = GetModuleHandleA(nullptr);
        if (!module) return false;
        auto base = reinterpret_cast<uint8_t*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress) return false;
        auto imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
        for (; imp->Name; ++imp) {
            const char* dll = reinterpret_cast<const char*>(base + imp->Name);
            if (!ieq(dll, "ws2_32.dll") && !ieq(dll, "wsock32.dll")) continue;
            auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);
            auto names = imp->OriginalFirstThunk ? reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->OriginalFirstThunk) : thunk;
            for (; names->u1.AddressOfData; ++names, ++thunk) {
                if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
                auto ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
                if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), "recv") != 0) continue;
                auto slot = reinterpret_cast<ULONG_PTR*>(&thunk->u1.Function);
                DWORD oldProtect{};
                if (!VirtualProtect(slot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect)) return false;
                g_recv = reinterpret_cast<recv_t>(*slot);
                g_recvSlot = slot;
                *slot = reinterpret_cast<ULONG_PTR>(&HookRecv);
                FlushInstructionCache(GetCurrentProcess(), slot, sizeof(ULONG_PTR));
                DWORD ignored{};
                VirtualProtect(slot, sizeof(ULONG_PTR), oldProtect, &ignored);
                return g_recv != nullptr;
            }
        }
        return false;
    }

    static void RemoveRecvHook()
    {
        g_shutdown.store(1, std::memory_order_release);
        if (g_recvSlot && g_recv) {
            DWORD oldProtect{};
            if (VirtualProtect(g_recvSlot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect)) {
                *g_recvSlot = reinterpret_cast<ULONG_PTR>(g_recv);
                FlushInstructionCache(GetCurrentProcess(), g_recvSlot, sizeof(ULONG_PTR));
                DWORD ignored{};
                VirtualProtect(g_recvSlot, sizeof(ULONG_PTR), oldProtect, &ignored);
            }
        }
        for (int i = 0; i < 500 && g_inflight.load(std::memory_order_acquire) != 0; ++i) Sleep(1);
        g_recvSlot = nullptr;
        g_recv = nullptr;
    }

    static std::string HexPreview(const uint8_t* p, size_t n)
    {
        char tmp[4];
        std::string out;
        n = std::min<size_t>(n, 64);
        for (size_t i = 0; i < n; ++i) {
            sprintf_s(tmp, "%02X", p[i]);
            if (i) out.push_back(' ');
            out += tmp;
        }
        return out;
    }
}

__declspec(dllexport) IPlugin* __stdcall expCreatePlugin(const char*) { return (IPlugin*)(new PartyFinder()); }
__declspec(dllexport) void __stdcall expDestroyPlugin(void* instance) { delete static_cast<PartyFinder*>(instance); }
__declspec(dllexport) double __stdcall expGetInterfaceVersion(void) { return ASHITA_INTERFACE_VERSION; }

bool PartyFinder::Initialize(IAshitaCore* core, ILogManager* logger, const uint32_t id)
{
    m_core = core; m_log = logger; m_id = id;
    g_shutdown.store(0);
    m_hookInstalled = InstallRecvHook();
    if (m_log) m_log->Log((uint32_t)(m_hookInstalled ? Ashita::LogLevel::Info : Ashita::LogLevel::Error), "PartyFinder",
        m_hookInstalled ? "recv hook installed. Use /pfcap before /sea." : "recv import not found; hook not installed.");
    return true;
}

void PartyFinder::Release(void)
{
    StopCapture();
    RemoveRecvHook();
}

bool PartyFinder::HandleCommand(int32_t, const char* command, bool)
{
    if (!command) return false;
    if (_stricmp(command, "/pfcap") == 0) { StartCapture(); return true; }
    if (_stricmp(command, "/pfcap stop") == 0) { StopCapture(); return true; }
    if (_stricmp(command, "/pfcap status") == 0) { PrintStatus(); return true; }
    return false;
}

void PartyFinder::StartCapture()
{
    if (!m_hookInstalled) { PrintStatus(); return; }
    CloseCaptureFiles();
    if (!OpenCaptureFiles()) return;
    g_dropped.store(0);
    m_captureUntil = GetTickCount64() + 15000;
    g_armed.store(true, std::memory_order_release);
    if (m_log) m_log->Log((uint32_t)Ashita::LogLevel::Info, "PartyFinder", "Raw recv capture armed for 15 seconds. Run /sea now.");
}

void PartyFinder::StopCapture()
{
    g_armed.store(false, std::memory_order_release);
    m_captureUntil = 0;
    FlushCapture();
    CloseCaptureFiles();
    if (m_log) m_log->Log((uint32_t)Ashita::LogLevel::Info, "PartyFinder", "Capture stopped.");
}

void PartyFinder::PrintStatus()
{
    if (!m_log) return;
    char msg[160];
    sprintf_s(msg, "[PartyFinder] hook=%s capture=%s dropped=%u", m_hookInstalled ? "yes" : "no", g_armed.load() ? "armed" : "off", g_dropped.load());
    m_log->Log((uint32_t)Ashita::LogLevel::Info, "PartyFinder", msg);
}

bool PartyFinder::OpenCaptureFiles()
{
    if (!m_core) return false;
    char dir[MAX_PATH];
    sprintf_s(dir, "%sconfig\\plugins\\partyfinder\\captures", m_core->GetInstallPath());
    CreateDirectoryA((std::string(m_core->GetInstallPath()) + "config\\plugins").c_str(), nullptr);
    CreateDirectoryA((std::string(m_core->GetInstallPath()) + "config\\plugins\\partyfinder").c_str(), nullptr);
    CreateDirectoryA(dir, nullptr);
    SYSTEMTIME st{}; GetLocalTime(&st);
    char base[MAX_PATH];
    sprintf_s(base, "%s\\partyfinder_recv_%04u%02u%02u_%02u%02u%02u", dir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fopen_s(&m_bin, (std::string(base) + ".bin").c_str(), "wb");
    fopen_s(&m_txt, (std::string(base) + ".txt").c_str(), "wt");
    if (!m_bin || !m_txt) { CloseCaptureFiles(); return false; }
    fprintf(m_txt, "PartyFinder v0.13 raw recv capture\nHook: main-module IAT recv only\nNo packet modification/injection\n\n");
    return true;
}

void PartyFinder::CloseCaptureFiles()
{
    if (m_bin) { fclose(m_bin); m_bin = nullptr; }
    if (m_txt) { fprintf(m_txt, "Dropped slots: %u\n", g_dropped.load()); fclose(m_txt); m_txt = nullptr; }
}

void PartyFinder::FlushCapture()
{
    if (!m_bin || !m_txt) return;
    for (;;) {
        const uint32_t r = g_read.load(std::memory_order_acquire);
        CaptureSlot& s = g_slots[r % kSlotCount];
        if (s.ready.load(std::memory_order_acquire) != 2) break;
        const uint32_t len = s.len;
        fwrite(&s.tick, sizeof(s.tick), 1, m_bin);
        fwrite(&len, sizeof(len), 1, m_bin);
        fwrite(s.data.data(), 1, len, m_bin);
        const auto hex = HexPreview(s.data.data(), len);
        fprintf(m_txt, "tick=%u len=%u hex=%s\n", s.tick, len, hex.c_str());
        s.ready.store(0, std::memory_order_release);
        g_read.store(r + 1, std::memory_order_release);
    }
    fflush(m_bin); fflush(m_txt);
}

void PartyFinder::Direct3DPresent(const RECT*, const RECT*, HWND, const RGNDATA*)
{
    FlushCapture();
    if (g_armed.load(std::memory_order_acquire) && m_captureUntil && GetTickCount64() >= m_captureUntil) {
        g_armed.store(false, std::memory_order_release);
        FlushCapture();
        CloseCaptureFiles();
        m_captureUntil = 0;
        if (m_log) m_log->Log((uint32_t)Ashita::LogLevel::Info, "PartyFinder", "15-second recv capture complete.");
    }
}
