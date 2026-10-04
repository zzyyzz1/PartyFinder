#include "PartyFinder.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstring>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

namespace
{
    using recv_t = int (WSAAPI*)(SOCKET, char*, int, int);

    struct HookSlot
    {
        ULONG_PTR* slot{};
        ULONG_PTR original{};
        char module[MAX_PATH]{};
    };

    constexpr size_t kMaxHooks = 64;
    constexpr size_t kSlotCount = 512;
    constexpr size_t kMaxPayload = 16384;

    struct CaptureSlot
    {
        std::atomic<long> ready{0};
        uint32_t len{};
        uint32_t tick{};
        std::array<uint8_t, kMaxPayload> data{};
    };

    std::array<HookSlot, kMaxHooks> g_hooks{};
    size_t g_hookCount = 0;
    recv_t g_originalRecv = nullptr;
    std::atomic<long> g_shutdown{0};
    std::atomic<long> g_inflight{0};
    std::atomic<bool> g_armed{false};
    std::array<CaptureSlot, kSlotCount> g_slots{};
    std::atomic<uint32_t> g_write{0};
    std::atomic<uint32_t> g_read{0};
    std::atomic<uint32_t> g_dropped{0};

    struct HookGuard
    {
        HookGuard() { g_inflight.fetch_add(1, std::memory_order_acq_rel); }
        ~HookGuard() { g_inflight.fetch_sub(1, std::memory_order_acq_rel); }
    };

    static void Chat(IAshitaCore* core, const char* message)
    {
        if (core && core->GetChatManager() && message)
            core->GetChatManager()->Write(1, false, message);
    }

    static std::string TrimLower(const char* text)
    {
        std::string s = text ? text : "";
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    static bool IsWinsockDll(const char* name)
    {
        return name && (_stricmp(name, "ws2_32.dll") == 0 || _stricmp(name, "wsock32.dll") == 0);
    }

    static bool FindRecvIatSlot(HMODULE module, ULONG_PTR** outSlot)
    {
        if (!module || !outSlot) return false;
        *outSlot = nullptr;

        auto base = reinterpret_cast<uint8_t*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size) return false;

        auto imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
        for (; imp->Name; ++imp)
        {
            const char* dll = reinterpret_cast<const char*>(base + imp->Name);
            if (!IsWinsockDll(dll)) continue;

            auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);
            auto names = imp->OriginalFirstThunk
                ? reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->OriginalFirstThunk)
                : nullptr;
            if (!names) continue;

            for (; names->u1.AddressOfData; ++names, ++thunk)
            {
                if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
                auto ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
                if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), "recv") == 0)
                {
                    *outSlot = reinterpret_cast<ULONG_PTR*>(&thunk->u1.Function);
                    return true;
                }
            }
        }
        return false;
    }

    static void QueueCapture(const char* buf, int len)
    {
        if (!g_armed.load(std::memory_order_acquire) || !buf || len <= 0) return;

        const uint32_t w = g_write.load(std::memory_order_relaxed);
        CaptureSlot& s = g_slots[w % kSlotCount];
        long expected = 0;
        if (!s.ready.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
        {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        s.len = static_cast<uint32_t>(std::min<int>(len, static_cast<int>(kMaxPayload)));
        s.tick = GetTickCount();
        std::memcpy(s.data.data(), buf, s.len);
        s.ready.store(2, std::memory_order_release);
        g_write.store(w + 1, std::memory_order_release);
    }

    static int WSAAPI HookRecv(SOCKET s, char* buf, int len, int flags)
    {
        recv_t original = g_originalRecv;
        if (!original) return SOCKET_ERROR;

        HookGuard guard;
        const int ret = original(s, buf, len, flags);
        if (!g_shutdown.load(std::memory_order_acquire) && ret > 0)
            QueueCapture(buf, ret);
        return ret;
    }

    static bool InstallRecvHooks(size_t& skippedDifferentTargets)
    {
        skippedDifferentTargets = 0;
        g_hookCount = 0;
        g_originalRecv = nullptr;

        HMODULE modules[512]{};
        DWORD needed = 0;
        HANDLE process = GetCurrentProcess();
        if (!EnumProcessModules(process, modules, sizeof(modules), &needed)) return false;

        const size_t count = std::min<size_t>(needed / sizeof(HMODULE), std::size(modules));
        for (size_t i = 0; i < count && g_hookCount < kMaxHooks; ++i)
        {
            ULONG_PTR* slot = nullptr;
            if (!FindRecvIatSlot(modules[i], &slot) || !slot) continue;

            const ULONG_PTR current = *slot;
            if (!current) continue;

            if (!g_originalRecv)
                g_originalRecv = reinterpret_cast<recv_t>(current);
            else if (current != reinterpret_cast<ULONG_PTR>(g_originalRecv))
            {
                ++skippedDifferentTargets;
                continue;
            }

            DWORD oldProtect = 0;
            if (!VirtualProtect(slot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect)) continue;

            HookSlot& h = g_hooks[g_hookCount];
            h.slot = slot;
            h.original = current;
            GetModuleFileNameA(modules[i], h.module, MAX_PATH);

            *slot = reinterpret_cast<ULONG_PTR>(&HookRecv);
            FlushInstructionCache(process, slot, sizeof(ULONG_PTR));
            DWORD ignored = 0;
            VirtualProtect(slot, sizeof(ULONG_PTR), oldProtect, &ignored);
            ++g_hookCount;
        }

        return g_hookCount > 0 && g_originalRecv != nullptr;
    }

    static void RemoveRecvHooks()
    {
        g_shutdown.store(1, std::memory_order_release);
        HANDLE process = GetCurrentProcess();

        for (size_t i = 0; i < g_hookCount; ++i)
        {
            HookSlot& h = g_hooks[i];
            if (!h.slot || !h.original) continue;
            DWORD oldProtect = 0;
            if (VirtualProtect(h.slot, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect))
            {
                *h.slot = h.original;
                FlushInstructionCache(process, h.slot, sizeof(ULONG_PTR));
                DWORD ignored = 0;
                VirtualProtect(h.slot, sizeof(ULONG_PTR), oldProtect, &ignored);
            }
        }

        for (int i = 0; i < 500 && g_inflight.load(std::memory_order_acquire) != 0; ++i)
            Sleep(1);

        for (auto& h : g_hooks) h = HookSlot{};
        g_hookCount = 0;
        g_originalRecv = nullptr;
    }

    static std::string HexPreview(const uint8_t* p, size_t n)
    {
        char tmp[4]{};
        std::string out;
        n = std::min<size_t>(n, 64);
        for (size_t i = 0; i < n; ++i)
        {
            sprintf_s(tmp, "%02X", p[i]);
            if (i) out.push_back(' ');
            out += tmp;
        }
        return out;
    }
}

__declspec(dllexport) IPlugin* __stdcall expCreatePlugin(const char*) { return new PartyFinder(); }
__declspec(dllexport) void __stdcall expDestroyPlugin(void* instance) { delete static_cast<PartyFinder*>(instance); }
__declspec(dllexport) double __stdcall expGetInterfaceVersion(void) { return ASHITA_INTERFACE_VERSION; }

bool PartyFinder::Initialize(IAshitaCore* core, ILogManager* logger, const uint32_t id)
{
    m_core = core;
    m_log = logger;
    m_id = id;
    g_shutdown.store(0, std::memory_order_release);
    g_armed.store(false, std::memory_order_release);
    g_write.store(0, std::memory_order_release);
    g_read.store(0, std::memory_order_release);
    g_dropped.store(0, std::memory_order_release);
    for (auto& s : g_slots) s.ready.store(0, std::memory_order_release);

    size_t skipped = 0;
    m_hookInstalled = InstallRecvHooks(skipped);

    char msg[256]{};
    sprintf_s(msg, "[PartyFinder v0.16] Loaded. recv hooks=%zu, skipped=%zu. Commands: /pfcap, /pfcap status, /pfcap stop", g_hookCount, skipped);
    Chat(m_core, msg);

    if (m_log)
        m_log->Log((uint32_t)(m_hookInstalled ? Ashita::LogLevel::Info : Ashita::LogLevel::Error), "PartyFinder", msg);

    return true;
}

void PartyFinder::Release(void)
{
    StopCapture(false);
    RemoveRecvHooks();
}

bool PartyFinder::HandleCommand(int32_t, const char* command, bool)
{
    const std::string cmd = TrimLower(command);
    if (cmd == "/pfcap" || cmd == "pfcap")
    {
        StartCapture();
        return true;
    }
    if (cmd == "/pfcap status" || cmd == "pfcap status")
    {
        PrintStatus();
        return true;
    }
    if (cmd == "/pfcap stop" || cmd == "pfcap stop")
    {
        StopCapture(true);
        return true;
    }
    return false;
}

void PartyFinder::StartCapture()
{
    if (!m_hookInstalled)
    {
        Chat(m_core, "[PartyFinder] Cannot capture: no recv IAT hook was installed.");
        return;
    }

    if (g_armed.load(std::memory_order_acquire))
    {
        Chat(m_core, "[PartyFinder] Capture is already running. Use /pfcap stop first.");
        return;
    }

    CloseCaptureFiles();
    if (!OpenCaptureFiles())
    {
        Chat(m_core, "[PartyFinder] ERROR: could not create capture files.");
        return;
    }

    g_dropped.store(0, std::memory_order_release);
    g_armed.store(true, std::memory_order_release);
    Chat(m_core, "[PartyFinder] Capture STARTED. Run /sea, wait for Search Results, then use /pfcap stop.");
}

void PartyFinder::StopCapture(bool announce)
{
    const bool wasArmed = g_armed.exchange(false, std::memory_order_acq_rel);
    FlushCapture();
    CloseCaptureFiles();

    if (announce)
    {
        char msg[192]{};
        sprintf_s(msg, "[PartyFinder] Capture %s. recv records=%u, dropped=%u.", wasArmed ? "SAVED" : "was not running", g_read.load(), g_dropped.load());
        Chat(m_core, msg);
    }
}

void PartyFinder::PrintStatus()
{
    FlushCapture();
    char msg[256]{};
    sprintf_s(msg, "[PartyFinder] hooks=%zu capture=%s records=%u dropped=%u", g_hookCount,
        g_armed.load(std::memory_order_acquire) ? "ON" : "OFF", g_read.load(), g_dropped.load());
    Chat(m_core, msg);
    if (m_log) m_log->Log((uint32_t)Ashita::LogLevel::Info, "PartyFinder", msg);
}

bool PartyFinder::OpenCaptureFiles()
{
    if (!m_core || !m_core->GetInstallPath()) return false;

    const std::string root = m_core->GetInstallPath();
    const std::string p1 = root + "config\\plugins";
    const std::string p2 = p1 + "\\partyfinder";
    const std::string p3 = p2 + "\\captures";
    CreateDirectoryA(p1.c_str(), nullptr);
    CreateDirectoryA(p2.c_str(), nullptr);
    CreateDirectoryA(p3.c_str(), nullptr);

    SYSTEMTIME st{};
    GetLocalTime(&st);
    char base[MAX_PATH]{};
    sprintf_s(base, "%s\\partyfinder_recv_%04u%02u%02u_%02u%02u%02u", p3.c_str(),
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    fopen_s(&m_bin, (std::string(base) + ".bin").c_str(), "wb");
    fopen_s(&m_txt, (std::string(base) + ".txt").c_str(), "wt");
    if (!m_bin || !m_txt)
    {
        CloseCaptureFiles();
        return false;
    }

    fprintf(m_txt, "PartyFinder v0.16 raw recv capture\n");
    fprintf(m_txt, "Capture-only diagnostic. Incoming bytes are not modified or blocked.\n");
    fprintf(m_txt, "Installed recv IAT hooks: %zu\n", g_hookCount);
    for (size_t i = 0; i < g_hookCount; ++i)
        fprintf(m_txt, "hook[%zu]=%s\n", i, g_hooks[i].module);
    fprintf(m_txt, "\n");

    m_lastCaptureBase = base;
    return true;
}

void PartyFinder::CloseCaptureFiles()
{
    if (m_bin)
    {
        fclose(m_bin);
        m_bin = nullptr;
    }
    if (m_txt)
    {
        fprintf(m_txt, "\nDropped records: %u\n", g_dropped.load());
        fclose(m_txt);
        m_txt = nullptr;
    }
}

void PartyFinder::FlushCapture()
{
    if (!m_bin || !m_txt) return;

    for (;;)
    {
        const uint32_t r = g_read.load(std::memory_order_acquire);
        const uint32_t w = g_write.load(std::memory_order_acquire);
        if (r >= w) break;

        CaptureSlot& s = g_slots[r % kSlotCount];
        if (s.ready.load(std::memory_order_acquire) != 2) break;

        const uint32_t len = s.len;
        fwrite(&s.tick, sizeof(s.tick), 1, m_bin);
        fwrite(&len, sizeof(len), 1, m_bin);
        fwrite(s.data.data(), 1, len, m_bin);

        const auto hex = HexPreview(s.data.data(), len);
        fprintf(m_txt, "record=%u tick=%u len=%u hex=%s\n", r + 1, s.tick, len, hex.c_str());

        s.ready.store(0, std::memory_order_release);
        g_read.store(r + 1, std::memory_order_release);
    }

    fflush(m_bin);
    fflush(m_txt);
}
