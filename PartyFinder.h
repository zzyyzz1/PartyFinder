#pragma once
#include <winsock2.h>
#include <windows.h>
#include "Ashita.h"
#include <atomic>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

class PartyFinder final : public IPlugin
{
public:
    const char* GetName(void) const override { return "PartyFinder"; }
    const char* GetAuthor(void) const override { return "sbn"; }
    const char* GetDescription(void) const override { return "Native /sea ingress diagnostic for PartyFinder."; }
    const char* GetLink(void) const override { return ""; }
    double GetVersion(void) const override { return 0.14; }
    int32_t GetPriority(void) const override { return 0; }

    // Commands only. Do not request Direct3D initialization.
    uint32_t GetFlags(void) const override
    {
        return (uint32_t)Ashita::PluginFlags::UseCommands;
    }

    bool Initialize(IAshitaCore* core, ILogManager* logger, const uint32_t id) override;
    void Release(void) override;
    bool HandleCommand(int32_t mode, const char* command, bool injected) override;

private:
    IAshitaCore* m_core{};
    ILogManager* m_log{};
    uint32_t m_id{};
    bool m_hookInstalled{};
    uint64_t m_captureUntil{};
    FILE* m_bin{};
    FILE* m_txt{};

    void StartCapture();
    void StopCapture();
    void FlushCapture();
    void PrintStatus();
    bool OpenCaptureFiles();
    void CloseCaptureFiles();
};
