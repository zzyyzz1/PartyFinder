PartyFinder v0.13 - Ashita v4 Native Plugin Diagnostic
Author: sbn
Target: Win32 / x86

Purpose
- First native-plugin diagnostic build for PartyFinder.
- Hooks only the process IAT import for Winsock recv().
- Does not alter, block, inject, or resend network data.
- Copies received bytes into a bounded native ring buffer while capture is armed.
- File I/O happens later on Ashita's Direct3DPresent callback, not in recv().

Commands
/pfcap        Arm raw recv capture for 15 seconds.
/pfcap stop   Stop capture and flush queued data.
/pfcap status Show hook/capture status.

Test
1. Build Release | Win32 in Visual Studio 2022.
2. Set ASHITA4_INSTALL_DIRECTORY to your Ashita v4 folder, ending with a backslash.
3. Put/load partyfinder.dll as an Ashita plugin.
4. In game run: /pfcap
5. Immediately run: /sea all inv 10-18
6. Wait until capture ends.
7. Send the newest partyfinder_recv_*.bin and partyfinder_recv_*.txt from Ashita\\config\\plugins\\partyfinder\\captures.

Safety / scope
- This is diagnostic source, not a proven Search Results decoder yet.
- It patches only the main process import named recv if found.
- If recv is not imported there, it fails closed and reports that the hook was not installed.
- No guessed FFXI packet IDs or scresult offsets are used.

Build dependency
- Ashita v4 plugin SDK headers from your own Ashita installation: plugins\\sdk\\
