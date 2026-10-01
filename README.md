# ⚡ Vortex Cleaner Ultra (v5.1.0)

<div align="center">

[![C++ Standard](https://img.shields.io/badge/C%2B%2B-23-00599C?style=for-the-badge&logo=c%2B%2B)](https://en.cppreference.com/w/cpp/23)
[![Toolchain](https://img.shields.io/badge/MSVC-19.51+-0078D7?style=for-the-badge&logo=visualstudio)](https://visualstudio.microsoft.com/)
[![Sanitization Standard](https://img.shields.io/badge/NIST-SP_800--88_Rev._1-red?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
[![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011%20(x64)-0078D4?style=for-the-badge&logo=windows)](https://microsoft.com/windows)
[![Security Hardening](https://img.shields.io/badge/Exploit_Mitigation-CFG%20%7C%20ASLR%20%7C%20DEP-success?style=for-the-badge)](https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-guard-checks)

**Enterprise-Grade High-Assurance Windows Kernel Trace Sanitizer & Storage Optimization Engine**

*Engineered with ISO C++23 • Zero-Warning Gate (`/WX`) • PatchGuard Compliant • Native Executive NT Syscalls*

</div>

---

## 📖 Overview

**Vortex Cleaner Ultra** is a high-assurance, bare-metal Windows trace eradication and storage optimization suite designed for security engineers, system administrators, and advanced users. Modern anti-cheat systems, kernel telemetry daemons, and diagnostics services embed persistent tracking artifacts across deep Windows operating system layers—including the **NTFS Change Journal (`$Extend\$UsnJrnl`)**, the **Windows NT Standby Page Lists (Priorities 0–7)**, **Windows Error Reporting (WER)** crash dumps, and **Windows Event Logs (`wevtapi.dll`)**.

Unlike generic cleaner tools or destructive batch scripts that trigger Blue Screens of Death (BSODs) or generate Level-1 Indicators of Compromise (such as Event ID 104 "Event Log Cleared"), Vortex Cleaner Ultra utilizes low-level NT system calls, cryptographic overwrites compliant with **NIST SP 800-88 Rev. 1**, and a mathematically proven 12-phase topological pipeline.

---

## ✨ Key Architectural Highlights

* **12-Phase Strict Topological DAG Pipeline:** Guarantees that no file deletion or service teardown regenerates forensic artifacts downstream.
* **Two-Phase NTFS USN Change Journal Eradication:** Issues direct `FSCTL_DELETE_USN_JOURNAL` and `FSCTL_CREATE_USN_JOURNAL` controls against raw volume handles, resetting `$Extend\$UsnJrnl:$J` without damaging volume integrity.
* **Native NT Syscall Memory Standby List Zeroing:** Dispatches Executive syscall `NtSetSystemInformation` under undocumented class 80 (`SystemMemoryListInformation`), flushing modified lists and zeroing cached physical RAM pages.
* **Surgical XPath Event Log Sanitization:** Employs the native Windows Event Log API (`wevtapi.dll`) to selectively purge target driver and service telemetry while strictly avoiding `EvtClearLog`—emitting **zero Event ID 104 or 1102** alarms.
* **Cryptographic Dump Shredder:** Scrambles and purges `%SystemRoot%\MEMORY.DMP`, LiveKernelReports, and WER Watson packages with 3-pass CSPRNG bitwise complement overwriting.
* **Dual-Engine User Interface:** Includes an Obsidian-glassmorphic luxury GUI with real-time vector animations and a dedicated headless CLI mode (`--cli`) for scriptable automation.

---

## 🏛️ The 12-Phase Execution Pipeline

```
  Phase 01  ──>  VSS Safety Snapshot & Rollback Baseline Initialization
  Phase 02  ──>  PnP Device Class Filter Multi-String Scrubbing (Upper/LowerFilters)
  Phase 03  ──>  Service Control Manager (SCM) Kernel Driver Teardown & DACL Seizure
  Phase 04  ──>  SetupAPI DriverStore Staged OEM Package Uninstallation
  Phase 05  ──>  Dual-View Registry Subtree Eradication (HKLM & HKCU 32/64-bit)
  Phase 06  ──>  Multi-Drive Cross-Volume Binary Shredding (NIST SP 800-88 3-Pass)
  Phase 07  ──>  Execution Traces & Forensic Artifacts Purge (BAM, DAM, Shimcache)
  Phase 08  ──>  Temporary Junk, DirectX Shader Caches & Prefetch Sweep
  Phase 09  ──>  Kernel Crash Dumps, Minidumps & LiveKernelReports Cryptographic Shredder
  Phase 10  ──>  Surgical Windows Event Log Sanitizer (XPath queries, zero Event ID 104)
  Phase 11  ──>  Deep NTFS USN Change Journal Obliteration ($Extend\$UsnJrnl:$J)
  Phase 12  ──>  Physical RAM Standby Page List (0-7) Zeroing via NtSetSystemInformation
```

> For the comprehensive mathematical formulation, locking theorems, and module topologies, see [STRUCTURE.md](STRUCTURE.md).

---

## 🔒 Security & Exploit Mitigations

Every binary produced by the Vortex build system is hardened to enterprise standards:

| Mitigation Flag | Defense Mechanism |
| :--- | :--- |
| `/guard:cf` / `/GUARD:CF` | Microsoft Control Flow Guard validation of indirect call targets. |
| `/sdl` & `/GS` | Security Development Lifecycle buffer security checks and stack canaries. |
| `/DYNAMICBASE` | Full Address Space Layout Randomization (ASLR). |
| `/HIGHENTROPYVA` | 64-bit high-entropy ASLR utilizing full 64-bit address space. |
| `/NXCOMPAT` | Data Execution Prevention (DEP) preventing code execution in data segments. |
| `/WX` | Zero-Warning Compiler Gate — all compiler warnings are treated as build errors. |

---

## 🛠️ Building from Source

### Prerequisites
* **Operating System:** Windows 10 (Build 19041+) or Windows 11 (x64)
* **Compiler:** Visual Studio 2022 / 2026 (MSVC v143 or v144 with ISO C++23 support)
* **Build System:** CMake 3.20 or newer
* **Windows SDK:** Windows SDK 10.0.22000.0 or higher

### Build Instructions

```powershell
# 1. Clone repository
git clone https://github.com/shehabhassanpro-stack/Vortex-Cleaner.git
cd Vortex-Cleaner

# 2. Configure with CMake
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# 3. Compile optimized Release binary
cmake --build build --config Release
```

The compiled executable will be generated at:
```
build/Release/VortexCleaner_v5.exe
```

---

## 🚀 Usage

### 1. Graphical Interface (Default)
Run `VortexCleaner_v5.exe` as Administrator to launch the luxury Obsidian/Mica interface. The GUI features a 60Hz vector dashboard, real-time multi-drive scan telemetry, and live pipeline destruction logs.

### 2. Headless Console Mode (`--cli`)
For automated deployments or scheduled maintenance, invoke the executable with the `--cli` argument:

```powershell
.\build\Release\VortexCleaner_v5.exe --cli
```

#### Sample Console Output:
```text
=========================================================
   WinTracePurge Ultra | Production-Grade Systems Engine
   C++23 Standards | NIST SP 800-88 | PatchGuard Compliant
=========================================================

[ 10%] Creating VSS safety restore point...
[ 20%] Scrubbing UpperFilters / LowerFilters in PnP Class GUIDs...
[ 32%] Gracefully stopping and unregistering kernel driver services...
[ 45%] Uninstalling OEM driver packages from DriverStore...
[ 58%] Purging 32-bit & 64-bit registry subtrees and vendor keys...
[ 70%] Sanitizing discovered anti-cheat platform binaries across all drives...
[ 78%] Purging BAM execution timestamps, Shimcache, and error logs...
[ 84%] Sweeping Temp files, Shader Caches, and Prefetch...
[ 89%] Cryptographically shredding Crash Dumps, LiveKernelReports & Watson packages...
[ 93%] Surgically sanitizing Event Logs (XPath telemetry query, zero Event ID 104)...
[ 96%] Eradicating NTFS USN Change Journals across all fixed drives (FSCTL two-phase)...
[ 99%] Zeroing physical RAM Standby Page Lists (0-7) via native NtSetSystemInformation...
[100%] Cleanup pipeline completed successfully.

---------------------------------------------------------
   EXECUTION REPORT & SUMMARY
---------------------------------------------------------
 - Services Stopped & Purged:    4
 - DriverStore Packages Removed: 2
 - Registry Subtrees Purged:     5
 - Files & Caches Sanitized:     128
 - Crash Dumps & WER Shredded:   12
 - Event Log Records Sanitized:  46
 - NTFS USN Journals Scrubbed:   2
 - Standby RAM Bytes Reclaimed:  1842.50 MB
 - Temp & Diagnostics Swept:     COMPLETED
---------------------------------------------------------
System cleanup finished cleanly. Please restart your PC.
```

---

## ⚖️ License & Ethical Use

Distributed under the **MIT License**.

**Disclaimer:** Vortex Cleaner Ultra is designed for legitimate software uninstallation, system storage optimization, digital privacy, and cybersecurity research. Users are solely responsible for ensuring compliance with applicable terms of service and local legislation.

---

<div align="center">
<b>Vortex Cleaner Ultra Engineering Team</b> • <i>Redefining Windows Systems Sanitization</i>
</div>
