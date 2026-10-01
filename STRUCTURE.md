# 🏛️ Vortex Cleaner Ultra — System Architecture & Internals Specification

### Enterprise Systems Engineering Blueprint
**Standard:** ISO C++23 | MSVC 19.51+ (Toolchain 14.51+) | Windows NT 10.0+ (x64)  
**Compliance Standards:** NIST SP 800-88 Rev. 1 | SEI CERT C++ | Microsoft Security Development Lifecycle (SDL)  
**Classification:** High-Assurance Windows Kernel Trace Sanitization & Storage Optimizer  

---

## 📑 Table of Contents

1. [Executive Summary & Engineering Philosophy](#1-executive-summary--engineering-philosophy)
2. [Layered Architecture Overview](#2-layered-architecture-overview)
3. [Deep-Dive Subsystem Taxonomy](#3-deep-dive-subsystem-taxonomy)
   - [3.1 Foundation Layer (`src/core/`)](#31-foundation-layer-srccore)
   - [3.2 Security & Privilege Subsystem (`src/security/`)](#32-security--privilege-subsystem-srcsecurity)
   - [3.3 Kernel Drivers & PnP Subsystem (`src/drivers/`)](#33-kernel-drivers--pnp-subsystem-srcdrivers)
   - [3.4 Storage & Volatile Memory Subsystem (`src/storage/`)](#34-storage--volatile-memory-subsystem-srcstorage)
   - [3.5 Orchestration Engine (`src/orchestration/`)](#35-orchestration-engine-srcorchestration)
   - [3.6 Presentation & Hardware Acceleration Layer (`src/gui/`)](#36-presentation--hardware-acceleration-layer-srcgui)
4. [The 12-Phase Pipeline & Topological Ordering Invariants](#4-the-12-phase-pipeline--topological-ordering-invariants)
5. [Concurrency, Deadlock-Free Lock Hierarchy & Synchronization](#5-concurrency-deadlock-free-lock-hierarchy--synchronization)
6. [Low-Level Protocols & Mathematical Formulations](#6-low-level-protocols--mathematical-formulations)
   - [6.1 NTFS USN Change Journal Eradication Protocol](#61-ntfs-usn-change-journal-eradication-protocol)
   - [6.2 Volatile Physical RAM Cache Zeroing Syscall Protocol](#62-volatile-physical-ram-cache-zeroing-syscall-protocol)
   - [6.3 NIST SP 800-88 Rev. 1 Multi-Pass Cryptographic Shredding](#63-nist-sp-800-88-rev-1-multi-pass-cryptographic-shredding)
   - [6.4 Surgical Event Log Filtering (Zero Event ID 104/1102)](#64-surgical-event-log-filtering-zero-event-id-1041102)
7. [Defensive Engineering & Binary Exploit Mitigations](#7-defensive-engineering--binary-exploit-mitigations)

---

## 1. Executive Summary & Engineering Philosophy

Vortex Cleaner Ultra is an enterprise-grade, high-assurance Windows trace sanitization and storage optimization engine engineered in ISO C++23. Unlike rudimentary uninstallation scripts or batch utilities that rely on broad, destructive commands (e.g., `wevtutil cl` or forced file unlinking), Vortex Cleaner Ultra operates directly against Windows NT Executive and Kernel interfaces to surgically eliminate persistent operational telemetry, unlinked driver residues, and forensic footprints.

### Core Architectural Principles
* **Strict RAII Lifetime Management:** Every dynamic Windows NT handle (`HANDLE`, `SC_HANDLE`, `EVT_HANDLE`, `HKEY`, `HDEVINFO`) is encapsulated in zero-cost RAII resource guards with deterministic cleanup semantics.
* **Topological Invariant Phasing:** Execution phases are mathematically ordered as a Directed Acyclic Graph (DAG) such that no purge action can regenerate telemetry or invalidate prior sanitization phases.
* **Non-Destructive Surgical Precision:** Active telemetry is scrubbed without clearing entire log channels, avoiding the generation of Level-1 Indicators of Compromise (IoCs) such as Event ID 104 or Event ID 1102.
* **Zero-Warning Gate Enforcement:** The entire codebase compiles with zero warnings under MSVC `/WX /W4 /permissive-` with Microsoft SDL and Control Flow Guard (`/guard:cf`) active.

---

## 2. Layered Architecture Overview

The codebase is organized into six strictly decoupled layers adhering to the Clean Architecture and Model-View-Presenter (MVP) design patterns:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER (src/gui/)                   │
│         WindowFrame (Win32)  ──>  LuxuryPresenter  ──>  D3D11/GDI+     │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ dispatches
┌────────────────────────────────────▼───────────────────────────────────┐
│                    ORCHESTRATION LAYER (src/orchestration/)            │
│         TargetProfileRegistry  ──>  PurgePipelineOrchestrator          │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ coordinates
┌────────────────────────────────────▼───────────────────────────────────┐
│            SUBSYSTEM ENGINES (src/drivers/, src/storage/)              │
│   ClassFilterScrubber   │   DriverStoreCleaner   │   ServiceController │
│   NtfsJournalScrubber   │   MemoryStandbyFlusher │   CrashDumpPurger   │
│   EventLogSanitizer     │   NistSanitizer        │   NvmeTrimSanitizer │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ leverages
┌────────────────────────────────────▼───────────────────────────────────┐
│                     SECURITY LAYER (src/security/)                     │
│    TokenPrivilegeScope  │  AuthorizationEngine  │  VssSafetyManager    │
│    RegistryDaclManager  │  AuthenticodeVerifier │  BinaryTrustEval     │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ foundations
┌────────────────────────────────────▼───────────────────────────────────┐
│                       CORE FOUNDATION (src/core/)                      │
│     Result<T, E>   │   ScopedResource<T>   │   zstring_view            │
│     Interfaces     │   AppLogger           │   AsyncLogger             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Deep-Dive Subsystem Taxonomy

### 3.1 Foundation Layer (`src/core/`)

| Header | Architectural Responsibility | Low-Level Mechanisms |
| :--- | :--- | :--- |
| `result.hpp` | Monadic error handling framework modeled after `std::expected`. Eliminates C++ exceptions across system boundaries. | `Core::Result<T, SystemError>`, `Core::ErrorCode`, Win32 error translation via `SystemError::FromWin32`. |
| `scoped_resource.hpp` | Generic zero-overhead RAII wrapper for operating system resources. | Customizable Deleter policies, `std::exchange` move mechanics, zero heap overhead. |
| `zstring_view.hpp` | Compile-time and runtime enforced null-terminated wide-string view. Prevents buffer overreads when bridging C++ string views with Win32 `LPCWSTR` APIs. | Inherits `std::wstring_view`, deletes sliced views, exposes guaranteed `c_str()`. |
| `logger.hpp` | High-throughput synchronized console logging with thread-safe formatting. | Structured severity levels (`Trace`, `Info`, `Warn`, `Error`), `std::format` integration. |
| `async_logger.hpp` | Non-blocking Lock-Free Multi-Producer Single-Consumer (MPSC) background telemetry logger. | Ring buffer queues, atomic index tracking, zero worker thread stalls. |
| `interfaces.hpp` | Abstract contracts and C++23 Concepts governing module lifecycle. | `ICleanerModule`, `CleanerModuleType<T>` concept validation. |

### 3.2 Security & Privilege Subsystem (`src/security/`)

| Header | Architectural Responsibility | Low-Level Mechanisms |
| :--- | :--- | :--- |
| `token_privilege_scope.hpp` | Process token privilege escalation and deterministic rollback guard. | `OpenProcessToken`, `AdjustTokenPrivileges`, caches previous privilege masks to restore on destruction. |
| `authorization_engine.hpp` | Windows NT Security Descriptor ownership seizure and ACL overriding. | `SetNamedSecurityInfoW`, acquires `SeTakeOwnershipPrivilege`, resets DACL with explicit Admin access. |
| `registry_dacl_manager.hpp` | Registry key ownership seizure and DACL manipulation for protected vendor keys. | `RegSetKeySecurity`, handles access denied states on locked `HKLM\SYSTEM` branches. |
| `vss_safety_manager.hpp` | Volume Shadow Copy Service (VSS) snapshot coordinator for fail-safe rollback. | `srclient.dll` system restore point creation prior to performing destructive kernel teardown. |
| `authenticode_verifier.hpp` | Validates digital certificates and trust chains of scanned kernel drivers. | `WinVerifyTrust`, `WINTRUST_ACTION_GENERIC_VERIFY_V2`, root certificate validation. |
| `binary_trust_evaluator.hpp` | Heuristic and cryptographic verification of unknown PE images. | Hash verification (`SHA-256`), catalog verification, revocation checks. |

### 3.3 Kernel Drivers & PnP Subsystem (`src/drivers/`)

| Header | Architectural Responsibility | Low-Level Mechanisms |
| :--- | :--- | :--- |
| `service_controller.hpp` | SCM kernel driver service lifecycle controller. Handles service dependencies, unhooking, and unregistration. | `OpenSCManagerW`, `ControlService(SERVICE_CONTROL_STOP)`, `DeleteService`, polling state machine. |
| `class_filter_scrubber.hpp` | Sanitizes `UpperFilters` and `LowerFilters` multi-string registry values across all PnP device classes. | Parses `REG_MULTI_SZ` byte sequences, extracts driver basenames, rebuilds double-null-terminated buffers. |
| `driver_store_cleaner.hpp` | Enumerates and uninstalls staged OEM driver packages from the system DriverStore. | `SetupCopyOEMInfW`, `DiUninstallDriverW`, `SetupUninstallOEMInfW`. |

### 3.4 Storage & Volatile Memory Subsystem (`src/storage/`)

| Header | Architectural Responsibility | Low-Level Mechanisms |
| :--- | :--- | :--- |
| `ntfs_journal_scrubber.hpp` | Two-phase NTFS USN Change Journal obliteration and reinitialization engine. | `FSCTL_QUERY_USN_JOURNAL`, `FSCTL_DELETE_USN_JOURNAL`, `FSCTL_CREATE_USN_JOURNAL`. |
| `memory_standby_flusher.hpp` | Volatile physical RAM cache and Standby Page List (Priorities 0–7) drain engine. | `ntdll.dll!NtSetSystemInformation` under class 80 (`SystemMemoryListInformation`). |
| `crash_dump_purger.hpp` | Discovers and cryptographically shreds kernel crash dumps, minidumps, and WER Watson diagnostics. | NIST SP 800-88 Rev. 1 3-pass overwrite, `BCryptGenRandom`, MFT metadata scrambling. |
| `event_log_sanitizer.hpp` | Surgical event log sanitizer using native Windows Event Log API and targeted XPath 1.0 queries. | `wevtapi.dll!EvtQuery`, `EvtNext`, non-destructive filtering without emitting Event ID 104/1102. |
| `nist_sanitizer.hpp` | General multi-pass file cryptographic shredder for unlinked binaries and artifacts. | CSPRNG random pass, inverted complement pass, zeroization pass, `FlushFileBuffers`. |
| `nvme_trim_sanitizer.hpp` | Hardware-level NAND block invalidation via NVMe Deallocate / SATA TRIM. | `FSCTL_FILE_LEVEL_TRIM`, `IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES`. |
| `filesystem_cleaner.hpp` | Cross-volume recursive directory tree purger with lock breaking. | `std::filesystem` directory iterators, attribute resetting, deferred reboot queueing. |
| `forensic_telemetry_cleaner.hpp` | Sanitizes Windows Execution Artifacts (BAM, DAM, Prefetch, ShimCache, Amcache). | Registry binary parsing, timestamp wiping, MRU list clearing. |

### 3.5 Orchestration Engine (`src/orchestration/`)

| Header | Architectural Responsibility | Low-Level Mechanisms |
| :--- | :--- | :--- |
| `purge_orchestrator.hpp` | Central execution engine enforcing strict topological ordering and deadlock-free lock acquisition across all 12 phases. | Manages phase lifecycle, dispatches progress callbacks, compiles `PipelineStats`. |
| `target_profile_registry.hpp` | Pre-configured target profiles for anti-cheat and telemetry footprints. | Configurations for Vanguard (`vgk.sys`), EasyAntiCheat (`easyanticheat.sys`), BattlEye (`BEService`). |

### 3.6 Presentation & Hardware Acceleration Layer (`src/gui/`)

| Header | Architectural Responsibility | Low-Level Mechanisms |
| :--- | :--- | :--- |
| `luxury_window_presenter.hpp` | Decoupled MVP Presenter coordinating UI state, asynchronous scan/purge execution, and event handling. | `std::jthread` worker thread, thread-safe message posting (`WM_APP_PURGE_PROGRESS`). |
| `d3d11_renderer.hpp` | High-fidelity hardware-accelerated Vector GUI renderer with Mica glassmorphism. | GDI+ double-buffered rasterizer, linear gradient brushes, anti-aliased path drawing. |
| `window_frame.hpp` | Custom non-client window frame implementing modern Windows 11 DWM dark aesthetics. | `DwmSetWindowAttribute`, `DWMWA_SYSTEMBACKDROP_TYPE`, Custom `WM_NCHITTEST` handling. |
| `ui_theme.hpp` | Unified design tokens, color palettes, fonts, and geometry constants. | Deep Obsidian background, Neon Cyan accents, Emerald Green status indicators. |

---

## 4. The 12-Phase Pipeline & Topological Ordering Invariants

Execution ordering is strictly governed by the following mathematical invariant DAG:

$$\text{Phase 1} \prec \text{Phase 2} \prec \text{Phase 3} \prec \text{Phase 4} \prec \text{Phase 5} \prec \text{Phase 6} \prec \text{Phase 7} \prec \text{Phase 8} \prec \text{Phase 9} \prec \text{Phase 10} \prec \text{Phase 11} \prec \text{Phase 12}$$

```
[Phase 1] VSS Safety Snapshot Isolation
    │
[Phase 2] PnP Class Filter Multi-Key Scrubbing
    │
[Phase 3] SCM Kernel Driver Service & Daemon Teardown
    │
[Phase 4] SetupAPI DriverStore OEM Package Removal
    │
[Phase 5] Dual-View Registry Subtree Purge & DACL Seizure
    │
[Phase 6] Multi-Drive Cross-Volume Binary Shredding (NIST SP 800-88)
    │
[Phase 7] Execution Traces Purge (BAM, DAM, Shimcache, Amcache)
    │
[Phase 8] Temporary Junk, Shader Caches & Diagnostic Sweeper
    │
[Phase 9] Crash Dumps, LiveKernelReports & WER Watson Eradication
    │
[Phase 10] Surgical Windows Event Log (EVTX) Sanitization
    │
[Phase 11] Deep NTFS USN Change Journal Obliteration ($Extend\$UsnJrnl)
    │
[Phase 12] Physical RAM Standby Page List Zeroing (NtSetSystemInformation)
```

### Invariant Rules:
1. **File I/O Precedence Over Journal Scrubbing:** All file modifications, unlinking, and crash dump shredding (Phases 6–9) **MUST** finish before USN Journal Eradication (Phase 11). If the journal is deleted prior to unlinking, `Ntfs.sys` records fresh `USN_REASON_FILE_DELETE` entries.
2. **System State Precedence Over Memory Purging:** Service unregistration and disk I/O **MUST** finish before Physical RAM Standby Zeroing (Phase 12). If standby pages are drained while active services are running, background threads immediately repopulate the standby cache with driver pages.

---

## 5. Concurrency, Deadlock-Free Lock Hierarchy & Synchronization

To guarantee mathematical deadlock freedom across multi-threaded execution, all subsystems adhere to a strict total ordering of resource acquisition:

$$\mathcal{L}_1 (\text{TokenPrivilegeScope}) \succ \mathcal{L}_2 (\text{SCM Database Lock}) \succ \mathcal{L}_3 (\text{Registry HIVE Handle}) \succ \mathcal{L}_4 (\text{Volume Handle}) \succ \mathcal{L}_5 (\text{File Handle})$$

* **Acquisition Rule:** A thread holding a lock $\mathcal{L}_i$ may only acquire lock $\mathcal{L}_j$ if $i < j$.
* **Release Rule:** Resources must be released in exact Last-In-First-Out (LIFO) order via RAII stack unwinding.
* **Volume Handle Rule:** Under zero circumstances may a raw volume handle (`\\.\C:`) be acquired while holding an exclusive file handle on that volume, preventing filesystem filter deadlock in `Ntfs.sys`.

---

## 6. Low-Level Protocols & Mathematical Formulations

### 6.1 NTFS USN Change Journal Eradication Protocol
The NTFS USN Journal (`$Extend\$UsnJrnl:$J`) records every disk transaction. Standard file deletion leaves an unalterable forensic record:
$$\mathcal{R} = \{\text{FileID}, \text{ParentID}, \text{USN}, \text{ReasonMask} = \text{USN\_REASON\_FILE\_DELETE}\}$$

Vortex Cleaner Ultra eradicates this via a two-phase FSCTL sequence on `\\.\<Drive>:`:
1. **Query Active State:** `FSCTL_QUERY_USN_JOURNAL` returns active `UsnJournalID`.
2. **Deallocate & Truncate:**
   ```cpp
   DELETE_USN_JOURNAL_DATA delData{};
   delData.UsnJournalID = journalData.UsnJournalID;
   delData.DeleteFlags = USN_DELETE_FLAG_DELETE; // Drops stream allocation
   DeviceIoControl(hVol, FSCTL_DELETE_USN_JOURNAL, &delData, sizeof(delData), ...);
   ```
3. **Re-instantiate Clean Journal:**
   ```cpp
   CREATE_USN_JOURNAL_DATA crData{};
   crData.MaximumSize = 0; // Windows NT defaults (32MB)
   crData.AllocationDelta = 0;
   DeviceIoControl(hVol, FSCTL_CREATE_USN_JOURNAL, &crData, sizeof(crData), ...);
   ```
   *Result:* $\text{LowestValidUsn} \to 0$, creating a completely blank transaction ledger with a new cryptographic ID.

### 6.2 Volatile Physical RAM Cache Zeroing Syscall Protocol
Terminated kernel drivers and game processes leave decrypted executable images and crypto keys in the Windows NT Standby Page List:
$$\mathcal{P}_{\text{phys}} = \mathcal{P}_{\text{active}} \cup \mathcal{P}_{\text{modified}} \cup \left(\bigcup_{k=0}^{7} \mathcal{P}_{\text{standby}}(k)\right) \cup \mathcal{P}_{\text{free}} \cup \mathcal{P}_{\text{zeroed}}$$

Interfacing directly with `ntdll.dll!NtSetSystemInformation` under class 80:
* **Step 1 (Working Set Trim):** Command `MemoryEmptyWorkingSets` (2) evicts pages from processes to the modified/standby lists.
* **Step 2 (Modified Page Flush):** Command `MemoryFlushModifiedList` (3) flushes modified dirty pages to disk, transitioning them to Standby Priority 7.
* **Step 3 (Standby Purge):** Command `MemoryPurgeStandbyList` (4) moves all standby pages across priorities $0 \le k \le 7$ to the Zeroed list:
  $$\bigcup_{k=0}^7 \mathcal{P}_{\text{standby}}(k) \xrightarrow{\text{Purge}} \emptyset$$

### 6.3 NIST SP 800-88 Rev. 1 Multi-Pass Cryptographic Shredding
Target files are sanitized across 3 sequential block overwrites:
1. **Pass 1 (CSPRNG Entropy):** Overwrite with pseudorandom bytes from `BCryptGenRandom`.
   $$H(X) = -\sum_{i=1}^{256} P(x_i) \log_2 P(x_i) \ge 7.995 \text{ bits/byte}$$
2. **Pass 2 (Bitwise Complement):** Overwrite with bitwise inversion ($\sim B_i$).
3. **Pass 3 (Zeroization):** Overwrite with `0x00`.
4. **Metadata Scrambling:** Truncate to 0 bytes via `SetEndOfFile`, rename to random 16-character alphanumeric sequence, and unlink via `DeleteFileW`.

### 6.4 Surgical Event Log Filtering (Zero Event ID 104/1102)
Standard log clearing (`wevtutil cl System`) emits **Event ID 104** ("The System log file was cleared"), creating an immediate IoC. Vortex Cleaner Ultra avoids `EvtClearLog` entirely:
1. Binds to `wevtapi.dll!EvtQuery` using targeted XPath 1.0 expressions:
   ```xml
   *[System[(EventID=7045 or EventID=7040)] and EventData[Data[@Name='ServiceName']='target']]
   ```
2. Sanitizes historical archived logs (`%SystemRoot%\System32\Winevt\Logs\Archive-*.evtx`) using cryptographic shredding.
3. Disables diagnostic telemetry channels without generating log clearance markers.

---

## 7. Defensive Engineering & Binary Exploit Mitigations

The compiled binary enforces enterprise security hardening at both compile-time and link-time:

```cmake
# Compile-time Flags
/std:c++23 /permissive- /W4 /WX /utf-8
/guard:cf          # Control Flow Guard (CFG) validation of indirect calls
/sdl               # Security Development Lifecycle checks
/GS                # Compiler Security Buffer Checks (Stack Canaries)

# Link-time Flags
/DYNAMICBASE       # Full Address Space Layout Randomization (ASLR)
/HIGHENTROPYVA     # 64-bit high-entropy ASLR (virtual address randomization)
/NXCOMPAT          # Data Execution Prevention (DEP / No-Execute)
/GUARD:CF          # Linker-enforced Control Flow Guard table emission
/MANIFESTUAC:"level='requireAdministrator' uiAccess='false'"
```

---

*Authored by Engineering Team. Adheres strictly to ISO C++23 standards and Microsoft Windows NT Kernel Architecture.*
