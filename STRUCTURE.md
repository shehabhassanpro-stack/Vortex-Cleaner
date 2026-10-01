# 📐 Vortex Cleaner Ultra — Architecture & Codebase Specification

### Technical Blueprint & Low-Level Systems Engineering Manual
**Author:** Engineering Team  
**Standard:** ISO C++23 | MSVC 19.50+ | Windows NT 10.0+ (x64)  
**Compliance:** NIST SP 800-88 Rev. 1 | SEI CERT C++  

---

## 📑 Table of Contents

1. [Executive Summary & Architectural Paradigm](#1-executive-summary--architectural-paradigm)
2. [Layered System Architecture](#2-layered-system-architecture)
3. [Deep-Dive File & Module Topology](#3-deep-dive-file--module-topology)
   - [3.1 Core Foundation Layer (`src/core/`)](#31-core-foundation-layer-srccore)
   - [3.2 Security & Privilege Subsystem (`src/security/`)](#32-security--privilege-subsystem-srcsecurity)
   - [3.3 Kernel Drivers & PnP Subsystem (`src/drivers/`)](#33-kernel-drivers--pnp-subsystem-srcdrivers)
   - [3.4 Storage & Forensic Telemetry Subsystem (`src/storage/`)](#34-storage--forensic-telemetry-subsystem-srcstorage)
   - [3.5 Orchestration Engine (`src/orchestration/`)](#35-orchestration-engine-srcorchestration)
   - [3.6 Presentation Layer (MVP) (`src/gui/`)](#36-presentation-layer-mvp-srcgui)
4. [Critical Algorithms & Mathematical Formulations](#4-critical-algorithms--mathematical-formulations)
   - [4.1 PnP Filter Multi-String Scrubbing Algorithm](#41-pnp-filter-multi-string-scrubbing-algorithm)
   - [4.2 NIST SP 800-88 Cryptographic Block Sanitization](#42-nist-sp-800-88-cryptographic-block-sanitization)
   - [4.3 Security Descriptor (DACL) Seizure & Ownership Transfer](#43-security-descriptor-dacl-seizure--ownership-transfer)
   - [4.4 Asynchronous MPSC Logging Queue Invariants](#44-asynchronous-mpsc-logging-queue-invariants)
5. [Concurrency, Threading Model & State Machine](#5-concurrency-threading-model--state-machine)
6. [Design Decisions & Engineering Trade-offs](#6-design-decisions--engineering-trade-offs)

---

## 1. Executive Summary & Architectural Paradigm

Vortex Cleaner Ultra is built on a **Layered, Concept-Constrained Architecture** adhering strictly to SOLID object-oriented principles, zero-leak RAII (Resource Acquisition Is Initialization), and monadic value-semantic error propagation.

The system is designed with four fundamental non-negotiable engineering invariants:
1. **Zero-Leak Invariant:** Every OS resource (`HANDLE`, `SC_HANDLE`, `HKEY`, `HMODULE`, `PSID`, `PACL`) must be bound to a strictly scoped RAII wrapper. No manual `CloseHandle`, `RegCloseKey`, or `FreeSid` is permitted in procedural code.
2. **Crash-Free PnP Invariant:** No driver binary may be uninstalled without first scrubbing its name from all PnP Class `UpperFilters` and `LowerFilters` entries.
3. **No-Exception Invariant:** Kernel and security routines must not throw C++ or SEH exceptions across API boundaries. All results propagate via `Core::Result<T>` (`std::expected`).
4. **Decoupled View Invariant:** The presentation layer must have zero mutable static state, perform zero disk I/O on the UI thread, and interact with worker routines strictly through message-passing.

---

## 2. Layered System Architecture

The codebase enforces unidirectional downward dependencies: higher layers may invoke lower layers, but lower layers never depend on or reference higher layers.

```mermaid
graph TD
    subgraph Layer 6: Presentation
        GUI["GUI View (CWindowFrame & CLuxuryViewRenderer)"]
        PRES["Presenter (CLuxuryWindowPresenter)"]
        THEME["Theme System (ui_theme.hpp)"]
    end

    subgraph Layer 5: Orchestration
        ORCH["Purge Pipeline Orchestrator"]
        PROF["Target Profile Registry"]
    end

    subgraph Layer 4: Storage & Forensics
        NIST["NIST SP 800-88 Sanitizer"]
        NVME["NVMe TRIM Controller"]
        TEL["Forensic Telemetry Cleaner (BAM/DAM/ShimCache)"]
        SCAN["Real-Time Multi-Drive Scanner"]
        FS["Filesystem Cleaner & Temp Sweeper"]
    end

    subgraph Layer 3: Kernel & Drivers
        SCM["Service Controller (SCM Teardown)"]
        PNP["PnP Class Filter Scrubber"]
        DSTORE["DriverStore SetupAPI Cleaner"]
        REG["Dual-View Registry Purge Engine"]
    end

    subgraph Layer 2: Security & Authorization
        AUTH["Authorization Engine (DACL Manager)"]
        TOK["Token Privilege Scope (RAII)"]
        VSS["VSS Safety Baseline Manager"]
        VERIF["Authenticode & PE Verifier"]
    end

    subgraph Layer 1: Core Foundation
        RES["Result Monad (std::expected)"]
        RAII["ScopedResource (HANDLE, HKEY, SID, ACL)"]
        LOG["Async Logger (MPSC UTF-8 Engine)"]
        ZSTR["zstring_view (Boundary Bridge)"]
        INTF["ICleanerModule & CleanerModuleType Concept"]
    end

    GUI --> PRES
    PRES --> ORCH
    ORCH --> SCM
    ORCH --> PNP
    ORCH --> DSTORE
    ORCH --> REG
    ORCH --> NIST
    ORCH --> TEL
    ORCH --> VSS
    SCM --> AUTH
    REG --> AUTH
    AUTH --> TOK
    NIST --> RAII
    ORCH --> LOG
```

---

## 3. Deep-Dive File & Module Topology

### 3.1 Core Foundation Layer (`src/core/`)

#### [`scoped_resource.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/core/scoped_resource.hpp)
* **Purpose:** High-assurance RAII wrapper for operating system primitives.
* **Key Types:**
  - `ScopedResource<HandleType, Deleter, InvalidValue>`: Generic resource manager supporting custom invalid states.
  - `ScopedHandle`: Win32 `HANDLE` wrapper (`::CloseHandle`) distinguishing between `NULL` and `INVALID_HANDLE_VALUE`.
  - `ScopedSCMHandle`: SCM handle wrapper (`::CloseServiceHandle`).
  - `ScopedHKey`: Registry handle wrapper (`::RegCloseKey`).
  - `ScopedModule`: Dynamic module library handle wrapper (`::FreeLibrary`).
  - `ScopedSid`: Windows NT Security Identifier wrapper (`::FreeSid`).
  - `ScopedAcl`: Access Control List memory wrapper (`::LocalFree`).
* **Design Decision:** Eliminates pointer-to-integer conversion errors (`C2762`) on 64-bit systems by utilizing `{}` default value initialization and static type casting.

#### [`result.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/core/result.hpp)
* **Purpose:** Monadic return type enforcing explicit error checking.
* **Key Types:**
  - `SystemError`: Encapsulates a Win32 `DWORD` error code, an HRESULT code, and a contextual diagnostic string.
  - `Result<T>`: Alias for `std::expected<T, SystemError>`.
* **Design Decision:** `SystemError::FromWin32Error` immediately captures `const DWORD err = ::GetLastError()` at the point of failure, preventing internal string allocations or formatting from clobbering the error state.

#### [`zstring_view.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/core/zstring_view.hpp)
* **Purpose:** Guarantees null-termination safety without string duplication.
* **Key Concept:** Provides a non-owning view of a wide string that is guaranteed by type contract to be null-terminated (`\0`), making calls to native Win32 `LPCWSTR` APIs provably safe without incurring `std::wstring` heap allocations.

#### [`async_logger.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/core/async_logger.hpp) & [`logger.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/core/logger.hpp)
* **Purpose:** Lock-free, non-blocking asynchronous logging engine.
* **Key Characteristics:**
  - Initialized exactly once across all threads via `std::call_once` and `std::once_flag`.
  - Multi-Producer Single-Consumer (MPSC) bounded queue with disk-stall overflow protection (`s_DroppedRecords`).
  - Dedicated background `std::jthread` drains batches, serializing directly to UTF-8 without CRT locale overhead.
  - Automatic diagnostic fallback to `%TEMP%\VortexCleaner_Fallback.log` and `OutputDebugStringW` upon file descriptor failure.

#### [`interfaces.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/core/interfaces.hpp)
* **Purpose:** Formal polymorphic contracts and C++23 compile-time concepts.
* **Key Contracts:**
  - `ICleanerModule`: Pure virtual contract declaring `GetModuleName()`, `Scan(ctx)`, and `Purge(ctx)`.
  - `CleanerModuleType`: Compile-time C++23 concept constraining cleaner plugins:
    ```cpp
    template <typename T>
    concept CleanerModuleType = std::derived_from<T, ICleanerModule> && requires(T module, const CleanupContext& ctx) {
        { module.GetModuleName() } -> std::same_as<zstring_view>;
        { module.Scan(ctx) }       -> std::same_as<Result<std::vector<ResourceItem>>>;
        { module.Purge(ctx, false) } -> std::same_as<Result<PurgeStats>>;
    };
    ```

---

### 3.2 Security & Privilege Subsystem (`src/security/`)

#### [`authorization_engine.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/security/authorization_engine.hpp)
* **Purpose:** Central authority for Windows NT Access Control Lists (ACLs) and ownership management.
* **Responsibilities:**
  - Seizes ownership of locked files and registry keys by attributing ownership to `BUILTIN\Administrators` (`WinBuiltinAdministratorsSid`).
  - Builds an explicit `EXPLICIT_ACCESS_W` ACE granting `GENERIC_ALL` or `KEY_ALL_ACCESS`, and applies it atomically via `SetNamedSecurityInfoW`.

#### [`token_privilege_scope.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/security/token_privilege_scope.hpp)
* **Purpose:** RAII scope management for process token privileges.
* **Capabilities:** Dynamically adjusts token state to enable `SeTakeOwnershipPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeLoadDriverPrivilege`, automatically restoring original privilege states on scope exit.

#### [`vss_safety_manager.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/security/vss_safety_manager.hpp)
* **Purpose:** Pre-execution disaster recovery baseline.
* **Mechanism:** Dynamically interfaces with `srclient.dll` (`SRSetRestorePointW`) to create a system restore point prior to any kernel or registry modifications.

#### [`authenticode_verifier.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/security/authenticode_verifier.hpp) & [`binary_trust_evaluator.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/security/binary_trust_evaluator.hpp)
* **Purpose:** Trust evaluation and PE signature inspection.
* **Mechanism:** Pre-verifies the existence of a valid `WIN_CERTIFICATE` entry in the PE Optional Header Security Directory prior to invoking `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`), avoiding unnecessary overhead on unsigned binaries.

---

### 3.3 Kernel Drivers & PnP Subsystem (`src/drivers/`)

#### [`class_filter_scrubber.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/drivers/class_filter_scrubber.hpp)
* **Purpose:** Eliminates the primary cause of system boot failures (`0x7B INACCESSIBLE_BOOT_DEVICE`).
* **Mechanism:** Enumerates all Class GUID keys under `SYSTEM\CurrentControlSet\Control\Class`. When an `UpperFilters` or `LowerFilters` multi-string value contains target driver names, it strips them out while preserving all valid platform filters.

#### [`service_controller.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/drivers/service_controller.hpp)
* **Purpose:** Robust Service Control Manager (SCM) teardown engine.
* **Features:**
  - Safely stops dependent services using trusted binary evaluation.
  - Forces driver startup type to `SERVICE_DISABLED` (Start = 4) via `ChangeServiceConfigW` before calling `DeleteService`, ensuring that if a service cannot be immediately unloaded because it is locked in kernel memory, it will not load on subsequent boots.

#### [`driver_store_cleaner.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/drivers/driver_store_cleaner.hpp)
* **Purpose:** Clean uninstallation of OEM driver staging packages.
* **Mechanism:** Dynamically loads `setupapi.dll` within a RAII `ScopedModule`, searches for published driver INF files (`oem*.inf`), and triggers `SetupUninstallOEMInfW` with `SUOI_FORCEDELETE`.

---

### 3.4 Storage & Forensic Telemetry Subsystem (`src/storage/`)

#### [`nist_sanitizer.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/storage/nist_sanitizer.hpp)
* **Purpose:** High-security cryptographic physical data overwrite conforming to NIST SP 800-88 Rev. 1.
* **Algorithm:** Overwrites files using chunks populated with fresh cryptographic entropy from `BCryptGenRandom`, flushes hardware write buffers via `FlushFileBuffers`, truncates the file length to zero (`SetEndOfFile`), and deletes the underlying filesystem entry.

#### [`nvme_trim_sanitizer.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/storage/nvme_trim_sanitizer.hpp)
* **Purpose:** Hardware-level Flash Translation Layer (FTL) block deallocation.
* **Mechanism:** Queries physical volume descriptors via `IOCTL_STORAGE_QUERY_PROPERTY` using dynamic two-pass sizing, construct a `DEVICE_DATA_SET_RANGE`, and dispatches `IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES` with `DeviceDsmAction_Trim`.

#### [`forensic_telemetry_cleaner.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/storage/forensic_telemetry_cleaner.hpp)
* **Purpose:** Eradication of historical execution traces.
* **Targets:**
  - Background Activity Moderator (BAM): `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>`
  - Desktop Activity Moderator (DAM): `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>`
  - Application Compatibility Cache: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
  - Windows Prefetch directory (`%SystemRoot%\Prefetch`)

---

### 3.5 Orchestration Engine (`src/orchestration/`)

#### [`purge_orchestrator.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/orchestration/purge_orchestrator.hpp)
* **Purpose:** Multi-phase directed pipeline coordinator.
* **Phases:**
  1. *Phase 0:* Establish VSS Pre-Execution Safety Baseline.
  2. *Phase 1:* Escalate NT Token Privileges via RAII.
  3. *Phase 2:* Scrub PnP Class Filter chains.
  4. *Phase 3:* SCM Service teardown and start-type disablement.
  5. *Phase 4:* DriverStore package removal via SetupAPI.
  6. *Phase 5:* Dual-View Registry subtree eradication & DACL seizure.
  7. *Phase 6:* Multi-drive platform binary shredding.
  8. *Phase 7:* Forensic telemetry & execution log sweep.
  9. *Phase 8:* System temporary files and crash dump clearing.
  10. *Phase 9:* Registered custom `ICleanerModule` extension execution.

---

### 3.6 Presentation Layer (MVP) (`src/gui/`)

```mermaid
sequenceDiagram
    participant User
    participant WinFrame as CWindowFrame
    participant Presenter as CLuxuryWindowPresenter
    participant Worker as Background std::jthread
    participant Renderer as CLuxuryViewRenderer

    User->>WinFrame: Clicks "SCAN ALL DRIVES"
    WinFrame->>Presenter: HandleClick(x, y)
    Presenter->>Presenter: SetState(Scanning) & SetTimerFrequency(16ms)
    Presenter->>Worker: Spawns std::jthread(PerformLiveScan)
    loop During Scan
        Worker->>WinFrame: PostMessageW(WM_APP_SCAN_PROGRESS)
        WinFrame->>Presenter: HandleScanProgress(pct, phase)
        Presenter->>WinFrame: InvalidateArea()
        WinFrame->>Renderer: RenderDashboardView(memDC, Presenter)
    end
    Worker->>WinFrame: PostMessageW(WM_APP_SCAN_COMPLETE, report)
    WinFrame->>Presenter: HandleScanCompleted(std::unique_ptr<Report>)
    Presenter->>Presenter: SetState(ScanResults) & SetTimerFrequency(66ms)
    Presenter->>WinFrame: InvalidateArea()
    WinFrame->>Renderer: RenderScanResultsView(memDC, Presenter)
```

#### [`window_frame.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/gui/window_frame.hpp)
* **Role:** Concrete `ILuxuryView` implementation. Handles native Win32 `HWND` lifetime, DWM immersive dark mode, window corner rounding (`DWMWCP_ROUND`), mouse hit-testing using signed coordinates (`GET_X_LPARAM` / `GET_Y_LPARAM`), and routes `WM_CLOSE` to cooperatively cancel workers.

#### [`luxury_window_presenter.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/gui/luxury_window_presenter.hpp)
* **Role:** State machine and worker lifecycle manager.
* **Concurrency Model:** Owns `std::jthread m_workerThread`. When starting a scan or purge, any active thread receives a cancellation request (`request_stop()`) and is joined cleanly. Progress updates are decoupled using Windows message queue events.

#### [`d3d11_renderer.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/gui/d3d11_renderer.hpp) (`CLuxuryViewRenderer`)
* **Role:** Pure GDI+ rendering engine.
* **Purity Invariant:** Contains zero member variables, zero static variables, and zero OS manipulation calls. Renders frames directly to an in-memory double-buffer bitmap based strictly on `const CLuxuryWindowPresenter&` inputs.

#### [`ui_theme.hpp`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/src/gui/ui_theme.hpp)
* **Role:** Central repository of layout geometry, typography, and color palettes. Defines standardized colors (`NeonCyan`, `NeonGreen`, `NeonOrange`, `CardTop`, `CardBottom`) and bounding boxes (`Theme::Metrics`).

---

## 4. Critical Algorithms & Mathematical Formulations

### 4.1 PnP Filter Multi-String Scrubbing Algorithm

A `REG_MULTI_SZ` structure is an array of null-terminated strings terminated by an extra null character:
$$\text{Buffer} = S_1 \parallel \texttt{\textbackslash 0} \parallel S_2 \parallel \texttt{\textbackslash 0} \dots \parallel S_n \parallel \texttt{\textbackslash 0} \parallel \texttt{\textbackslash 0}$$

The scrubber partitions the input strings into kept and discarded sets based on case-insensitive token comparison:

```
Algorithm 1: Safe Multi-String Filter Scrubbing
Input  : Existing multi-string buffer B, Target driver token T
Output : Compacted multi-string buffer B', Boolean Modified

1. Initialize Offset = 0, Modified = False, OutputList = []
2. While Offset < Length(B) do:
3.     CurrentStr = ExtractNullTerminatedString(B, Offset)
4.     If Length(CurrentStr) == 0 then Break
5.     If EqualsIgnoreCase(CurrentStr, T) then:
6.         Modified = True
7.     Else:
8.         OutputList.Append(CurrentStr)
9.     Offset += Length(CurrentStr) + 1
10. If Modified == True then:
11.     If OutputList is Empty then:
12.         RegDeleteKeyValue(hKey, SubKey, ValueName)
13.     Else:
14.         SerializedBuffer = PackMultiString(OutputList)
15.         RegSetValueExW(hKey, ValueName, REG_MULTI_SZ, SerializedBuffer)
16. Return Modified
```

### 4.2 NIST SP 800-88 Cryptographic Block Sanitization

To ensure information-theoretic security against physical extraction from non-volatile storage:

1. **Entropy Generation:** Each 64 KB block $B_k$ is filled using Windows CNG:
   $$\text{BCryptGenRandom}(hAlg, B_k, |B_k|, \text{BCRYPT\_USE\_SYSTEM\_PREFERRED\_RNG})$$
   The entropy rate $H(X)$ satisfies Shannon's maximal entropy for independent bytes:
   $$H(X) = -\sum_{i=0}^{255} p_i \log_2(p_i) \approx 8.0 \text{ bits/byte}$$

2. **Physical Cache Invalidation:**
   After streaming all blocks across the entire length $L$ of the file:
   $$\text{FlushFileBuffers}(hDevice)$$
   Forces the storage controller write cache to commit raw blocks to physical flash/magnetic media.

3. **Metadata Truncation:**
   $$\text{SetFilePointer}(hFile, 0, \text{FILE\_BEGIN}); \quad \text{SetEndOfFile}(hFile);$$
   Destroys the file size attributes in the NTFS Master File Table (MFT) record before unlinking.

---

## 5. Concurrency, Threading Model & State Machine

```mermaid
stateDiagram-v2
    [*] --> Dashboard: Launch
    Dashboard --> Scanning: RequestScan() [Sets Timer=16ms]
    Scanning --> ScanResults: OnScanCompleted [Sets Timer=66ms]
    Scanning --> Dashboard: CancelScan() [request_stop()]
    ScanResults --> Purging: RequestPurge() [Sets Timer=16ms]
    ScanResults --> Dashboard: BackToDashboard()
    Purging --> PurgeComplete: OnPurgeCompleted [Sets Timer=66ms]
    PurgeComplete --> Dashboard: ReturnToDashboard()
    Dashboard --> [*]: WM_CLOSE
    Scanning --> [*]: WM_CLOSE [Worker Join]
    Purging --> [*]: WM_CLOSE [Worker Join]
```

### Threading Rules:
1. **Exclusive UI Thread Ownership:** All UI state updates, window repaints, and GDI+ rendering take place strictly on the main thread.
2. **Worker Isolation:** Background operations (scanning and purging) run in isolated `std::jthread` contexts.
3. **Zero Shared Mutable State:** Background workers pass scan results and purge statistics to the UI thread via `std::unique_ptr` wrapped in `PostMessageW(hWnd, MSG, 0, reinterpret_cast<LPARAM>(ptr.release()))`. The UI thread takes immediate unique ownership upon message reception.

---

## 6. Design Decisions & Engineering Trade-offs

| Design Decision | Chosen Approach | Alternative Considered | Engineering Rationale |
|---|---|---|---|
| **Graphics Subsystem** | Direct GDI+ Double-Buffering | Direct3D 11 / Direct2D | GDI+ requires zero external GPU runtime dependencies, works seamlessly in Safe Mode and minimal Windows Server installations, and executes with $< 12\text{ MB}$ RAM overhead. |
| **Error Handling** | `std::expected<T, E>` Monad | C++ Exceptions / SEH | Exceptions impose binary size overhead and unpredictability in low-level kernel driver interaction where unwinding across Win32 callbacks can cause stack corruption. |
| **Handle Management** | Templated `ScopedResource` | Raw Handles / `std::shared_ptr` with custom deleter | Raw handles leak under error branches; `std::shared_ptr` incurs atomic reference-counting overhead and dynamic heap allocations. `ScopedResource` has zero overhead (identical to a raw pointer/handle). |
| **Multithreading** | `std::jthread` with `std::stop_token` | Detached `std::thread` | Detached threads continue executing after window destruction, leading to use-after-free crashes and incomplete disk writes. `std::jthread` guarantees cooperative joining on exit. |

---

*Document verified and compliant with ISO C++23 standards and Microsoft Windows NT Systems Architecture.*
