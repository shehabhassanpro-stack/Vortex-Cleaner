# 📋 VORTEX CLEANER — MASTER EXECUTION & IMPLEMENTATION TASKS
### High-Assurance Systems Engineering | ISO C++23 & Tier-1 Big Tech Architecture
**Reference Audit:** [`DEEP_CODE_AUDIT_REPORT.md`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/DEEP_CODE_AUDIT_REPORT.md)  
**Reference Blueprint:** [`DEEP_ARCHITECTURAL_SOLUTIONS_BLUEPRINT.md`](file:///d:/VIP/Project/driver-level%20spoofer/Vortex%20Cleaner/DEEP_ARCHITECTURAL_SOLUTIONS_BLUEPRINT.md)  
**Compiler Standard:** MSVC 19.51+ (Visual Studio 2026) | `/std:c++23 /permissive- /WX /guard:cf /sdl /GS`  
**Current Status:** `38 / 38 Tasks Completed` (100%)

---

## 📊 REAL-TIME EXECUTION DASHBOARD

| Phase | Description | Task Count | Completed | Status |
|---|---|:---:|:---:|:---:|
| **Phase 1** | Core Foundation, Type Safety & Zero-Leak RAII Systems | 7 | 7 | ✅ COMPLETED |
| **Phase 2** | Cryptographic Sanitization, SSD Media & Authorization Engine | 8 | 8 | ✅ COMPLETED |
| **Phase 3** | Kernel Services, SCM Controller, DriverStore & PnP Scrubbing | 4 | 4 | ✅ COMPLETED |
| **Phase 4** | Target Profiles, Registry Engines & Modular Cleaners | 6 | 6 | ✅ COMPLETED |
| **Phase 5** | Presentation Layer, Concurrency & MVP Decomposition | 9 | 9 | ✅ COMPLETED |
| **Phase 6** | Asynchronous I/O, Logging Engine, CLI & Build Hardening | 4 | 4 | ✅ COMPLETED |
| **TOTAL** | **Enterprise Hardening Lifecycle** | **38** | **38** | **100%** |

---

## 🧭 EXECUTION RULES & SAFETY PROTOCOLS

1. **Topological Order Invariance:** Tasks MUST be executed strictly according to their Phase numbering (Phase 1 \(\to\) Phase 6). Do NOT jump across phases.
2. **Zero-Warning Gate (`/WX`):** Every code modification must build cleanly under `/WX` (warnings treated as errors). No build warnings are tolerated.
3. **Check-Off Protocol:** When a task is fully implemented, verified, and compiled with exit code 0, change `[ ]` to `[x]` in this document.
4. **Binary Non-Regression:** After completing each Phase, the executable `build/Release/VortexCleaner.exe` must be compiled and verified.

---

## 🧱 PHASE 1: CORE FOUNDATION, TYPE SAFETY & ZERO-LEAK RAII SYSTEMS

- [x] **TASK-01: Extract Shared UI Types (`gui_types.hpp`) to Eliminate ODR Violations**
  - **Defect Addressed:** `VTX-AUDIT-001` (CRITICAL - ODR Violation Risk)
  - **Files Affected:**
    - `src/gui/gui_types.hpp` *(NEW FILE)*
    - `src/gui/d3d11_renderer.hpp` (Lines 24–37)
    - `src/gui/luxury_window_presenter.hpp` (Lines 13–26)
  - **Implementation Detail:** Create `src/gui/gui_types.hpp` containing the definitive `enum class ViewState : uint8_t` and `struct UIRect`. Remove duplicate definitions from `d3d11_renderer.hpp` and `luxury_window_presenter.hpp`, replacing them with `#include "gui_types.hpp"`.
  - **Verification:** Both headers must compile within the same translation unit without redeclaration errors.

- [x] **TASK-02: Implement RAII Wrappers for Windows NT SIDs and ACLs**
  - **Defect Addressed:** `VTX-AUDIT-003` (CRITICAL - SID Memory Leak & UB)
  - **Files Affected:**
    - `src/core/scoped_resource.hpp` (Lines 67–73)
  - **Implementation Detail:** Add type aliases in `scoped_resource.hpp`:
    ```cpp
    using ScopedSid = ScopedResource<PSID, ::FreeSid, static_cast<PSID>(nullptr)>;
    using ScopedAcl = ScopedResource<PACL, ::LocalFree, static_cast<PACL>(nullptr)>;
    ```
  - **Verification:** Verify that `ScopedSid` and `ScopedAcl` automatically release resources upon destruction without manual `FreeSid`/`LocalFree`.

- [x] **TASK-03: C++23 Concept Specialization for Handle Validation in `ScopedResource`**
  - **Defect Addressed:** `VTX-AUDIT-021`, `VTX-AUDIT-045` (MEDIUM & LOW)
  - **Files Affected:**
    - `src/core/scoped_resource.hpp` (Lines 52–65)
  - **Implementation Detail:**
    - Specialize `IsValid()`: For `HANDLE` types, properly distinguish between `NULL` and `INVALID_HANDLE_VALUE`. For pointer/HKEY types, check only `m_handle != InvalidValue`.
    - Mark `operator HandleType()` as `explicit` to prevent implicit ownership escapes.
  - **Verification:** Unit test handle validity checks against `HKEY`, `SC_HANDLE`, and file `HANDLE`.

- [x] **TASK-04: Enforce Explicit Conversion on `zstring_view`**
  - **Defect Addressed:** `VTX-AUDIT-037` (MEDIUM - Overload Resolution Ambiguity)
  - **Files Affected:**
    - `src/core/zstring_view.hpp` (Lines 45–49)
  - **Implementation Detail:** Mark `operator const wchar_t*()` as `explicit`. Ensure `.c_str()` remains the primary accessor for Win32 API interop.
  - **Verification:** Verify zero ambiguous overload compilation errors with `std::wstring_view` parameters.

- [x] **TASK-05: Enclose File-Scope Namespace Aliases in Header Files**
  - **Defect Addressed:** `VTX-AUDIT-039` (LOW - Namespace Leakage)
  - **Files Affected:**
    - `src/storage/filesystem_cleaner.hpp` (Line 11)
    - `src/storage/platform_library_resolver.hpp` (Line 13)
    - `src/storage/real_time_scanner.hpp` (Line 12)
    - `src/storage/temp_junk_cleaner.hpp` (Line 10)
    - `src/storage/forensic_telemetry_cleaner.hpp` (Line 18)
    - `src/orchestration/purge_orchestrator.hpp` (Line 27)
  - **Implementation Detail:** Move `namespace fs = std::filesystem;` inside the enclosing `WinTracePurge::...` namespace blocks.
  - **Verification:** Verify no global `fs` alias leaks into external translation units.

- [x] **TASK-06: Preserve Win32 `GetLastError()` in `SystemError::FromLastError()`**
  - **Defect Addressed:** `VTX-AUDIT-044` (LOW - TOCTOU Error Code Overwrite)
  - **Files Affected:**
    - `src/core/result.hpp` (Lines 71–74)
  - **Implementation Detail:** Capture `const DWORD err = ::GetLastError();` immediately as the very first instruction before any string allocation or formatting.
  - **Verification:** Verify that error formatting retains the authentic Win32 error code.

- [x] **TASK-07: Replace Raw `HKEY` Handle with `ScopedHKey` in Library Resolver**
  - **Defect Addressed:** `VTX-AUDIT-004` (CRITICAL - Handle Leak Risk)
  - **Files Affected:**
    - `src/storage/platform_library_resolver.hpp` (Lines 52–58)
  - **Implementation Detail:** Replace `HKEY hSteamKey` with `Core::ScopedHKey hSteamKey;` and query using `hSteamKey.Put()` and `hSteamKey.Get()`.
  - **Verification:** Verify automated closure of the Steam registry key on all branch exits.

---

## 🔒 PHASE 2: CRYPTOGRAPHIC SANITIZATION, SSD TOPOLOGY & AUTHORIZATION ENGINE

- [x] **TASK-08: Per-Chunk True CSPRNG Stream Generator in `CNistSanitizer`**
  - **Defect Addressed:** `VTX-AUDIT-006` (CRITICAL - Repeating Pattern Security Weakness)
  - **Files Affected:**
    - `src/storage/nist_sanitizer.hpp` (Lines 57–77)
  - **Implementation Detail:** Move `::BCryptGenRandom` inside the `while (bytesRemaining > 0)` loop, generating fresh cryptographically secure random bytes for each 64KB block.
  - **Verification:** Mathematical verification that Shannon Entropy \(H(X) \ge 7.999\) bits/byte across all file sectors without repeating periodic autocorrelation.

- [x] **TASK-09: Dynamic Two-Pass Adapter Query in `CNvmeTrimSanitizer`**
  - **Defect Addressed:** `VTX-AUDIT-049` (LOW - Undersized Stack Buffer)
  - **Files Affected:**
    - `src/storage/nvme_trim_sanitizer.hpp` (Lines 75–81)
  - **Implementation Detail:** Issue a two-pass `IOCTL_STORAGE_QUERY_PROPERTY` using `STORAGE_DESCRIPTOR_HEADER` first to determine the exact required buffer size, then allocate a dynamic heap buffer.
  - **Verification:** Verify robust detection of NVMe/SATA bus types on devices with extended vendor descriptors.

- [x] **TASK-10: Dynamic KnownFolder API Resolution in `CForensicTelemetryCleaner`**
  - **Defect Addressed:** `VTX-AUDIT-016` (HIGH - Hardcoded `C:\` System Paths)
  - **Files Affected:**
    - `src/storage/forensic_telemetry_cleaner.hpp` (Lines 194–207, Line 265)
  - **Implementation Detail:** Replace hardcoded `C:\ProgramData` and `C:\Windows` with dynamic queries to `SHGetKnownFolderPath(FOLDERID_ProgramData)` and `::GetWindowsDirectoryW()`.
  - **Verification:** Test on multi-drive Windows installations where the OS partition is non-C:.

- [x] **TASK-11: Build Centralized `CAuthorizationEngine` & Refactor DACL Managers**
  - **Defect Addressed:** `VTX-AUDIT-003`, `VTX-AUDIT-020` (CRITICAL & HIGH - Code Duplication & UB)
  - **Files Affected:**
    - `src/security/authorization_engine.hpp` *(NEW FILE)*
    - `src/security/registry_dacl_manager.hpp` (Lines 20–93)
    - `src/security/security_manager.hpp` (Lines 60–115)
  - **Implementation Detail:** Implement `CAuthorizationEngine` with full RAII (`ScopedSid`, `ScopedAcl`), comprehensive error checks on `AllocateAndInitializeSid`, and parameterized `SE_OBJECT_TYPE`. Delegate `CRegistryDaclManager` and `CSecurityManager` to this canonical engine.
  - **Verification:** Test ownership seizure and DACL modification on protected registry keys with zero memory leaks.

- [x] **TASK-12: Enforce Ephemeral RAII Token Privilege Scoping**
  - **Defect Addressed:** `VTX-AUDIT-014` (HIGH - Persistent Privilege Escalation Leak)
  - **Files Affected:**
    - `src/security/security_manager.hpp` (Lines 50–58)
  - **Implementation Detail:** Remove `static auto s_persistentScope`. Privilege escalation must return a stack-allocated `TokenPrivilegeScope` whose destructor automatically restores the original token privileges upon exit.
  - **Verification:** Verify that process token privileges revert to standard user/admin state after cleanup pipeline execution.

- [x] **TASK-13: Optimize Authenticode Verification & Streamline PE Verifier**
  - **Defect Addressed:** `VTX-AUDIT-040`, `VTX-AUDIT-041` (LOW - Redundant I/O & Class Bloat)
  - **Files Affected:**
    - `src/security/authenticode_verifier.hpp` (Lines 59–88)
    - `src/security/pe_signature_verifier.hpp` (Lines 8–15)
  - **Implementation Detail:** In `CAuthenticodeVerifier::InspectSignature`, reuse certificate store queries to avoid reopening the binary file twice. Simplify `CPeSignatureVerifier` to a lightweight type alias.
  - **Verification:** Benchmark reduced file I/O latency during multi-drive scanning.

- [x] **TASK-14: Implement Locale-Safe Case-Insensitive Matching in `CBinaryTrustEvaluator`**
  - **Defect Addressed:** `VTX-AUDIT-022`, `VTX-AUDIT-023` (MEDIUM - Dead Code & Locale Vulnerability)
  - **Files Affected:**
    - `src/security/binary_trust_evaluator.hpp` (Lines 39–60, Lines 72–80)
  - **Implementation Detail:** Remove dead `ContainsIgnoreCase` method. Replace raw `::towlower` transformations with `std::ranges::equal` parameterized by a locale-invariant comparator.
  - **Verification:** Verify string matches on Turkish and international Windows locales.

- [x] **TASK-15: Diagnostic Logging for VSS Description Truncation**
  - **Defect Addressed:** `VTX-AUDIT-048` (LOW - Silent String Truncation)
  - **Files Affected:**
    - `src/security/vss_safety_manager.hpp` (Lines 47–49)
  - **Implementation Detail:** Check description string length before copying to `restorePointInfo.szDescription`. Emit an informational log if truncation occurs.
  - **Verification:** Pass descriptions > 64 characters and verify warning log emission.

---

## ⚙️ PHASE 3: KERNEL SERVICES, SCM CONTROLLER, DRIVERSTORE & PNP SCRUBBING

- [x] **TASK-16: Target-Aware SCM Dependency Teardown Filtering**
  - **Defect Addressed:** `VTX-AUDIT-011` (HIGH - Collateral Destruction of Shared Services)
  - **Files Affected:**
    - `src/drivers/service_controller.hpp` (Lines 239–258)
  - **Implementation Detail:** Before recursively calling `StopAndPurgeService` on dependent services in `StopDependentServices`, query the dependent service's binary path and pass it to `CBinaryTrustEvaluator::IsTargetAntiCheatBinary()`. Only proceed if confirmed as a target component.
  - **Verification:** Test mock service hierarchy with legitimate shared system dependencies.

- [x] **TASK-17: RAII Dynamic Module Loading in `CDriverStoreCleaner`**
  - **Defect Addressed:** `VTX-AUDIT-015` (HIGH - `setupapi.dll` Resource Leak)
  - **Files Affected:**
    - `src/drivers/driver_store_cleaner.hpp` (Lines 116–125)
  - **Implementation Detail:** Wrap dynamic `LoadLibraryW(L"setupapi.dll")` in `Core::ScopedResource<HMODULE, ::FreeLibrary>`.
  - **Verification:** Verify zero module handle leaks during DriverStore enumeration.

- [x] **TASK-18: Bounds-Checked String Operations in Driver Store & Class Filters**
  - **Defect Addressed:** `VTX-AUDIT-024`, `VTX-AUDIT-025` (MEDIUM - Sliced String View Misuse)
  - **Files Affected:**
    - `src/drivers/class_filter_scrubber.hpp` (Lines 160–165, Lines 188–193)
    - `src/drivers/driver_store_cleaner.hpp` (Lines 158–164)
  - **Implementation Detail:** Replace `_wcsicmp` and `wcsstr` with bounds-safe `std::wstring_view` comparisons (`std::ranges::equal` and `.find()`).
  - **Verification:** Test string comparisons against non-null-terminated `std::wstring_view` slices.

- [x] **TASK-19: Comprehensive RAII Handle Adoption in `CRealTimeScanEngine`**
  - **Defect Addressed:** `VTX-AUDIT-012`, `VTX-AUDIT-013`, `VTX-AUDIT-050` (HIGH & LOW - Handle Leaks & Missing Header)
  - **Files Affected:**
    - `src/storage/real_time_scanner.hpp` (Line 3, Lines 76–161)
  - **Implementation Detail:**
    - Add `#include <functional>`.
    - Replace raw `SC_HANDLE` with `Core::ScopedSCMHandle`.
    - Replace raw `HKEY` with `Core::ScopedHKey`.
  - **Verification:** Verify zero open handle leaks via Process Explorer during repeated real-time scans.

---

## 🗃️ PHASE 4: TARGET PROFILES, REGISTRY ENGINES & MODULAR CLEANERS

- [x] **TASK-20: Fix Critical Driver Typo `bedisy.sys` & Unify Target Constants**
  - **Defect Addressed:** `VTX-AUDIT-005`, `VTX-AUDIT-035` (CRITICAL & MEDIUM - Data Typo & Redundancy)
  - **Files Affected:**
    - `src/orchestration/target_profile_registry.hpp` (Lines 37–96)
  - **Implementation Detail:**
    - Correct typo `bedisy.sys` \(\to\) `bedrive.sys`.
    - Create a canonical `TargetConstants` struct/namespace containing target service names, driver filenames, and registry paths.
    - Refactor `GetConfigForProfile` to inherit from a common base configuration, overriding only profile-specific flags.
  - **Verification:** Verify that BattlEye drivers (`bedrive.sys`) are correctly matched and targeted in all profiles.

- [x] **TASK-21: Exact Token Delimiter Enforcement in `IsHivePathCompatible`**
  - **Defect Addressed:** `VTX-AUDIT-027` (MEDIUM - Overly Broad Key Filter)
  - **Files Affected:**
    - `src/registry/registry_cleaner.hpp` (Lines 29–59)
  - **Implementation Detail:** Require exact token delimiter (`\\` or `/`) after `SYSTEM`, preventing false-positive blocking of valid subkeys like `SystemCertificates`.
  - **Verification:** Unit test `IsHivePathCompatible(HKEY_CURRENT_USER, L"SystemCertificates")` returns `true`.

- [x] **TASK-22: Symmetric Telemetry Discovery Accounting in `CForensicTelemetryCleaner`**
  - **Defect Addressed:** `VTX-AUDIT-028` (MEDIUM - BAM Accounting Inconsistency)
  - **Files Affected:**
    - `src/storage/forensic_telemetry_cleaner.hpp` (Lines 231–274)
  - **Implementation Detail:** Refactor `Scan()` to enumerate individual BAM/DAM binary execution entries rather than only reporting root key existence, ensuring `ItemsScanned == ItemsPurged`.
  - **Verification:** Verify that scan results report the exact item count subsequently purged.

- [x] **TASK-23: Implement `Core::ICleanerModule` on `CTempJunkCleanerModule`**
  - **Defect Addressed:** `VTX-AUDIT-029` (MEDIUM - Interface Non-Compliance)
  - **Files Affected:**
    - `src/storage/temp_junk_cleaner.hpp` (Lines 14–24)
  - **Implementation Detail:** Make `CTempJunkCleanerModule` inherit from `Core::ICleanerModule`. Implement `GetModuleName()`, `Scan()`, and `Purge()` contracts.
  - **Verification:** Register `CTempJunkCleanerModule` dynamically via `orchestrator.RegisterModule()`.

- [x] **TASK-24: Implement `Core::ICleanerModule` on `CFileSystemCleaner`**
  - **Defect Addressed:** `VTX-AUDIT-030` (MEDIUM - Interface Non-Compliance)
  - **Files Affected:**
    - `src/storage/filesystem_cleaner.hpp` (Lines 15–20)
  - **Implementation Detail:** Convert `CFileSystemCleaner` to implement the `Core::ICleanerModule` interface for polymorphic orchestration.
  - **Verification:** Polymorphic invocation of `Scan()` and `Purge()` via base pointer.

- [x] **TASK-25: Hive-Aware Orchestrator Purging & Concept Application**
  - **Defect Addressed:** `VTX-AUDIT-033`, `VTX-AUDIT-047` (MEDIUM & LOW - Blind Hive Purge & Unused Concept)
  - **Files Affected:**
    - `src/orchestration/purge_orchestrator.hpp` (Lines 110–120, Lines 50–55)
  - **Implementation Detail:**
    - Apply `IsHivePathCompatible` before attempting `PurgeSubtree` on `HKCU`.
    - Constrain `RegisterModule` with the C++23 `CleanerModuleType` concept.
  - **Verification:** Verify zero redundant HKCU lookups for `SYSTEM\\CurrentControlSet` in Registry Monitor logs.

---

## 🎨 PHASE 5: PRESENTATION LAYER, CONCURRENCY & MVP DECOMPOSITION

- [x] **TASK-26: Deconstruct 951-Line `CLuxuryWindowRenderer` into Clean MVP**
  - **Defect Addressed:** `VTX-AUDIT-007` (HIGH - Monolithic God Object)
  - **Files Affected:**
    - `src/gui/d3d11_renderer.hpp` (Full refactor into `CLuxuryViewRenderer`)
    - `src/gui/luxury_window_presenter.hpp`
    - `src/gui/window_frame.hpp` *(NEW FILE)*
  - **Implementation Detail:** Separate responsibilities:
    1. `CLuxuryViewRenderer`: GDI+ graphics rendering only. Zero state mutation, zero worker threads.
    2. `CLuxuryWindowPresenter`: State machine, progress tracking, and worker job management.
    3. `CWindowFrame`: Window creation, DWM attributes, and message routing.
  - **Verification:** Verify individual unit testability of Presenter without instantiating Win32 windows.

- [x] **TASK-27: Wire Up MVP Presenter to Window Event Loop**
  - **Defect Addressed:** `VTX-AUDIT-008` (HIGH - Dead Code Elimination)
  - **Files Affected:**
    - `src/gui/luxury_window_presenter.hpp`
    - `src/gui/d3d11_renderer.hpp`
    - `src/main.cpp`
  - **Implementation Detail:** Connect `CLuxuryWindowPresenter` to the window event loop. Have `WindowProc` route messages (`WM_APP_*`, `WM_LBUTTONDOWN`) directly into the presenter.
  - **Verification:** Verify complete elimination of dead code warnings and full functional coverage of the presenter.

- [x] **TASK-28: Eliminate Thread-Safety Violations in Shared UI State**
  - **Defect Addressed:** `VTX-AUDIT-002` (CRITICAL - Unsynchronized Static State)
  - **Files Affected:**
    - `src/gui/luxury_window_presenter.hpp`
    - `src/gui/d3d11_renderer.hpp`
  - **Implementation Detail:** Eliminate shared mutable static state. Transfer report and statistics payloads strictly via `std::unique_ptr` passed as `LPARAM` in `PostMessageW`. The UI thread remains the exclusive owner of presentation state.
  - **Verification:** Run ThreadSanitizer (TSan) or stress-test with rapid Scan/Cancel/Purge cycles.

- [x] **TASK-29: Bind GUI Purge Pipeline to `CTargetProfileRegistry`**
  - **Defect Addressed:** `VTX-AUDIT-036` (MEDIUM - Hardcoded GUI Target Bypass)
  - **Files Affected:**
    - `src/gui/d3d11_renderer.hpp` (Lines 758–778)
  - **Implementation Detail:** In `StartLivePurge`, obtain base configuration via `CTargetProfileRegistry::GetConfigForProfile(ProfileKind::AntiCheatStandard)`, then overlay dynamically discovered files from the scan report.
  - **Verification:** Confirm that targets purged by the GUI match the profile registry specification.

- [x] **TASK-30: Signed Multi-Monitor Coordinate Resolution with `<windowsx.h>`**
  - **Defect Addressed:** `VTX-AUDIT-009` (HIGH - Multi-Monitor Mouse Hit-Test Truncation)
  - **Files Affected:**
    - `src/gui/d3d11_renderer.hpp` (Lines 849–850, Lines 892–893)
  - **Implementation Detail:** `#include <windowsx.h>` and replace `LOWORD(lParam)` / `HIWORD(lParam)` with `GET_X_LPARAM(lParam)` and `GET_Y_LPARAM(lParam)`.
  - **Verification:** Test UI button hit-testing on secondary monitors situated to the left of the primary display.

- [x] **TASK-31: Cooperative Worker Thread Cancellation via `std::jthread` & Stop Tokens**
  - **Defect Addressed:** `VTX-AUDIT-017` (HIGH - Detached Worker Threads)
  - **Files Affected:**
    - `src/gui/luxury_window_presenter.hpp`
    - `src/gui/d3d11_renderer.hpp`
  - **Implementation Detail:** Store background worker threads as `std::jthread`. Pass `std::stop_token` to scan and purge routines. Ensure automatic cancellation and join on window destruction.
  - **Verification:** Close window midway through a deep purge; verify immediate, clean termination without process crash or memory leak.

- [x] **TASK-32: Adaptive Dynamic Animation Timer Throttling**
  - **Defect Addressed:** `VTX-AUDIT-034` (MEDIUM - Frozen Ambient Dashboard Animation)
  - **Files Affected:**
    - `src/gui/d3d11_renderer.hpp` (Lines 799–805, Lines 881–890)
  - **Implementation Detail:** Implement dual-rate timer: 60Hz (16ms) during active `Scanning`/`Purging` states for smooth progress spinner animation; 15Hz (66ms) on idle `Dashboard` to animate ambient radar arcs with < 0.1% CPU consumption.
  - **Verification:** Profile CPU usage in Task Manager: verify 0.0%–0.1% CPU utilization on idle dashboard while ambient arcs rotate smoothly.

- [x] **TASK-33: Centralize UI Metrics and Color Palettes into Theme System**
  - **Defect Addressed:** `VTX-AUDIT-042` (LOW - Magic Constants in Rendering)
  - **Files Affected:**
    - `src/gui/ui_theme.hpp` *(NEW FILE)*
    - `src/gui/d3d11_renderer.hpp`
  - **Implementation Detail:** Define `struct LuxuryTheme` with standard constexpr GDI+ colors, font families, margins, and corner radii.
  - **Verification:** Verify visual consistency and zero hardcoded magic hex codes across rendering routines.

- [x] **TASK-34: Graceful Shutdown on `WM_CLOSE` with Log Flushing**
  - **Defect Addressed:** `VTX-AUDIT-019`, `VTX-AUDIT-046` (HIGH & LOW - Window Registration & Shutdown)
  - **Files Affected:**
    - `src/gui/d3d11_renderer.hpp` (Lines 104–106, Line 790)
  - **Implementation Detail:**
    - Check return value of `::RegisterClassExW`.
    - Explicitly handle `WM_CLOSE`, trigger worker cancellation, flush logger buffers, and destroy window cleanly.
  - **Verification:** Verify log file contains clean session close record upon closing window.

---

## 🚀 PHASE 6: ASYNCHRONOUS I/O, LOGGING ENGINE, CLI & BUILD HARDENING

- [x] **TASK-35: Thread-Safe `std::call_once` Logger Initialization**
  - **Defect Addressed:** `VTX-AUDIT-010` (HIGH - Auto-Init Race Condition)
  - **Files Affected:**
    - `src/core/async_logger.hpp` (Lines 43–55, Lines 72–76)
  - **Implementation Detail:** Guard `Initialize()` using `std::once_flag` and `std::call_once`, guaranteeing exactly-once execution across all caller threads.
  - **Verification:** Stress test logger auto-init with 50 concurrent threads logging simultaneously.

- [x] **TASK-36: Diagnostic Fallback Logging Channel**
  - **Defect Addressed:** `VTX-AUDIT-018`, `VTX-AUDIT-038` (HIGH & MEDIUM - Silent Log Failure & Hot-Path Copies)
  - **Files Affected:**
    - `src/core/async_logger.hpp` (Lines 77–85, Lines 130–135)
  - **Implementation Detail:**
    - If primary log file fails to open, fall back to `%TEMP%\\VortexCleaner_Fallback.log` and emit `OutputDebugStringW`.
    - Optimize `PostLog` by taking `std::wstring&&` or using move semantics to avoid redundant heap allocations.
  - **Verification:** Test logging with read-only working directory; verify fallback file creation.

- [x] **TASK-37: Secure Native Console Handling in CLI Mode**
  - **Defect Addressed:** `VTX-AUDIT-031`, `VTX-AUDIT-032` (MEDIUM - Command Injection & Unused Pointers)
  - **Files Affected:**
    - `src/main.cpp` (Lines 68–78)
  - **Implementation Detail:**
    - Check return values of `freopen_s`.
    - Replace vulnerable `system("pause")` with safe native input:
      ```cpp
      std::wcout << L"\nPress Enter to exit...";
      std::wstring dummy;
      std::getline(std::wcin, dummy);
      ```
  - **Verification:** Run `VortexCleaner.exe --cli` from a directory with a malicious `pause.bat` on PATH; confirm no child process spawned.

- [x] **TASK-38: Modernize CMake Source Sets & Execute Enterprise Build Hardening**
  - **Defect Addressed:** `VTX-AUDIT-043` (LOW - Header Source Bloat)
  - **Files Affected:**
    - `CMakeLists.txt`
  - **Implementation Detail:** Update `CMakeLists.txt` to register newly added headers (`gui_types.hpp`, `authorization_engine.hpp`, `ui_theme.hpp`). Ensure `/WX /guard:cf /sdl /GS /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` compile and link cleanly.
  - **Verification:** Execute `cmake --build build --config Release`. Verify Exit Code 0, Zero Warnings, Zero Errors.

---

*This document is the official tracking matrix for the Vortex Cleaner codebase hardening. Check off tasks as completed.*
