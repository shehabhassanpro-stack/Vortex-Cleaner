cmake_minimum_required(VERSION 3.20)
project(VortexCleaner VERSION 5.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Global Definitions
add_definitions(-DUNICODE -D_UNICODE -DNOMINMAX -DWIN32_LEAN_AND_MEAN)

# Explicit Deterministic Source List (Zero GLOB_RECURSE - Resolves VTX-SYS-017)
set(VORTEX_SOURCES
    src/main.cpp
    src/core/zstring_view.hpp
    src/core/interfaces.hpp
    src/core/result.hpp
    src/core/scoped_resource.hpp
    src/core/logger.hpp
    src/core/async_logger.hpp
    src/security/token_privilege_scope.hpp
    src/security/authorization_engine.hpp
    src/security/security_manager.hpp
    src/security/registry_dacl_manager.hpp
    src/security/vss_safety_manager.hpp
    src/security/authenticode_verifier.hpp
    src/security/binary_trust_evaluator.hpp
    src/security/pe_signature_verifier.hpp
    src/drivers/class_filter_scrubber.hpp
    src/drivers/driver_store_cleaner.hpp
    src/drivers/service_controller.hpp
    src/registry/registry_cleaner.hpp
    src/storage/nvme_trim_sanitizer.hpp
    src/storage/nist_sanitizer.hpp
    src/storage/filesystem_cleaner.hpp
    src/storage/temp_junk_cleaner.hpp
    src/storage/forensic_telemetry_cleaner.hpp
    src/storage/ntfs_journal_scrubber.hpp
    src/storage/memory_standby_flusher.hpp
    src/storage/crash_dump_purger.hpp
    src/storage/event_log_sanitizer.hpp
    src/storage/platform_library_resolver.hpp
    src/storage/real_time_scanner.hpp
    src/orchestration/target_profile_registry.hpp
    src/orchestration/purge_orchestrator.hpp
    src/gui/ui_events.hpp
    src/gui/gui_types.hpp
    src/gui/ui_theme.hpp
    src/gui/luxury_window_presenter.hpp
    src/gui/d3d11_renderer.hpp
    src/gui/window_frame.hpp
)

add_executable(VortexCleaner WIN32 ${VORTEX_SOURCES})

set_target_properties(VortexCleaner PROPERTIES
    OUTPUT_NAME "VortexCleaner_v5"
)

# Target Include Directories
target_include_directories(VortexCleaner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Linked System Libraries (Dead d3d11.lib explicitly pruned - Resolves VTX-ARCH-004)
target_link_libraries(VortexCleaner PRIVATE
    dwmapi
    setupapi
    newdev
    bcrypt
    advapi32
    srclient
    shell32
    ole32
    gdiplus
    msimg32
    version
    wintrust
    crypt32
    wevtapi
)

# Enterprise Binary Hardening & Exploit Mitigation Flags (Resolves VTX-SYS-018)
if(MSVC)
    target_compile_options(VortexCleaner PRIVATE
        /utf-8
        /W4
        /WX
        /permissive-
        /Zc:preprocessor
        /guard:cf
        /sdl
        /GS
    )
    
    target_link_options(VortexCleaner PRIVATE
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        /GUARD:CF
        /MANIFEST:EMBED
        /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'"
    )
endif()
