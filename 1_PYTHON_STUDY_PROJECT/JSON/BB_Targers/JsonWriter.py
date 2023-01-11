import json;

from enum import Enum, unique

@unique
class TargetType(Enum):
    UNDEFINED = 0;
    UNIT_TESTS = 1;
    BROWSER_TESTS = 2;
    PERFORMANCE_TESTS = 3;
    INSTALLER_PY_TESTS = 4; 

targets = list();

targets.append(dict(name = "chromedriver_tests", buildCommand = "chrome/test/chromedriver:chromedriver_tests", executableName = "chromedriver_tests.exe", description = "  [Chromedriver tests]"));
targets.append(dict(name = "chromedriver_unittests", buildCommand = "chrome/test/chromedriver:chromedriver_unittests", executableName = "chromedriver_unittests.exe", description = "  [Chromedriver unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "elevation_service_unittests", buildCommand = "chrome/elevation_service:elevation_service_unittests", executableName = "elevation_service_unittests.exe", description = "  [Elevation service unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "vr_common_unittests", buildCommand = "chrome/browser/vr:vr_common_unittests", executableName = "vr_common_unittests.exe", description = "  [Common unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "url_unittests", buildCommand = "url:url_unittests", executableName = "url_unittests.exe", description = "  [URL unit test suite]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "accessibility_unittests", buildCommand = "ui/accessibility:accessibility_unittests", executableName = "accessibility_unittests.exe", description = "  [Accessibility unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "display_unittests", buildCommand = "ui/display:display_unittests", executableName = "display_unittests.exe", description = "  [Display unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "events_unittests", buildCommand = "ui/events:events_unittests", executableName = "events_unittests.exe", description = "  [Events unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "latency_unittests", buildCommand = "ui/latency:latency_unittests", executableName = "latency_unittests.exe", description = "  [Latency unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "ui_touch_selection_unittests", buildCommand = "ui/touch_selection:ui_touch_selection_unittests", executableName = "ui_touch_selection_unittests.exe", description = "  [UI touch selection unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "views_unittests", buildCommand = "ui/views:views_unittests", executableName = "views_unittests.exe", description = "  [unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "zucchini_unittests", buildCommand = "components/zucchini:zucchini_unittests", executableName = "zucchini_unittests.exe", description = "  [ Zucchini unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "cronet_tests", buildCommand = "components/cronet:cronet_tests", executableName = "cronet_tests.exe", description = "  [Cronet tests]"));
targets.append(dict(name = "cronet_unittests", buildCommand = "components/cronet:cronet_unittests", executableName = "cronet_unittests.exe", description = "  [ Cronet unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "cast_unittests", buildCommand = "media/cast:cast_unittests", executableName = "cast_unittests.exe", description = "  [Cast unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "midi_unittests", buildCommand = "media/midi:midi_unittests", executableName = "midi_unittests.exe", description = "  [Midi unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "media_mojo_unittests", buildCommand = "media/mojo:media_mojo_unittests", executableName = "media_mojo_unittests.exe", description = "  [Media mojo unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "media_service_unittests", buildCommand = "media/mojo/services:media_service_unittests", executableName = "media_service_unittests.exe", description = "  [ Media service unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "url_ipc_unittests", buildCommand = "url/ipc:url_ipc_unittests", executableName = "url_ipc_unittests.exe", description = "  [Url ipc unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "sbox_validation_tests", buildCommand = "sandbox/win:sbox_validation_tests", executableName = "sbox_validation_tests.exe", description = "  [SandBox validation tests]"));
targets.append(dict(name = "ppapi_unittests", buildCommand = "ppapi:ppapi_unittests", executableName = "ppapi_unittests.exe", description = "  [PPApi unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "sbox_integration_tests", buildCommand = "sandbox/win:sbox_integration_tests", executableName = "sbox_integration_tests.exe", description = "  [SandBox integration_tests]"));
targets.append(dict(name = "chrome_elf_import_unittests", buildCommand = "chrome_elf:chrome_elf_import_unittests", executableName = "chrome_elf_import_unittests.exe", description = "  [Chrome elf import unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "chrome_elf_unittests", buildCommand = "chrome_elf:chrome_elf_unittests", executableName = "chrome_elf_unittests.exe", description = "  [Chrome elf  unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "gpu_unittests", buildCommand = "gpu:gpu_unittests", executableName = "gpu_unittests.exe", description = "  [GPU unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "ipc_tests", buildCommand = "ipc:ipc_tests", executableName = "ipc_tests.exe", description = "  [IPC tests]"));
targets.append(dict(name = "cacheinvalidation_unittests", buildCommand = "third_party/cacheinvalidation:cacheinvalidation_unittests", executableName = "cacheinvalidation_unittests.exe", description = "  [Cache invalidation unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "env_chromium_unittests", buildCommand = "third_party/leveldatabase:env_chromium_unittests", executableName = "env_chromium_unittests.exe", description = "  [Chrome environment unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "libphonenumber_unittests", buildCommand = "third_party/libphonenumber:libphonenumber_unittests", executableName = "libphonenumber_unittests.exe", description = "  [Library phone number unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "device_unittests", buildCommand = "device:device_unittests", executableName = "device_unittests.exe", description = "  [Device unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "crypto_unittests", buildCommand = "crypto:crypto_unittests", executableName = "crypto_unittests.exe", description = "  [Crypto unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "gcm_unit_tests", buildCommand = "google_apis/gcm:gcm_unit_tests", executableName = "gcm_unit_tests.exe", description = "  [GCM unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "skia_unittests", buildCommand = "skia:skia_unittests", executableName = "skia_unittests.exe", description = "  [ Skia unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "storage_unittests", buildCommand = "storage:storage_unittests", executableName = "storage_unittests.exe", description = "  [ Storage unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "mojo_unittests", buildCommand = "mojo:mojo_unittests", executableName = "mojo_unittests.exe", description = "  [ Mojo unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "printing_unittests", buildCommand = "printing:printing_unittests", executableName = "printing_unittests.exe", description = "  [ Printing unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "jingle_unittests", buildCommand = "jingle:jingle_unittests", executableName = "jingle_unittests.exe", description = "  [ Jingle unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "cloud_print_unittests", buildCommand = "cloud_print:cloud_print_unittests", executableName = "cloud_print_unittests.exe", description = "  [ Cloud print unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "chrome_app_unittests", buildCommand = "chrome/test:chrome_app_unittests", executableName = "chrome_app_unittests.exe", description = "  [ Chrome app unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "headless_unittests", buildCommand = "headless:headless_unittests", executableName = "headless_unittests.exe", description = "  [Headless unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "captured_sites_interactive_tests", buildCommand = "chrome/test:captured_sites_interactive_tests", executableName = "captured_sites_interactive_tests.exe", description = "  [Captured sites interactive tests]"));
targets.append(dict(name = "wm_unittests", buildCommand = "ui/wm:wm_unittests", executableName = "wm_unittests.exe", description = "  [WM unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "mojo_core_unittests", buildCommand = "mojo/core:mojo_core_unittests", executableName = "mojo_core_unittests.exe", description = "  [Mojo core unit tests]", type = TargetType.UNIT_TESTS));    
targets.append(dict(name = "native_theme_unittests", buildCommand = "ui/native_theme:native_theme_unittests", executableName = "native_theme_unittests.exe", description = "  [Native theme unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "message_center_unittests", buildCommand = "ui/message_center:message_center_unittests", executableName = "message_center_unittests.exe", description = "  [Message center unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "cctest", buildCommand = "v8/test/cctest:cctest", executableName = "cctest.exe", description = "  [CCTests]"));
targets.append(dict(name = "libaddressinput_unittests", buildCommand = "third_party/libaddressinput:libaddressinput_unittests", executableName = "libaddressinput_unittests.exe", description = "  [Library address input unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "capture_unittests", buildCommand = "media/capture:capture_unittests", executableName = "capture_unittests.exe", description = "  [Capture unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "ui_base_unittests", buildCommand = "ui/base:ui_base_unittests", executableName = "ui_base_unittests.exe", description = "  [Base unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "compositor_unittests", buildCommand = "ui/compositor:compositor_unittests", executableName = "compositor_unittests.exe", description = "  [Compositor unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "media_pipeline_integration_unittests", buildCommand = "media/mojo/services:media_pipeline_integration_unittests", executableName = "media_pipeline_integration_unittests.exe", description = "  [Media pipeline integration unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "media_unittests", buildCommand = "media:media_unittests", executableName = "media_unittests.exe", description = "  [Media unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "sql_unittests", buildCommand = "sql:sql_unittests", executableName = "sql_unittests.exe", description = "  [SQL unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "gin_unittests", buildCommand = "gin:gin_unittests", executableName = "gin_unittests.exe", description = "  [Git unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "courgette_unittests", buildCommand = "courgette:courgette_unittests", executableName = "courgette_unittests.exe", description = "  [Courgette unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "install_static_unittests", buildCommand = "chrome/install_static:install_static_unittests", executableName = "install_static_unittests.exe", description = "  [Install static unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "angle_white_box_tests", buildCommand = "third_party/angle/src/tests:angle_white_box_tests", executableName = "angle_white_box_tests.exe", description = "  [Angle white box tests]"));
targets.append(dict(name = "webkit_unit_tests", buildCommand = "third_party/blink/renderer/controller:webkit_unit_tests", executableName = "webkit_unit_tests.exe", description = "  [WebKit unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "wtf_unittests", buildCommand = "third_party/blink/renderer/platform/wtf:wtf_unittests", executableName = "wtf_unittests.exe", description = "  [ WTF unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "blink_common_unittests", buildCommand = "third_party/blink/common:blink_common_unittests", executableName = "blink_common_unittests.exe", description = "  [Blink common unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "sbox_unittests", buildCommand = "sandbox/win:sbox_unittests", executableName = "sbox_unittests.exe", description = "  [Sand Box unit test suite]", type = TargetType.UNIT_TESTS)); 
targets.append(dict(name = "chrome_cleaner_unittests", buildCommand = "chrome/chrome_cleaner:chrome_cleaner_unittests", executableName = "chrome_cleaner_unittests.exe", description = "  [Chrome cleaner unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "gfx_unittests", buildCommand = "ui/gfx:gfx_unittests", executableName = "gfx_unittests.exe", description = "  [GFX unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "gl_unittests", buildCommand = "ui/gl:gl_unittests", executableName = "gl_unittests.exe", description = "  [GL unit  tests]", type = TargetType.UNIT_TESTS, osSupported = {"Win8", "Win10"}));
targets.append(dict(name = "notification_helper_unittests", buildCommand = "chrome/notification_helper:notification_helper_unittests", executableName = "notification_helper_unittests.exe", description = "  [Notification helper unittests]", type = TargetType.UNIT_TESTS, osSupported = {"Win8", "Win10"}));
targets.append(dict(name = "vr_pixeltests", buildCommand = "chrome/browser/vr:vr_pixeltests", executableName = "vr_pixeltests.exe", description = "  [VR pixel tests]"));
targets.append(dict(name = "gl_tests", buildCommand = "gpu:gl_tests", executableName = "gl_tests.exe", description = "  [GL tests]"));
targets.append(dict(name = "audio_unittests", buildCommand = "media:audio_unittests", executableName = "audio_unittests.exe", description = "  [Audio unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "command_buffer_gles2_tests", buildCommand = "gpu:command_buffer_gles2_tests", executableName = "command_buffer_gles2_tests.exe", description = "  [Command_ buffer gles2 tests]"));
targets.append(dict(name = "setup_unittests", buildCommand = "chrome/installer/setup:setup_unittests", executableName = "setup_unittests.exe", description = "  [Setup unit tests.]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "cc_unittests", buildCommand = "cc:cc_unittests", executableName = "cc_unittests.exe", description = "  [CC unit tests]", type = TargetType.UNIT_TESTS));        
targets.append(dict(name = "remoting_unittests", buildCommand = "remoting:remoting_unittests", executableName = "remoting_unittests.exe", description = "  [Remoting unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "base_unittests", buildCommand = "base:base_unittests", executableName = "base_unittests.exe", description = "  [Base unit test suite]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "ntp_render_browsertests", buildCommand = "chrome/test:ntp_render_browsertests", executableName = "ntp_render_browsertests.exe", description = "  [NTP render browser tests]"));
targets.append(dict(name = "viz_unittests", buildCommand = "components/viz:viz_unittests", executableName = "viz_unittests.exe", description = "  [VIZ unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "sync_integration_tests", buildCommand = "chrome/test:sync_integration_tests", executableName = "sync_integration_tests.exe", description = "  [Syncronization integration tests]"));
targets.append(dict(name = "angle_unittests", buildCommand = "third_party/angle/src/tests:angle_unittests", executableName = "angle_unittests.exe", description = "  [Angle unit tests]", type = TargetType.UNIT_TESTS));        
targets.append(dict(name = "headless_browsertests", buildCommand = "headless:headless_browsertests", executableName = "headless_browsertests.exe", description = "  [Headless browser tests]"));        
targets.append(dict(name = "unittests", buildCommand = "v8/test/unittests:unittests", executableName = "unittests.exe", description = "  [Unit tests (Update this description)]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "snapshot_unittests", buildCommand = "ui/snapshot:snapshot_unittests", executableName = "snapshot_unittests.exe", description = "  [Snapshot unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "unit_tests", buildCommand = "chrome/test:unit_tests", executableName = "unit_tests.exe", description = "  [Unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "net_unittests", buildCommand = "net:net_unittests", executableName = "net_unittests.exe", description = "  [Net unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "content_unittests", buildCommand = "content/test:content_unittests", executableName = "content_unittests.exe", description = "  [Content unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "services_unittests", buildCommand = "services:services_unittests", executableName = "services_unittests.exe", description = "  [ Services unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "angle_end2end_tests", buildCommand = "third_party/angle/src/tests:angle_end2end_tests", executableName = "angle_end2end_tests.exe", description = "  [Angle end2end tests]"));
targets.append(dict(name = "gpu_perftests", buildCommand = "gpu:gpu_perftests", executableName = "gpu_perftests.exe", description = "  [performance tests]"));
targets.append(dict(name = "command_buffer_perftests", buildCommand = "gpu:command_buffer_perftests", executableName = "command_buffer_perftests.exe", description = "  [performance tests]"));
targets.append(dict(name = "content_perftests", buildCommand = "content/test:content_perftests", executableName = "content_perftests.exe", description = "  [Content performance tests]"));
targets.append(dict(name = "cc_perftests", buildCommand = "cc:cc_perftests", executableName = "cc_perftests.exe", description = "  [CC performance tests]"));
targets.append(dict(name = "vr_common_perftests", buildCommand = "chrome/browser/vr:vr_common_perftests", executableName = "vr_common_perftests.exe", description = "  [VR common performance tests]", osSupported = {"Win7"}));
targets.append(dict(name = "load_library_perf_tests", buildCommand = "chrome/test:load_library_perf_tests", executableName = "load_library_perf_tests.exe", description = "  [Load library performance tests]"));
targets.append(dict(name = "viz_perftests", buildCommand = "components/viz:viz_perftests", executableName = "viz_perftests.exe", description = "  [VIZ performance tests]"));
targets.append(dict(name = "views_perftests", buildCommand = "ui/views:views_perftests", executableName = "views_perftests.exe", description = "  [Views performance tests]"));
targets.append(dict(name = "ppapi_perftests", buildCommand = "ppapi:ppapi_perftests", executableName = "ppapi_perftests.exe", description = "  [PPApi performance tests]"));    
targets.append(dict(name = "ipc_perftests", buildCommand = "ipc:ipc_perftests", executableName = "ipc_perftests.exe", description = "  [performance tests]"));
targets.append(dict(name = "components_perftests", buildCommand = "components:components_perftests", executableName = "components_perftests.exe", description = "  [Components performance tests]"));
targets.append(dict(name = "media_perftests", buildCommand = "media:media_perftests", executableName = "media_perftests.exe", description = "  [Media performance tests]"));
targets.append(dict(name = "sync_performance_tests", buildCommand = "chrome/test:sync_performance_tests", executableName = "sync_performance_tests.exe", description = "  [Syncronization performance tests]"));    
targets.append(dict(name = "latency_perftests", buildCommand = "ui/latency:latency_perftests", executableName = "latency_perftests.exe", description = "  [performance tests]"));
targets.append(dict(name = "telemetry_perf_unittests", buildCommand = "chrome/test:telemetry_perf_unittests", executableName = "telemetry_perf_unittests.exe", description = "  [Telemetry performance tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "performance_browser_tests", buildCommand = "chrome/test:performance_browser_tests", executableName = "performance_browser_tests.exe", description = "  [performance tests]"));
targets.append(dict(name = "angle_perftests", buildCommand = "chrome/test:angle_perftests", executableName = "angle_perftests.exe", description = "  [performance tests]"));
targets.append(dict(name = "base_perftests", buildCommand = "base:base_perftests", executableName = "base_perftests.exe", description = "  [Base performance tests]"));
targets.append(dict(name = "mojo_perftests", buildCommand = "mojo:mojo_perftests", executableName = "mojo_perftests.exe", description = "  [performance tests]"));
targets.append(dict(name = "net_perftests", buildCommand = "net:net_perftests", executableName = "net_perftests.exe", description = "  [Net performance tests]"));
targets.append(dict(name = "components_browsertests", buildCommand = "components:components_browsertests", executableName = "components_browsertests.exe", description = "  [Components browser tests]"));
targets.append(dict(name = "browser_tests", buildCommand = "chrome/test:browser_tests", executableName = "browser_tests.exe", description = "  [Browser tests]"));
targets.append(dict(name = "interactive_ui_tests", buildCommand = "chrome/test:interactive_ui_tests", executableName = "interactive_ui_tests.exe", description = "  [Interactive UI tests]"));
targets.append(dict(name = "content_browsertests", buildCommand = "content/test:content_browsertests", executableName = "content_browsertests.exe", description = "  [Content browser tests]"));
targets.append(dict(name = "chrome_official_builder_no_unittests", buildCommand = ":chrome_official_builder_no_unittests", executableName = "chrome_official_builder_no_unittests.exe", description = "  [Chrome official builder unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "installer_util_unittests", buildCommand = "chrome/installer/util:installer_util_unittests", executableName = "installer_util_unittests.exe", description = "  [Installer unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "views_interactive_ui_tests", buildCommand = "ui/views:views_interactive_ui_tests", executableName = "views_interactive_ui_tests.exe", description = "  [Views interactive UI tests]"));
targets.append(dict(name = "mini_installer_tests", buildCommand = "chrome/test/mini_installer:mini_installer_tests", executableName = "EXECUTABLE.exe", description = "  [DESCRIPTION]"));
targets.append(dict(name = "mini_installer", buildCommand = "chrome/installer/mini_installer:mini_installer", executableName = "EXECUTABLE.exe", description = "  [DESCRIPTION]"));
targets.append(dict(name = "alternate_version_generator", buildCommand = "chrome/installer/test:alternate_version_generator", executableName = "alternate_version_generator.exe", description = "  [DESCRIPTION]"));
targets.append(dict(name = "audio:tests", buildCommand = "services/audio:tests", executableName = "EXECUTABLE.exe", description = "  [DESCRIPTION]"));
targets.append(dict(name = "device:tests", buildCommand = "services/device:tests", executableName = "EXECUTABLE.exe", description = "  [DESCRIPTION]"));
targets.append(dict(name = "app_shell_unittests", buildCommand = "extensions/shell:app_shell_unittests", executableName = "app_shell_unittests.exe", description = "  [Application shell unit tests]", type = TargetType.UNIT_TESTS))
targets.append(dict(name = "extensions_unittests", buildCommand = "extensions:extensions_unittests", executableName = "extensions_unittests.exe", description = "  [Extensions unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "blink_platform_unittests", buildCommand = "third_party/blink/renderer/platform:blink_platform_unittests", executableName = "blink_platform_unittests.exe", description = "  [Blink platform unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "blink_heap_unittests", buildCommand = "third_party/blink/renderer/platform/heap:blink_heap_unittests", executableName = "blink_heap_unittests.exe", description = "  [Blink heap unit tests]", type = TargetType.UNIT_TESTS));    
targets.append(dict(name = "components_unittests", buildCommand = "components:components_unittests", executableName = "components_unittests.exe", description = "  [Components unit tests]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "extensions_browsertests", buildCommand = "extensions:extensions_browsertests", executableName = "extensions_browsertests.exe", description = "  [Extensions browser tests]"));
targets.append(dict(name = "webrunner_unittests", buildCommand = "webrunner:webrunner_unittests", executableName = "webrunner_unittests.exe", description = "  [DESCRIPTION]", type = TargetType.UNIT_TESTS));
targets.append(dict(name = "views_mus_interactive_ui_tests", buildCommand = "ui/views/mus:views_mus_interactive_ui_tests", executableName = "views_mus_interactive_ui_tests.exe", description = "  [DESCRIPTION]"));
targets.append(dict(name = "views_mus_unittests", buildCommand = "ui/views/mus:views_mus_unittests", executableName = "views_mus_unittests.exe", description = "  [unit tests]", type = TargetType.UNIT_TESTS));


if __name__ == "__main__":
    
    targetsJson = []

    #targetsJson = targetsJson +  [{ "name" : "test1", "descr" : "DECR_1"}];
    #targetsJson = targetsJson +  [{ "name" : "test2", "descr" : "DECR_2"}];
    
    print("[")
    for target in targets:
        print("   ",target, ",")
    print("]")
        
    '''
    jsonFile = "R:\\Projects\\Python\\PythonStudyApplication\\JsonParsing\\Targers_out.json";
    with open(jsonFile, "w") as json_file:
        json.dump(targetsJson, json_file)
    '''

        
        
        
        
        
        
        
        
        
        
        