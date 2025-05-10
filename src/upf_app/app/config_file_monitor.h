#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <sys/inotify.h> // Required for inotify

namespace oai::config {

class upf; // Forward declaration

class ConfigFileMonitor {
public:
    // Constructor:
    // - watched_symlink_path: Path to the config.yaml symlink.
    // - upf_config_instance: Pointer to the oai::config::upf instance to notify.
    ConfigFileMonitor(const std::string& watched_symlink_path, oai::config::upf* upf_config_instance);
    ~ConfigFileMonitor();

    void start_monitoring();
    void stop_monitoring();

private:
    void monitor_loop();
    std::string resolve_symlink(const std::string& symlink_path);

    std::string m_watched_symlink_path;
    std::string m_resolved_target_path; // Actual file being watched
    oai::config::upf* m_upf_config_instance; // Pointer to the upf config object

    std::thread m_monitor_thread;
    std::atomic<bool> m_stop_flag;

    int m_inotify_fd;
    int m_watch_descriptor;
};

} // namespace oai::config 