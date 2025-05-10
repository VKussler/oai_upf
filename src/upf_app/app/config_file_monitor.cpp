#include "config_file_monitor.h"
#include "upf_config_yaml.hpp" // To call reload_upf_info_from_node
#include "spdlog/spdlog.h"
#include "yaml-cpp/yaml.h" // For YAML::LoadFile and YAML::Node

#include <unistd.h> // For read, close, readlink
#include <limits.h> // For PATH_MAX
#include <errno.h>  // For errno
#include <string.h> // For strerror

// UNIQUE CHANGE TO FORCE NEW LAYER HASH 2024-05-10-TRY-AGAIN-A

namespace oai::config {

ConfigFileMonitor::ConfigFileMonitor(
    const std::string& watched_symlink_path,
    oai::config::upf* upf_config_instance)
    : m_watched_symlink_path(watched_symlink_path),
      m_upf_config_instance(upf_config_instance),
      m_stop_flag(false),
      m_inotify_fd(-1),
      m_watch_descriptor(-1) {}

ConfigFileMonitor::~ConfigFileMonitor() {
    stop_monitoring();
}

std::string ConfigFileMonitor::resolve_symlink(const std::string& symlink_path) {
    char buf[PATH_MAX];
    ssize_t len = readlink(symlink_path.c_str(), buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        // If the link is relative, we might need to make it absolute
        // For now, assume it gives a path that can be opened, or it's absolute
        // For robustness, use realpath() if available and suitable.
        char actual_path[PATH_MAX];
        if (realpath(symlink_path.c_str(), actual_path)) {
            spdlog::info("Resolved symlink '{}' to actual path '{}'", symlink_path, actual_path);
            return std::string(actual_path);
        } else {
            spdlog::error("realpath failed for '{}': {}. Using readlink output: {}", symlink_path, strerror(errno), buf);
            return std::string(buf); // Fallback to readlink output, might be relative
        }
    } else {
        spdlog::error("Could not resolve symlink '{}': {}. Watching the link itself.", symlink_path, strerror(errno));
        return symlink_path; // Fallback to watching the symlink itself
    }
}

void ConfigFileMonitor::start_monitoring() {
    if (m_monitor_thread.joinable()) {
        spdlog::warn("Monitoring thread already started.");
        return;
    }

    m_resolved_target_path = resolve_symlink(m_watched_symlink_path);
    if (m_resolved_target_path.empty()) {
        spdlog::error("Failed to resolve configuration file path. Monitoring cannot start.");
        return;
    }

    m_inotify_fd = inotify_init1(IN_NONBLOCK); // Use IN_NONBLOCK to allow stopping
    if (m_inotify_fd < 0) {
        spdlog::error("inotify_init1 failed: {}", strerror(errno));
        return;
    }

    // Watch the symlink itself, not the resolved path
    m_watch_descriptor = inotify_add_watch(m_inotify_fd, m_watched_symlink_path.c_str(), IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE_SELF | IN_ATTRIB);
    if (m_watch_descriptor < 0) {
        spdlog::error("inotify_add_watch failed for '{}': {}. Ensure the path is correct and accessible.", m_watched_symlink_path, strerror(errno));
        close(m_inotify_fd);
        m_inotify_fd = -1;
        return;
    }

    m_stop_flag = false;
    m_monitor_thread = std::thread(&ConfigFileMonitor::monitor_loop, this);
    spdlog::info("Started monitoring configuration file symlink: {}", m_watched_symlink_path);
}

void ConfigFileMonitor::stop_monitoring() {
    m_stop_flag = true;
    if (m_monitor_thread.joinable()) {
        // If the thread is blocked in read(), it won't stop immediately
        // IN_NONBLOCK helps, but a more robust way might involve writing to a pipe
        // to wake up the select/poll on inotify_fd and the pipe_fd.
        // For now, rely on the loop checking m_stop_flag.
        if (m_inotify_fd >=0 && m_watch_descriptor >=0) {
             inotify_rm_watch(m_inotify_fd, m_watch_descriptor);
             m_watch_descriptor = -1;
        }
        if (m_inotify_fd >=0) {
            close(m_inotify_fd);
            m_inotify_fd = -1;
        }
        m_monitor_thread.join();
        spdlog::info("Stopped monitoring configuration file.");
    }
}

void ConfigFileMonitor::monitor_loop() {
    const size_t EVENT_BUF_LEN = (10 * (sizeof(struct inotify_event) + NAME_MAX + 1));
    char buffer[EVENT_BUF_LEN];

    while (!m_stop_flag) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(m_inotify_fd, &rfds);
        struct timeval tv;
        tv.tv_sec = 1; // Timeout for select to check m_stop_flag periodically
        tv.tv_usec = 0;

        int retval = select(m_inotify_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval < 0) {
            if (errno == EINTR) continue; // Interrupted by signal, continue
            spdlog::error("select() error in monitor_loop: {}", strerror(errno));
            break; 
        } else if (retval > 0 && FD_ISSET(m_inotify_fd, &rfds)) {
            ssize_t len = read(m_inotify_fd, buffer, EVENT_BUF_LEN);
            if (len < 0) {
                if (errno == EINTR) continue;
                spdlog::error("read from inotify_fd failed: {}", strerror(errno));
                break;
            }

            ssize_t i = 0;
            while (i < len) {
                struct inotify_event* event = (struct inotify_event*)&buffer[i];
                
                // Handle any event that might indicate a config change
                if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_ATTRIB)) {
                    spdlog::info("Configuration change detected. Event mask: 0x{:x}", event->mask);
                    
                    // Resolve the symlink again to get the new target
                    std::string new_resolved_path = resolve_symlink(m_watched_symlink_path);
                    if (new_resolved_path != m_resolved_target_path) {
                        spdlog::info("Symlink target changed from '{}' to '{}'", m_resolved_target_path, new_resolved_path);
                        m_resolved_target_path = new_resolved_path;
                    }
                    
                    try {
                        spdlog::info("Attempting to reload configuration from '{}'", m_resolved_target_path);
                        YAML::Node config_root = YAML::LoadFile(m_resolved_target_path);
                        if (config_root["upf"] && config_root["upf"][UPF_CONFIG_UPF_INFO]) {
                            if (m_upf_config_instance) {
                                bool success = m_upf_config_instance->reload_upf_info_from_node(config_root["upf"][UPF_CONFIG_UPF_INFO]);
                                if (success) {
                                    spdlog::info("Configuration reloaded successfully.");
                                } else {
                                    spdlog::error("Failed to reload configuration.");
                                }
                            } else {
                                spdlog::error("UPF config instance is null.");
                            }
                        } else {
                            spdlog::warn("'upf.upf_info' section not found in configuration file '{}'.", m_resolved_target_path);
                        }
                    } catch (const YAML::Exception& e) {
                        spdlog::error("YAML parsing error: {}", e.what());
                    } catch (const std::exception& e) {
                        spdlog::error("Exception while reloading configuration: {}", e.what());
                    }
                }
                
                if (event->mask & (IN_MOVED_FROM | IN_DELETE_SELF)) {
                    spdlog::warn("Watched symlink '{}' was moved or deleted.", m_watched_symlink_path);
                    m_watch_descriptor = -1;
                    break;
                }

                i += sizeof(struct inotify_event) + event->len;
            }
        }
        
        // Handle re-initialization if needed
        if (m_watch_descriptor == -1 && !m_stop_flag) {
            spdlog::info("Re-initializing watch on symlink '{}'", m_watched_symlink_path);
            if (m_inotify_fd >= 0) {
                close(m_inotify_fd);
            }
            
            m_inotify_fd = inotify_init1(IN_NONBLOCK);
            if (m_inotify_fd < 0) {
                spdlog::error("Failed to re-initialize inotify: {}", strerror(errno));
                break;
            }
            
            // Always watch the symlink path, not the resolved path
            m_watch_descriptor = inotify_add_watch(m_inotify_fd, m_watched_symlink_path.c_str(), 
                IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE_SELF | IN_ATTRIB);
            if (m_watch_descriptor < 0) {
                spdlog::error("Failed to re-add watch: {}", strerror(errno));
                break;
            }
            
            // Update the resolved path after re-initialization
            m_resolved_target_path = resolve_symlink(m_watched_symlink_path);
            spdlog::info("Successfully re-initialized watch on symlink '{}' (resolved to '{}')", 
                m_watched_symlink_path, m_resolved_target_path);
        }
    }
    
    spdlog::info("Exiting monitor_loop for {}", m_watched_symlink_path);
}

} // namespace oai::config 