#include "behavior_detector.h"

#include "event_writer.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>

namespace {

int countNumericProcDirs() {
    DIR* d = opendir("/proc");
    if (!d) {
        return 0;
    }
    int c = 0;
    while (dirent* ent = readdir(d)) {
        std::string n(ent->d_name);
        bool digit = !n.empty();
        for (char ch : n) {
            if (ch < '0' || ch > '9') {
                digit = false;
                break;
            }
        }
        if (digit) {
            c++;
        }
    }
    closedir(d);
    return c;
}

long fileSize(const char* path) {
    struct stat st {};
    if (stat(path, &st) != 0) {
        return -1;
    }
    return static_cast<long>(st.st_size);
}

long fileMtime(const char* path) {
    struct stat st {};
    if (stat(path, &st) != 0) {
        return -1;
    }
    return static_cast<long>(st.st_mtime);
}

float loadAvg1m() {
    std::ifstream f("/proc/loadavg");
    float v = 0.0f;
    if (!(f >> v)) {
        return -1.0f;
    }
    return v;
}

bool memUsagePercent(double* out_pct) {
    std::ifstream f("/proc/meminfo");
    if (!f) {
        return false;
    }
    std::string key;
    long value = 0;
    std::string unit;
    long total_kb = -1;
    long avail_kb = -1;
    while (f >> key >> value >> unit) {
        if (key == "MemTotal:") {
            total_kb = value;
        } else if (key == "MemAvailable:") {
            avail_kb = value;
        }
        if (total_kb > 0 && avail_kb >= 0) {
            break;
        }
    }
    if (total_kb <= 0 || avail_kb < 0) {
        return false;
    }
    *out_pct = (1.0 - static_cast<double>(avail_kb) / static_cast<double>(total_kb)) * 100.0;
    return true;
}

const char* envOr(const char* k, const char* d) {
    const char* v = std::getenv(k);
    return v && v[0] ? v : d;
}

} // namespace

BehaviorDetector::BehaviorDetector(EventWriter* writer)
    : writer_(writer), last_proc_count_(-1), last_auth_size_(-1), last_watch_mtime_(-1), last_load1_(-1.0f) {}

void BehaviorDetector::checkSpike() {
    int n = countNumericProcDirs();
    if (last_proc_count_ < 0) {
        last_proc_count_ = n;
        return;
    }
    int delta = n - last_proc_count_;
    int threshold = std::atoi(envOr("HIDRS_SPIKE_DELTA", "40"));
    if (delta >= threshold) {
        std::ostringstream o;
        o << "{\"type\":\"PROCESS_SPIKE\",\"source\":\"os_engine\",\"severity\":\"CRITICAL\","
          << "\"detail\":\"Process count jump delta=" << delta << " total=" << n << "\","
          << "\"pid\":0,\"force_alert\":true}";
        writer_->writeLine(o.str());
    }
    last_proc_count_ = n;
}

void BehaviorDetector::checkAuthLog() {
    const char* path = envOr("HIDRS_AUTH_SIM_LOG", "/tmp/hidrs_sim_auth.log");
    long sz = fileSize(path);
    if (sz < 0) {
        return;
    }
    if (last_auth_size_ < 0) {
        last_auth_size_ = sz;
        return;
    }
    long growth = sz - last_auth_size_;
    if (growth > 200) {
        std::ostringstream o;
        o << "{\"type\":\"LOGIN_ANOMALY\",\"source\":\"os_engine\",\"severity\":\"HIGH\","
          << "\"detail\":\"Rapid growth in simulated auth log bytes=" << growth << "\","
          << "\"auth_log\":\"" << path << "\",\"force_alert\":true}";
        writer_->writeLine(o.str());
    }
    last_auth_size_ = sz;
}

void BehaviorDetector::checkWatchFile() {
    const char* path = envOr("HIDRS_WATCH_FILE", "/tmp/hidrs_watch_file.txt");
    long mt = fileMtime(path);
    if (mt < 0) {
        return;
    }
    if (last_watch_mtime_ < 0) {
        last_watch_mtime_ = mt;
        return;
    }
    if (mt != last_watch_mtime_) {
        std::ostringstream o;
        o << "{\"type\":\"FILE_TAMPER\",\"source\":\"os_engine\",\"severity\":\"HIGH\","
          << "\"detail\":\"Canary mtime changed\",\"path\":\"" << path
          << "\",\"force_alert\":true}";
        writer_->writeLine(o.str());
    }
    last_watch_mtime_ = mt;
}

void BehaviorDetector::checkResourcePressure() {
    const int min_delta = std::atoi(envOr("HIDRS_RESOURCE_MIN_DELTA", "2"));
    const int load_threshold = std::atoi(envOr("HIDRS_LOADAVG_HIGH", "4"));
    const int mem_threshold = std::atoi(envOr("HIDRS_MEM_HIGH_PCT", "85"));
    const int emit_interval = std::atoi(envOr("HIDRS_RESOURCE_EMIT_SEC", "15"));

    static int tick = 0;
    tick += 1;
    if (tick < emit_interval) {
        return;
    }
    tick = 0;

    float l1 = loadAvg1m();
    double mem_pct = 0.0;
    bool mem_ok = memUsagePercent(&mem_pct);
    if (l1 < 0.0f || !mem_ok) {
        return;
    }
    bool load_jump = (last_load1_ >= 0.0f) && ((l1 - last_load1_) >= static_cast<float>(min_delta));
    bool high_load = static_cast<int>(l1) >= load_threshold;
    bool high_mem = static_cast<int>(mem_pct) >= mem_threshold;
    if (high_load || high_mem || load_jump) {
        std::ostringstream o;
        o << "{\"type\":\"RESOURCE_PRESSURE\",\"source\":\"os_engine\",\"severity\":\"HIGH\","
          << "\"detail\":\"Resource pressure load1=" << std::fixed << std::setprecision(2) << l1
          << " mem_used_pct=" << std::setprecision(1) << mem_pct << "\","
          << "\"load1\":" << std::setprecision(2) << l1 << ",\"mem_used_pct\":" << std::setprecision(1)
          << mem_pct << ",\"force_alert\":true}";
        writer_->writeLine(o.str());
    }
    last_load1_ = l1;
}

void BehaviorDetector::runLoop(std::atomic<bool>* stop_flag) {
    using namespace std::chrono_literals;
    while (!stop_flag->load()) {
        checkSpike();
        checkAuthLog();
        checkWatchFile();
        checkResourcePressure();
        std::this_thread::sleep_for(700ms);
    }
}
