#pragma once
#include <cstring>
#include <fstream>
#include <iomanip>
#include <string>
#include <mutex>

class Logger {
public:
    // Initialize the log file (optional: specify filename)
    static void Init(const std::string& filename = "log.txt") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ofs_.is_open()) {
            ofs_.open(filename, std::ios::app);
        }
    }

    // Log a message to the file
    static void Log(const std::string& message) {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%d-%m-%Y %H-%M-%S");
        std::string time_str = oss.str();

        std::string log_message = time_str + " " + message;

        std::lock_guard<std::mutex> lock(mutex_);
        if (ofs_.is_open()) {
            ofs_ << log_message << std::endl;
        }
    }

    // Optional: Close file on shutdown
    static void Close() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ofs_.is_open()) {
            ofs_.close();
        }
    }

private:
    static std::ofstream ofs_;
    static std::mutex mutex_;
};

// Define static members in the header (for header-only)
inline std::ofstream Logger::ofs_;
inline std::mutex Logger::mutex_;

