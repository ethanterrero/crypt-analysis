#pragma once
#include <chrono>
#include <cstdint>

class Profiler {
public:
    void start();
    void stop();

    // The results
    double getSeconds() const;
    uint64_t getTotalCycles() const;
    double getMBPerSecond(std::uintmax_t bytesProcessed) const;
    double getCyclesPerByte(std::uintmax_t bytesProcessed) const;

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_time;
    std::chrono::time_point<std::chrono::high_resolution_clock> end_time;
    
    uint64_t start_cycles;
    uint64_t end_cycles;

    // Internal helper to read CPU TSC (Time Stamp Counter)
    uint64_t read_tsc(); 
};