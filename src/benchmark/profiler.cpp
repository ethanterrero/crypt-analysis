#include "profiler.h"
#include <cstring>

#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#elif defined(__aarch64__)
// ARM64: use cycle counter via inline asm
#endif

void Profiler::start() {
    start_cycles = read_tsc();
    start_time = std::chrono::high_resolution_clock::now();
}

void Profiler::stop() {
    end_time = std::chrono::high_resolution_clock::now();
    end_cycles = read_tsc();
}

double Profiler::getSeconds() const {
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    return duration.count() / 1e6;
}

uint64_t Profiler::getTotalCycles() const {
    return end_cycles - start_cycles;
}

double Profiler::getMBPerSecond(std::uintmax_t bytesProcessed) const {
    double sec = getSeconds();
    if (sec <= 0.0) return 0.0;
    return (static_cast<double>(bytesProcessed) / (1024.0 * 1024.0)) / sec;
}

double Profiler::getCyclesPerByte(std::uintmax_t bytesProcessed) const {
    if (bytesProcessed == 0) return 0.0;
    return static_cast<double>(getTotalCycles()) / static_cast<double>(bytesProcessed);
}

uint64_t Profiler::read_tsc() {
#if defined(__x86_64__) || defined(_M_X64)
    return __rdtsc();
#elif defined(__aarch64__)
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    // Fallback: use chrono nanoseconds as proxy
    auto now = std::chrono::high_resolution_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count());
#endif
}
