#include "profiler.h"

// Platform-specific cycle counter headers
#if defined(__x86_64__) || defined(__i386__)
    #include <x86intrin.h>
#endif

uint64_t Profiler::read_tsc() {
#if defined(__x86_64__) || defined(__i386__)
    return __rdtsc();
#elif defined(__aarch64__)
    // Apple Silicon: cntvct_el0 is a fixed-frequency counter, not true CPU cycles.
    // It ticks at ~24 MHz regardless of core clock speed.
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    // Fallback: nanosecond timestamp as a cycle proxy
    return static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()
    );
#endif
}

void Profiler::start() {
    start_cycles = read_tsc();
    start_time = std::chrono::high_resolution_clock::now();
}

void Profiler::stop() {
    end_time = std::chrono::high_resolution_clock::now();
    end_cycles = read_tsc();
}

double Profiler::getSeconds() const {
    std::chrono::duration<double> elapsed = end_time - start_time;
    return elapsed.count();
}

uint64_t Profiler::getTotalCycles() const {
    return end_cycles - start_cycles;
}

double Profiler::getMBPerSecond(std::uintmax_t bytesProcessed) const {
    double seconds = getSeconds();
    if (seconds == 0.0) return 0.0;
    return (static_cast<double>(bytesProcessed) / (1024.0 * 1024.0)) / seconds;
}

double Profiler::getCyclesPerByte(std::uintmax_t bytesProcessed) const {
    if (bytesProcessed == 0) return 0.0;
    return static_cast<double>(getTotalCycles()) / static_cast<double>(bytesProcessed);
}
