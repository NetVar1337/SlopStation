#pragma once

// double-buffered sequential reader for dump loops: the read for chunk k+1
// is issued while the caller consumes chunk k, so the wire (or the target)
// stays busy across the consume step (file writes, retries, validation).
// Two caller-owned buffer slots alternate: prefetch(i) into buf[i % 2],
// reap(i) before reusing that slot for chunk i+2. The read function may be
// called from two threads across overlapping calls; every backend
// read_memory is safe for that (console connections serialize commands
// internally, local ReadProcessMemory is thread-safe)

#include "core/runtime/backend.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>

namespace slop::core::memory {

class read_ahead_t {
public:
    using read_fn_t =
        std::function<runtime::io_result_t(uintptr_t, void*, size_t)>;

    explicit read_ahead_t(read_fn_t read) : read_(std::move(read)) {}
    read_ahead_t(const read_ahead_t&) = delete;
    read_ahead_t& operator=(const read_ahead_t&) = delete;

    ~read_ahead_t() {
        for (auto& f : pending_)
            if (f.valid()) f.wait();
    }

    // start the read of [addr, addr+len) into dst; dst must stay valid until
    // the reap() that returns it. Alternates between two slots; a slot is
    // reused only after its previous reap()
    void prefetch(uintptr_t addr, void* dst, size_t len) {
        auto& f = pending_[next_];
        if (f.valid()) f.wait();   // slot discipline guard
        f = std::async(std::launch::async, read_, addr, dst, len);
        next_ = 1 - next_;
    }

    // wait for the oldest in-flight read and return its result
    runtime::io_result_t reap() {
        auto& f = pending_[oldest_];
        if (!f.valid()) return {};
        auto r = f.get();
        f = {};
        oldest_ = 1 - oldest_;
        return r;
    }

private:
    read_fn_t read_;
    std::array<std::future<runtime::io_result_t>, 2> pending_;
    size_t next_ = 0;    // slot the next prefetch writes
    size_t oldest_ = 0;  // slot the next reap reads
};

} // namespace slop::core::memory
