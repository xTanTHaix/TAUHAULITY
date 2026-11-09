//! Monotonic hardware counter used to timestamp pillar events.
//!
//! Windows exposes QueryPerformanceCounter, a monotonic counter backed by the
//! TSC or HPET depending on the hardware abstraction layer; Linux exposes
//! clock_gettime(CLOCK_MONOTONIC), which the kernel guarantees never steps
//! backwards across NTP corrections. Both are preferable to wall clock time
//! because a dossier stamped with an NTP-corrected clock can appear to record
//! events out of order.
//!
//! Every platform path has a software fallback so the counter never fails: a
//! counter that returns a constant on an exotic target would silently break the
//! seqlock timeouts that consume it, which is worse than falling back to
//! `std::time::Instant`, which is at least monotonic within the process.

use std::time::Instant;

/// Lazily initialised process start reference used by the software fallback.
fn software_counter() -> u64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// Return a monotonically non-decreasing counter value.
///
/// The unit is platform specific (QPC ticks on Windows, nanoseconds on Linux),
/// so callers must only ever compare two values from the same process, never
/// interpret an absolute value or mix values across processes.
#[cfg(windows)]
pub fn counter() -> u64 {
    // QueryPerformanceCounter is the only Windows API that is guaranteed
    // monotonic and synchronised across processors; GetTickCount has a coarse
    // 10-16 ms resolution and wraps every 49 days.
    #[link(name = "kernel32")]
    extern "system" {
        fn QueryPerformanceCounter(counter: *mut i64) -> i32;
    }

    let mut value: i64 = 0;
    let ok = unsafe { QueryPerformanceCounter(&mut value) };
    if ok != 0 && value >= 0 {
        value as u64
    } else {
        software_counter()
    }
}

/// Return a monotonically non-decreasing counter value in nanoseconds.
#[cfg(not(windows))]
pub fn counter() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // clock_gettime is resolved from the C library that std already links.
        // The struct timespec layout for time_t/long is 16 bytes on every
        // Linux ABI the project targets (x86_64, aarch64); a 32 bit target
        // would need a different struct, so the software fallback stays in
        // place as the safety net.
        #[repr(C)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }
        extern "C" {
            fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
        }
        const CLOCK_MONOTONIC: i32 = 1;
        let mut stamp = Timespec { tv_sec: 0, tv_nsec: 0 };
        let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut stamp) };
        if rc == 0 && stamp.tv_sec >= 0 && (0..1_000_000_000).contains(&stamp.tv_nsec) {
            return (stamp.tv_sec as u64).saturating_mul(1_000_000_000) + stamp.tv_nsec as u64;
        }
        software_counter()
    }
    #[cfg(not(target_os = "linux"))]
    {
        software_counter()
    }
}

#[cfg(test)]
mod tests {
    use super::counter;

    #[test]
    fn counter_never_goes_backwards() {
        let mut previous = counter();
        for _ in 0..10_000 {
            let current = counter();
            assert!(current >= previous, "counter regressed from {previous} to {current}");
            previous = current;
        }
    }

    #[test]
    fn counter_advances_across_sleeps() {
        let before = counter();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let after = counter();
        assert!(after > before, "counter did not advance: {before} -> {after}");
    }
}
