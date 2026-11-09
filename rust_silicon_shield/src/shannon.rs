//! Shannon entropy in bits per byte, identical to the Python LUT implementation.
//!
//! `tauhaulity.core.entropy.shannon_entropy` evaluates
//! H = log2(n) - sum(c_i * log2(c_i)) / n using a precomputed table over the
//! only 256 possible byte counts. The native path must agree with it to within
//! a floating point ulp, because the dossier prints both values and a
//! difference of more than 1e-9 would let the same payload be judged benign by
//! one backend and suspicious by the other. `f64::log2` and `math.log2` are
//! both correctly rounded single-result libm calls on every supported target,
//! so the two implementations agree bit for bit in practice.
//!
//! Negative intermediate results are clamped to zero: floating point rounding
//! can push a perfectly uniform single byte payload (H = 0) one ulp below zero,
//! and an entropy gate that reports a negative density is worse than useless.

/// Return the Shannon entropy of a byte slice in bits per byte.
///
/// An empty slice yields exactly zero, matching the Python reference that
/// short circuits before doing any counting.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for byte in data {
        counts[usize::from(*byte)] += 1;
    }
    let total = data.len() as f64;
    let mut accumulator = 0.0f64;
    for count in counts {
        if count != 0 {
            let value = count as f64;
            accumulator += value * value.log2();
        }
    }
    let measured = total.log2() - accumulator / total;
    if measured < 0.0 {
        0.0
    } else {
        measured
    }
}

#[cfg(test)]
mod tests {
    use super::entropy;

    const TOLERANCE: f64 = 1e-12;

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() <= TOLERANCE,
            "expected {expected}, measured {actual}"
        );
    }

    #[test]
    fn empty_and_uniform_inputs_are_zero() {
        assert_eq!(entropy(b""), 0.0);
        assert_eq!(entropy(b"a"), 0.0);
        assert_eq!(entropy(b"aaaaaaa"), 0.0);
    }

    #[test]
    fn uniform_byte_distribution_reaches_eight_bits() {
        let payload: Vec<u8> = (0u8..=255).collect();
        assert_close(entropy(&payload), 8.0);
    }

    #[test]
    fn python_reference_values_match() {
        assert_close(entropy(b"abc"), 1.584_962_500_721_156);
        assert_close(entropy(b"ab"), 1.0);
        assert_close(entropy(b"abcd"), 2.0);
        assert_close(entropy(b"hello world"), 2.845_350_936_622_436_3);
    }

    #[test]
    fn entropy_is_bounded_and_monotonic_in_alphabet_size() {
        let mut previous = 0.0f64;
        for alphabet in 1u16..=256 {
            let payload: Vec<u8> = (0..alphabet).map(|value| value as u8).collect();
            let measured = entropy(&payload);
            assert!((0.0..=8.0).contains(&measured));
            assert!(measured + TOLERANCE >= previous);
            previous = measured;
        }
    }

    #[test]
    fn all_byte_values_are_handled() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let measured = entropy(&payload);
        assert_close(measured, 8.0);
    }
}
