use rustfft::num_complex::Complex;
use rustfft::{Fft, FftPlanner};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Arc;

const FFT_OK: i32 = 0;
const FFT_NULL_POINTER: i32 = 1;
const FFT_INVALID_SIZE: i32 = 2;
const FFT_PANIC: i32 = 3;

pub struct FftPlan {
    polynomial_size: usize,
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
}

impl FftPlan {
    fn new(polynomial_size: usize) -> Option<Self> {
        if polynomial_size == 0 || !polynomial_size.is_power_of_two() {
            return None;
        }
        let mut planner = FftPlanner::<f64>::new();
        let fft_size = polynomial_size.checked_mul(2)?;
        Some(Self {
            polynomial_size,
            forward: planner.plan_fft_forward(fft_size),
            inverse: planner.plan_fft_inverse(fft_size),
        })
    }

    fn convolve_negacyclic(&self, lhs: &[f64], rhs: &[f64]) -> Vec<i64> {
        let n = self.polynomial_size;
        let fft_size = 2 * n;
        let mut left = vec![Complex::new(0.0, 0.0); fft_size];
        let mut right = vec![Complex::new(0.0, 0.0); fft_size];
        for index in 0..n {
            left[index].re = lhs[index];
            right[index].re = rhs[index];
        }
        self.forward.process(&mut left);
        self.forward.process(&mut right);
        for index in 0..fft_size {
            left[index] *= right[index];
        }
        self.inverse.process(&mut left);
        let scale = fft_size as f64;
        (0..n)
            .map(|index| {
                let low = (left[index].re / scale).round() as i64;
                let high = (left[index + n].re / scale).round() as i64;
                low - high
            })
            .collect()
    }

    fn multiply(&self, lhs: &[u32], rhs: &[u32], output: &mut [u32]) {
        let n = self.polynomial_size;
        let mut lhs_low = vec![0.0; n];
        let mut lhs_high = vec![0.0; n];
        let mut rhs_low = vec![0.0; n];
        let mut rhs_high = vec![0.0; n];
        for index in 0..n {
            lhs_low[index] = (lhs[index] & 0xffff) as f64;
            lhs_high[index] = (lhs[index] >> 16) as f64;
            rhs_low[index] = (rhs[index] & 0xffff) as f64;
            rhs_high[index] = (rhs[index] >> 16) as f64;
        }

        let low_low = self.convolve_negacyclic(&lhs_low, &rhs_low);
        let low_high = self.convolve_negacyclic(&lhs_low, &rhs_high);
        let high_low = self.convolve_negacyclic(&lhs_high, &rhs_low);

        for index in 0..n {
            let value = (low_low[index] as i128)
                + (((low_high[index] as i128) + (high_low[index] as i128)) << 16);
            output[index] = value as u32;
        }
    }
}

#[no_mangle]
pub extern "C" fn fft_plan_new(polynomial_size: u32) -> *mut FftPlan {
    match catch_unwind(|| FftPlan::new(polynomial_size as usize)) {
        Ok(Some(plan)) => Box::into_raw(Box::new(plan)),
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn fft_plan_scratch_bytes(plan: *const FftPlan) -> usize {
    if plan.is_null() {
        return 0;
    }
    // Reserved caller-owned workspace for ABI stability. The current RustFFT
    // adapter keeps temporary Complex buffers inside the guarded call.
    (*plan).polynomial_size * 2 * std::mem::size_of::<Complex<f64>>()
}

#[no_mangle]
pub unsafe extern "C" fn negacyclic_mul_u32(
    plan: *const FftPlan,
    lhs: *const u32,
    rhs: *const u32,
    output: *mut u32,
    scratch: *mut u8,
) -> i32 {
    if plan.is_null() || lhs.is_null() || rhs.is_null() || output.is_null() {
        return FFT_NULL_POINTER;
    }
    if scratch.is_null() {
        return FFT_NULL_POINTER;
    }
    let operation = catch_unwind(AssertUnwindSafe(|| {
        let plan = &*plan;
        let n = plan.polynomial_size;
        if n == 0 {
            return FFT_INVALID_SIZE;
        }
        let lhs = slice::from_raw_parts(lhs, n);
        let rhs = slice::from_raw_parts(rhs, n);
        let output = slice::from_raw_parts_mut(output, n);
        plan.multiply(lhs, rhs, output);
        FFT_OK
    }));
    operation.unwrap_or(FFT_PANIC)
}

/// Accumulate a batch of negacyclic products. The flattened inputs contain
/// `term_count` consecutive polynomials of the plan size.
#[no_mangle]
pub unsafe extern "C" fn external_product_accumulate_u32(
    plan: *const FftPlan,
    lhs: *const u32,
    rhs: *const u32,
    term_count: u32,
    output: *mut u32,
    scratch: *mut u8,
) -> i32 {
    if plan.is_null()
        || lhs.is_null()
        || rhs.is_null()
        || output.is_null()
        || scratch.is_null()
    {
        return FFT_NULL_POINTER;
    }
    let operation = catch_unwind(AssertUnwindSafe(|| {
        let plan = &*plan;
        let n = plan.polynomial_size;
        let terms = term_count as usize;
        if n == 0 || terms == 0 {
            return FFT_INVALID_SIZE;
        }
        let total = match n.checked_mul(terms) {
            Some(value) => value,
            None => return FFT_INVALID_SIZE,
        };
        let lhs = slice::from_raw_parts(lhs, total);
        let rhs = slice::from_raw_parts(rhs, total);
        let output = slice::from_raw_parts_mut(output, n);
        output.fill(0);
        let mut term = vec![0u32; n];
        for index in 0..terms {
            let start = index * n;
            plan.multiply(
                &lhs[start..start + n],
                &rhs[start..start + n],
                &mut term,
            );
            for coefficient in 0..n {
                output[coefficient] = output[coefficient].wrapping_add(term[coefficient]);
            }
        }
        FFT_OK
    }));
    operation.unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn fft_plan_free(plan: *mut FftPlan) {
    if !plan.is_null() {
        drop(Box::from_raw(plan));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(lhs: &[u32], rhs: &[u32]) -> Vec<u32> {
        let n = lhs.len();
        let mut output = vec![0u32; n];
        for i in 0..n {
            for j in 0..n {
                let product = lhs[i].wrapping_mul(rhs[j]);
                let index = i + j;
                if index < n {
                    output[index] = output[index].wrapping_add(product);
                } else {
                    output[index - n] = output[index - n].wrapping_sub(product);
                }
            }
        }
        output
    }

    #[test]
    fn full_width_coefficients_match_reference() {
        let lhs = [0, 1, u32::MAX, 0x8000_0000, 0x1234_5678, 7, 9, 11];
        let rhs = [u32::MAX, 3, 5, 0x8000_0001, 13, 17, 19, 23];
        let plan = FftPlan::new(lhs.len()).unwrap();
        let mut output = vec![0; lhs.len()];
        plan.multiply(&lhs, &rhs, &mut output);
        assert_eq!(output, reference(&lhs, &rhs));
    }

    #[test]
    fn c_abi_round_trip_uses_explicit_scratch() {
        let lhs = [0xFFFF_0001, 0x8000_0000, 7, 0x1234_5678];
        let rhs = [0x0001_FFFF, 3, 0x8000_0001, 11];
        let plan = fft_plan_new(lhs.len() as u32);
        assert!(!plan.is_null());
        let scratch_len = unsafe { fft_plan_scratch_bytes(plan) };
        assert!(scratch_len > 0);
        let mut scratch = vec![0u8; scratch_len];
        let mut output = vec![0u32; lhs.len()];
        let status = unsafe {
            negacyclic_mul_u32(
                plan,
                lhs.as_ptr(),
                rhs.as_ptr(),
                output.as_mut_ptr(),
                scratch.as_mut_ptr(),
            )
        };
        assert_eq!(status, FFT_OK);
        assert_eq!(output, reference(&lhs, &rhs));
        unsafe { fft_plan_free(plan) };
    }

    #[test]
    fn invalid_plan_size_is_rejected() {
        assert!(FftPlan::new(0).is_none());
        assert!(FftPlan::new(6).is_none());
    }

    #[test]
    fn batched_external_product_matches_reference_sum() {
        let n = 8;
        let lhs = [
            1, 2, 3, 4, 5, 6, 7, 8, u32::MAX, 3, 5, 7, 11, 13, 17, 19,
        ];
        let rhs = [
            8, 7, 6, 5, 4, 3, 2, 1, 0x8000_0000, 2, 4, 6, 8, 10, 12, 14,
        ];
        let expected_left = reference(&lhs[..n], &rhs[..n]);
        let expected_right = reference(&lhs[n..], &rhs[n..]);
        let expected: Vec<u32> = expected_left
            .iter()
            .zip(expected_right.iter())
            .map(|(left, right)| left.wrapping_add(*right))
            .collect();
        let plan = fft_plan_new(n as u32);
        let scratch_len = unsafe { fft_plan_scratch_bytes(plan) };
        let mut scratch = vec![0u8; scratch_len];
        let mut output = vec![0u32; n];
        let status = unsafe {
            external_product_accumulate_u32(
                plan,
                lhs.as_ptr(),
                rhs.as_ptr(),
                2,
                output.as_mut_ptr(),
                scratch.as_mut_ptr(),
            )
        };
        assert_eq!(status, FFT_OK);
        assert_eq!(output, expected);
        unsafe { fft_plan_free(plan) };
    }
}
