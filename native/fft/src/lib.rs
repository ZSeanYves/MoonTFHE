use rustfft::num_complex::Complex;
use rustfft::{Fft, FftPlanner};
use std::f64::consts::PI;
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
    half_size: usize,
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
    forward_twist: Vec<Complex<f64>>,
    inverse_twist: Vec<Complex<f64>>,
    fft_scratch_len: usize,
}

pub struct FftScratch {
    polynomial_size: usize,
    digit_capacity: usize,
    output_capacity: usize,
    left: Vec<Complex<f64>>,
    right: Vec<Complex<f64>>,
    fft_scratch: Vec<Complex<f64>>,
    convolution_0: Vec<i64>,
    convolution_1: Vec<i64>,
    convolution_2: Vec<i64>,
    temporary_output: Vec<u32>,
    digit_fourier: Vec<Complex<f64>>,
    half_accumulator: Vec<Complex<f64>>,
}

pub struct FourierBootstrapKey {
    polynomial_size: usize,
    ggsw_count: usize,
    digit_count: usize,
    output_count: usize,
    // [ggsw][digit][output][N/2], using centered Torus32 coefficients.
    spectra: Vec<Complex<f64>>,
}

#[derive(Clone, Copy)]
enum Limb {
    Low,
    High,
}

impl FftPlan {
    fn new(polynomial_size: usize) -> Option<Self> {
        if polynomial_size < 2 || !polynomial_size.is_power_of_two() {
            return None;
        }
        let mut planner = FftPlanner::<f64>::new();
        let forward = planner.plan_fft_forward(polynomial_size);
        let inverse = planner.plan_fft_inverse(polynomial_size);
        let fft_scratch_len = forward
            .get_inplace_scratch_len()
            .max(inverse.get_inplace_scratch_len());
        let forward_twist: Vec<Complex<f64>> = (0..polynomial_size)
            .map(|index| {
                Complex::from_polar(1.0, -PI * index as f64 / polynomial_size as f64)
            })
            .collect();
        let inverse_twist = forward_twist.iter().map(|value| value.conj()).collect();
        Some(Self {
            polynomial_size,
            half_size: polynomial_size / 2,
            forward,
            inverse,
            forward_twist,
            inverse_twist,
            fft_scratch_len,
        })
    }

    fn new_scratch(&self, digit_capacity: usize, output_capacity: usize) -> Option<FftScratch> {
        if digit_capacity == 0 || output_capacity == 0 {
            return None;
        }
        Some(FftScratch {
            polynomial_size: self.polynomial_size,
            digit_capacity,
            output_capacity,
            left: vec![Complex::new(0.0, 0.0); self.polynomial_size],
            right: vec![Complex::new(0.0, 0.0); self.polynomial_size],
            fft_scratch: vec![Complex::new(0.0, 0.0); self.fft_scratch_len],
            convolution_0: vec![0; self.polynomial_size],
            convolution_1: vec![0; self.polynomial_size],
            convolution_2: vec![0; self.polynomial_size],
            temporary_output: vec![0; self.polynomial_size],
            digit_fourier: vec![
                Complex::new(0.0, 0.0);
                digit_capacity * self.half_size
            ],
            half_accumulator: vec![Complex::new(0.0, 0.0); self.half_size],
        })
    }

    fn limb(value: u32, limb: Limb) -> f64 {
        match limb {
            Limb::Low => (value & 0xffff) as f64,
            Limb::High => (value >> 16) as f64,
        }
    }

    fn convolve_limbs(
        &self,
        lhs: &[u32],
        lhs_limb: Limb,
        rhs: &[u32],
        rhs_limb: Limb,
        scratch: &mut FftScratch,
        output_index: usize,
    ) {
        let n = self.polynomial_size;
        for index in 0..n {
            scratch.left[index] = self.forward_twist[index] * Self::limb(lhs[index], lhs_limb);
            scratch.right[index] =
                self.forward_twist[index] * Self::limb(rhs[index], rhs_limb);
        }
        self.forward
            .process_with_scratch(&mut scratch.left, &mut scratch.fft_scratch);
        self.forward
            .process_with_scratch(&mut scratch.right, &mut scratch.fft_scratch);
        for index in 0..n {
            scratch.left[index] *= scratch.right[index];
        }
        self.inverse
            .process_with_scratch(&mut scratch.left, &mut scratch.fft_scratch);
        let scale = n as f64;
        let output = match output_index {
            0 => &mut scratch.convolution_0,
            1 => &mut scratch.convolution_1,
            _ => &mut scratch.convolution_2,
        };
        for index in 0..n {
            output[index] =
                ((scratch.left[index] * self.inverse_twist[index]).re / scale).round() as i64;
        }
    }

    fn multiply(&self, lhs: &[u32], rhs: &[u32], output: &mut [u32], scratch: &mut FftScratch) {
        self.multiply_into_temporary(lhs, rhs, scratch);
        output.copy_from_slice(&scratch.temporary_output);
    }

    fn multiply_into_temporary(&self, lhs: &[u32], rhs: &[u32], scratch: &mut FftScratch) {
        self.convolve_limbs(lhs, Limb::Low, rhs, Limb::Low, scratch, 0);
        self.convolve_limbs(lhs, Limb::Low, rhs, Limb::High, scratch, 1);
        self.convolve_limbs(lhs, Limb::High, rhs, Limb::Low, scratch, 2);
        for index in 0..self.polynomial_size {
            let value = scratch.convolution_0[index] as i128
                + ((scratch.convolution_1[index] as i128
                    + scratch.convolution_2[index] as i128)
                    << 16);
            scratch.temporary_output[index] = value as u32;
        }
    }

    fn polynomial_centered_to_half(
        &self,
        coefficients: &[u32],
        scratch: &mut FftScratch,
        output: &mut [Complex<f64>],
    ) {
        for index in 0..self.polynomial_size {
            scratch.left[index] = self.forward_twist[index] * (coefficients[index] as i32 as f64);
        }
        self.forward
            .process_with_scratch(&mut scratch.left, &mut scratch.fft_scratch);
        output.copy_from_slice(&scratch.left[..self.half_size]);
    }

    fn signed_polynomial_to_half(
        &self,
        coefficients: &[u32],
        scratch: &mut FftScratch,
        output_offset: usize,
    ) {
        for index in 0..self.polynomial_size {
            scratch.left[index] =
                self.forward_twist[index] * (coefficients[index] as i32 as f64);
        }
        self.forward
            .process_with_scratch(&mut scratch.left, &mut scratch.fft_scratch);
        scratch.digit_fourier[output_offset..output_offset + self.half_size]
            .copy_from_slice(&scratch.left[..self.half_size]);
    }

    fn inverse_half_accumulator(&self, scratch: &mut FftScratch, output_index: usize) {
        for frequency in 0..self.half_size {
            let value = scratch.half_accumulator[frequency];
            scratch.left[frequency] = value;
            scratch.left[self.polynomial_size - 1 - frequency] = value.conj();
        }
        self.inverse
            .process_with_scratch(&mut scratch.left, &mut scratch.fft_scratch);
        let scale = self.polynomial_size as f64;
        let output = if output_index == 0 {
            &mut scratch.convolution_0
        } else {
            &mut scratch.convolution_1
        };
        for index in 0..self.polynomial_size {
            output[index] =
                ((scratch.left[index] * self.inverse_twist[index]).re / scale).round() as i64;
        }
    }
}

impl FourierBootstrapKey {
    fn new(plan: &FftPlan, ggsw_count: usize, digit_count: usize, output_count: usize) -> Option<Self> {
        if ggsw_count == 0 || digit_count == 0 || output_count == 0 {
            return None;
        }
        let polynomial_count = ggsw_count
            .checked_mul(digit_count)?
            .checked_mul(output_count)?;
        let spectrum_count = polynomial_count.checked_mul(plan.half_size)?;
        Some(Self {
            polynomial_size: plan.polynomial_size,
            ggsw_count,
            digit_count,
            output_count,
            spectra: vec![Complex::new(0.0, 0.0); spectrum_count],
        })
    }

    fn spectrum_offset(&self, ggsw: usize, digit: usize, output: usize) -> usize {
        ((ggsw * self.digit_count + digit) * self.output_count + output)
            * (self.polynomial_size / 2)
    }

    fn convert(&mut self, plan: &FftPlan, coefficients: &[u32], scratch: &mut FftScratch) -> bool {
        if plan.polynomial_size != self.polynomial_size {
            return false;
        }
        let expected = self.ggsw_count
            * self.digit_count
            * self.output_count
            * self.polynomial_size;
        if coefficients.len() != expected {
            return false;
        }
        let half = plan.half_size;
        for ggsw in 0..self.ggsw_count {
            for digit in 0..self.digit_count {
                for output in 0..self.output_count {
                    let polynomial = (ggsw * self.digit_count * self.output_count
                        + digit * self.output_count
                        + output)
                        * self.polynomial_size;
                    let coefficients = &coefficients[polynomial..polynomial + self.polynomial_size];
                    let spectrum_offset = self.spectrum_offset(ggsw, digit, output);
                    plan.polynomial_centered_to_half(
                        coefficients,
                        scratch,
                        &mut self.spectra[spectrum_offset..spectrum_offset + half],
                    );
                }
            }
        }
        true
    }

    fn external_product(
        &self,
        plan: &FftPlan,
        scratch: &mut FftScratch,
        ggsw_index: usize,
        digits: &[u32],
        output: &mut [u32],
    ) -> bool {
        if plan.polynomial_size != self.polynomial_size
            || ggsw_index >= self.ggsw_count
            || scratch.digit_capacity < self.digit_count
            || scratch.output_capacity < self.output_count
            || digits.len() != self.digit_count * self.polynomial_size
            || output.len() != self.output_count * self.polynomial_size
        {
            return false;
        }
        let half = plan.half_size;
        for digit in 0..self.digit_count {
            let start = digit * self.polynomial_size;
            plan.signed_polynomial_to_half(
                &digits[start..start + self.polynomial_size],
                scratch,
                digit * half,
            );
        }
        for output_index in 0..self.output_count {
            scratch.half_accumulator.fill(Complex::new(0.0, 0.0));
            for digit in 0..self.digit_count {
                let digit_offset = digit * half;
                let key_offset = self.spectrum_offset(ggsw_index, digit, output_index);
                for frequency in 0..half {
                    scratch.half_accumulator[frequency] += scratch.digit_fourier
                        [digit_offset + frequency]
                        * self.spectra[key_offset + frequency];
                }
            }
            plan.inverse_half_accumulator(scratch, 0);
            let output_start = output_index * self.polynomial_size;
            for coefficient in 0..self.polynomial_size {
                output[output_start + coefficient] = scratch.convolution_0[coefficient] as u32;
            }
        }
        true
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
pub unsafe extern "C" fn fft_plan_scratch_bytes(
    plan: *const FftPlan,
    digit_capacity: u32,
    output_capacity: u32,
) -> usize {
    if plan.is_null() || digit_capacity == 0 || output_capacity == 0 {
        return 0;
    }
    let plan = &*plan;
    let digit_values = match (digit_capacity as usize).checked_mul(plan.half_size) {
        Some(value) => value,
        None => return 0,
    };
    let complex_values = match plan
        .polynomial_size
        .checked_mul(2)
        .and_then(|value| value.checked_add(plan.fft_scratch_len))
        .and_then(|value| value.checked_add(digit_values))
        .and_then(|value| value.checked_add(plan.half_size))
    {
        Some(value) => value,
        None => return 0,
    };
    let complex_bytes = match complex_values.checked_mul(std::mem::size_of::<Complex<f64>>()) {
        Some(value) => value,
        None => return 0,
    };
    let bytes_per_coefficient = 3 * std::mem::size_of::<i64>() + std::mem::size_of::<u32>();
    let integer_bytes = match plan.polynomial_size.checked_mul(bytes_per_coefficient) {
        Some(value) => value,
        None => return 0,
    };
    complex_bytes.checked_add(integer_bytes).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn fft_scratch_new(
    plan: *const FftPlan,
    digit_capacity: u32,
    output_capacity: u32,
) -> *mut FftScratch {
    if plan.is_null() {
        return ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        (&*plan).new_scratch(digit_capacity as usize, output_capacity as usize)
    })) {
        Ok(Some(scratch)) => Box::into_raw(Box::new(scratch)),
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn negacyclic_mul_u32(
    plan: *const FftPlan,
    scratch: *mut FftScratch,
    lhs: *const u32,
    lhs_len: usize,
    rhs: *const u32,
    rhs_len: usize,
    output: *mut u32,
    output_len: usize,
) -> i32 {
    if plan.is_null() || scratch.is_null() || lhs.is_null() || rhs.is_null() || output.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let plan = &*plan;
        let scratch = &mut *scratch;
        if lhs_len != plan.polynomial_size
            || rhs_len != plan.polynomial_size
            || output_len != plan.polynomial_size
            || scratch.polynomial_size != plan.polynomial_size
        {
            return FFT_INVALID_SIZE;
        }
        plan.multiply(
            slice::from_raw_parts(lhs, lhs_len),
            slice::from_raw_parts(rhs, rhs_len),
            slice::from_raw_parts_mut(output, output_len),
            scratch,
        );
        FFT_OK
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn batched_glwe_convolution_u32(
    plan: *const FftPlan,
    scratch: *mut FftScratch,
    lhs: *const u32,
    rhs: *const u32,
    term_count: u32,
    output: *mut u32,
) -> i32 {
    if plan.is_null() || scratch.is_null() || lhs.is_null() || rhs.is_null() || output.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let plan = &*plan;
        let scratch = &mut *scratch;
        let terms = term_count as usize;
        if terms == 0 || scratch.polynomial_size != plan.polynomial_size {
            return FFT_INVALID_SIZE;
        }
        let total = match plan.polynomial_size.checked_mul(terms) {
            Some(value) => value,
            None => return FFT_INVALID_SIZE,
        };
        let lhs = slice::from_raw_parts(lhs, total);
        let rhs = slice::from_raw_parts(rhs, total);
        let output = slice::from_raw_parts_mut(output, plan.polynomial_size);
        output.fill(0);
        for term in 0..terms {
            let start = term * plan.polynomial_size;
            plan.multiply_into_temporary(
                &lhs[start..start + plan.polynomial_size],
                &rhs[start..start + plan.polynomial_size],
                scratch,
            );
            for coefficient in 0..plan.polynomial_size {
                output[coefficient] =
                    output[coefficient].wrapping_add(scratch.temporary_output[coefficient]);
            }
        }
        FFT_OK
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn fourier_bsk_new(
    plan: *const FftPlan,
    ggsw_count: u32,
    digit_count: u32,
    output_count: u32,
) -> *mut FourierBootstrapKey {
    if plan.is_null() {
        return ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        FourierBootstrapKey::new(
            &*plan,
            ggsw_count as usize,
            digit_count as usize,
            output_count as usize,
        )
    })) {
        Ok(Some(key)) => Box::into_raw(Box::new(key)),
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn fourier_bsk_convert(
    plan: *const FftPlan,
    key: *mut FourierBootstrapKey,
    scratch: *mut FftScratch,
    coefficients: *const u32,
    coefficient_count: usize,
) -> i32 {
    if plan.is_null() || key.is_null() || scratch.is_null() || coefficients.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if (&mut *key).convert(
            &*plan,
            slice::from_raw_parts(coefficients, coefficient_count),
            &mut *scratch,
        ) {
            FFT_OK
        } else {
            FFT_INVALID_SIZE
        }
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn indexed_ggsw_external_product_u32(
    plan: *const FftPlan,
    key: *const FourierBootstrapKey,
    scratch: *mut FftScratch,
    ggsw_index: u32,
    digits: *const u32,
    digit_count: usize,
    output: *mut u32,
    output_count: usize,
) -> i32 {
    if plan.is_null()
        || key.is_null()
        || scratch.is_null()
        || digits.is_null()
        || output.is_null()
    {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if (&*key).external_product(
            &*plan,
            &mut *scratch,
            ggsw_index as usize,
            slice::from_raw_parts(digits, digit_count),
            slice::from_raw_parts_mut(output, output_count),
        ) {
            FFT_OK
        } else {
            FFT_INVALID_SIZE
        }
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn fourier_bsk_free(key: *mut FourierBootstrapKey) {
    if !key.is_null() {
        drop(Box::from_raw(key));
    }
}

#[no_mangle]
pub unsafe extern "C" fn fft_scratch_free(scratch: *mut FftScratch) {
    if !scratch.is_null() {
        drop(Box::from_raw(scratch));
    }
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

    fn reference_signed(lhs: &[u32], rhs: &[u32]) -> Vec<u32> {
        let n = lhs.len();
        let mut output = vec![0u32; n];
        for i in 0..n {
            for j in 0..n {
                let product = (lhs[i] as i32 as i64) * (rhs[j] as i64);
                let index = i + j;
                if index < n {
                    output[index] = output[index].wrapping_add(product as u32);
                } else {
                    output[index - n] = output[index - n].wrapping_sub(product as u32);
                }
            }
        }
        output
    }

    #[test]
    fn full_width_coefficients_match_reference() {
        for &n in &[8usize, 32, 512, 1024] {
            let lhs: Vec<u32> = (0..n)
                .map(|index| (index as u32).wrapping_mul(0x9E37_79B9) ^ 0x8000_0001)
                .collect();
            let rhs: Vec<u32> = (0..n)
                .map(|index| (index as u32).wrapping_mul(0x85EB_CA6B) ^ 0xFFFF_0001)
                .collect();
            let plan = FftPlan::new(n).unwrap();
            let mut scratch = plan.new_scratch(1, 1).unwrap();
            let mut output = vec![0; n];
            plan.multiply(&lhs, &rhs, &mut output, &mut scratch);
            assert_eq!(output, reference(&lhs, &rhs), "N={n}");
        }
    }

    #[test]
    fn c_abi_round_trip_uses_reusable_scratch() {
        let lhs = [0xFFFF_0001, 0x8000_0000, 7, 0x1234_5678, 1, 2, 3, 4];
        let rhs = [0x0001_FFFF, 3, 0x8000_0001, 11, 5, 6, 7, 8];
        let plan = fft_plan_new(lhs.len() as u32);
        let scratch = unsafe { fft_scratch_new(plan, 1, 1) };
        assert!(!plan.is_null());
        assert!(!scratch.is_null());
        let mut output = vec![0u32; lhs.len()];
        let status = unsafe {
            negacyclic_mul_u32(
                plan,
                scratch,
                lhs.as_ptr(),
                lhs.len(),
                rhs.as_ptr(),
                rhs.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(status, FFT_OK);
        assert_eq!(output, reference(&lhs, &rhs));
        unsafe {
            fft_scratch_free(scratch);
            fft_plan_free(plan);
        }
    }

    #[test]
    fn fourier_bsk_indexed_external_product_matches_reference() {
        let n = 8usize;
        let ggsw_count = 2usize;
        let digit_count = 2usize;
        let output_count = 2usize;
        let plan = FftPlan::new(n).unwrap();
        let mut scratch = plan.new_scratch(digit_count, output_count).unwrap();
        let mut key = FourierBootstrapKey::new(&plan, ggsw_count, digit_count, output_count).unwrap();
        assert_eq!(
            key.spectra.len(),
            ggsw_count * digit_count * output_count * (n / 2)
        );
        let coefficients: Vec<u32> = (0..ggsw_count * digit_count * output_count * n)
            .map(|index| (index as u32).wrapping_mul(0x9E37_79B9) ^ 0xF000_0001)
            .collect();
        assert!(key.convert(&plan, &coefficients, &mut scratch));
        let digits = [1u32, u32::MAX, 2, 0, 3, u32::MAX - 1, 1, 0, 0, 1, u32::MAX, 2, 1, 0, 3, u32::MAX];
        let mut output = vec![0u32; output_count * n];
        assert!(key.external_product(&plan, &mut scratch, 1, &digits, &mut output));
        for output_index in 0..output_count {
            let mut expected = vec![0u32; n];
            for digit in 0..digit_count {
                let polynomial = ((digit_count * output_count) + digit * output_count + output_index) * n;
                let product = reference_signed(
                    &digits[digit * n..(digit + 1) * n],
                    &coefficients[polynomial..polynomial + n],
                );
                for coefficient in 0..n {
                    expected[coefficient] = expected[coefficient].wrapping_add(product[coefficient]);
                }
            }
            assert_eq!(&output[output_index * n..(output_index + 1) * n], expected);
        }
    }

    #[test]
    fn malformed_lengths_are_rejected() {
        let plan = fft_plan_new(8);
        let scratch = unsafe { fft_scratch_new(plan, 2, 2) };
        let values = [0u32; 8];
        let mut output = [0u32; 8];
        assert_eq!(
            unsafe {
                negacyclic_mul_u32(
                    plan,
                    scratch,
                    values.as_ptr(),
                    7,
                    values.as_ptr(),
                    8,
                    output.as_mut_ptr(),
                    8,
                )
            },
            FFT_INVALID_SIZE
        );
        unsafe {
            fft_scratch_free(scratch);
            fft_plan_free(plan);
        }
    }
}
