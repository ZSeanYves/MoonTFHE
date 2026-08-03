use rustfft::num_complex::Complex;
use rustfft::{Fft, FftPlanner};
use std::f64::consts::PI;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "allocation-counter")]
mod allocation_counter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub struct CountingAllocator;

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if ENABLED.load(Ordering::Relaxed) {
                ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            }
            System.alloc(layout)
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            System.dealloc(pointer, layout)
        }

        unsafe fn realloc(
            &self,
            pointer: *mut u8,
            layout: Layout,
            new_size: usize,
        ) -> *mut u8 {
            if ENABLED.load(Ordering::Relaxed) {
                ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            }
            System.realloc(pointer, layout, new_size)
        }
    }

    pub fn start() {
        ALLOCATIONS.store(0, Ordering::SeqCst);
        ENABLED.store(true, Ordering::SeqCst);
    }

    pub fn stop() -> usize {
        ENABLED.store(false, Ordering::SeqCst);
        ALLOCATIONS.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "allocation-counter")]
#[global_allocator]
static ALLOCATOR: allocation_counter::CountingAllocator =
    allocation_counter::CountingAllocator;

const FFT_OK: i32 = 0;
const FFT_NULL_POINTER: i32 = 1;
const FFT_INVALID_SIZE: i32 = 2;
const FFT_PANIC: i32 = 3;
const FFT_BUSY: i32 = 4;

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

pub struct NativePbsContext {
    plan: FftPlan,
    scratch: FftScratch,
    key: FourierBootstrapKey,
    ksk: Vec<u32>,
    input_dimension: usize,
    glwe_dimension: usize,
    pbs_base_log: usize,
    pbs_level: usize,
    ksk_input_dimension: usize,
    ksk_output_dimension: usize,
    ksk_base_log: usize,
    ksk_level: usize,
    order: u32,
    state_a: Vec<u32>,
    state_b: Vec<u32>,
    rotated: Vec<u32>,
    difference: Vec<u32>,
    digits: Vec<u32>,
    decomposition_digits: Vec<i32>,
    extracted: Vec<u32>,
    ksk_result: Vec<u32>,
    switched_input: Vec<u32>,
    initialized_controls: Vec<bool>,
    last_key_switch_ns: u64,
    last_external_product_ns: u64,
    last_external_product_count: u64,
    last_blind_rotation_ns: u64,
    last_sample_extraction_ns: u64,
    busy: AtomicBool,
}

struct BusyGuard(*const AtomicBool);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        // The guard never outlives its context and only touches the atomic flag.
        unsafe { (&*self.0).store(false, Ordering::Release) };
    }
}

#[derive(Clone, Copy)]
enum Limb {
    Low,
    High,
}

impl FftScratch {
    fn reset(&mut self) {
        self.left.fill(Complex::new(0.0, 0.0));
        self.right.fill(Complex::new(0.0, 0.0));
        self.fft_scratch.fill(Complex::new(0.0, 0.0));
        self.convolution_0.fill(0);
        self.convolution_1.fill(0);
        self.convolution_2.fill(0);
        self.temporary_output.fill(0);
        self.digit_fourier.fill(Complex::new(0.0, 0.0));
        self.half_accumulator.fill(Complex::new(0.0, 0.0));
    }

    fn resident_bytes(&self) -> usize {
        (self.left.len()
            + self.right.len()
            + self.fft_scratch.len()
            + self.digit_fourier.len()
            + self.half_accumulator.len())
            * std::mem::size_of::<Complex<f64>>()
            + (self.convolution_0.len()
                + self.convolution_1.len()
                + self.convolution_2.len())
                * std::mem::size_of::<i64>()
            + self.temporary_output.len() * std::mem::size_of::<u32>()
    }
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

    fn resident_bytes(&self) -> usize {
        (self.forward_twist.len() + self.inverse_twist.len())
            * std::mem::size_of::<Complex<f64>>()
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
        for ggsw in 0..self.ggsw_count {
            let control_size = self.digit_count * self.output_count * self.polynomial_size;
            let start = ggsw * control_size;
            if !self.convert_control(plan, ggsw, &coefficients[start..start + control_size], scratch) {
                return false;
            }
        }
        true
    }

    fn convert_control(
        &mut self,
        plan: &FftPlan,
        ggsw: usize,
        coefficients: &[u32],
        scratch: &mut FftScratch,
    ) -> bool {
        let expected = self.digit_count * self.output_count * self.polynomial_size;
        if plan.polynomial_size != self.polynomial_size
            || ggsw >= self.ggsw_count
            || coefficients.len() != expected
        {
            return false;
        }
        let half = plan.half_size;
        for digit in 0..self.digit_count {
            for output in 0..self.output_count {
                let polynomial = (digit * self.output_count + output) * self.polynomial_size;
                let spectrum_offset = self.spectrum_offset(ggsw, digit, output);
                plan.polynomial_centered_to_half(
                    &coefficients[polynomial..polynomial + self.polynomial_size],
                    scratch,
                    &mut self.spectra[spectrum_offset..spectrum_offset + half],
                );
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

    fn external_product_add(
        &self,
        plan: &FftPlan,
        scratch: &mut FftScratch,
        ggsw_index: usize,
        digits: &[u32],
        addend: &[u32],
        output: &mut [u32],
    ) -> bool {
        if addend.len() != output.len()
            || !self.external_product(plan, scratch, ggsw_index, digits, output)
        {
            return false;
        }
        for (value, addend) in output.iter_mut().zip(addend.iter()) {
            *value = value.wrapping_add(*addend);
        }
        true
    }

    fn export_coefficients(&self, plan: &FftPlan, scratch: &mut FftScratch, output: &mut [u32]) -> bool {
        let expected = match self
            .ggsw_count
            .checked_mul(self.digit_count)
            .and_then(|value| value.checked_mul(self.output_count))
            .and_then(|value| value.checked_mul(self.polynomial_size))
        {
            Some(value) => value,
            None => return false,
        };
        if output.len() != expected || plan.polynomial_size != self.polynomial_size {
            return false;
        }
        let half = plan.half_size;
        for ggsw in 0..self.ggsw_count {
            for digit in 0..self.digit_count {
                for component in 0..self.output_count {
                    let spectrum_offset = self.spectrum_offset(ggsw, digit, component);
                    for frequency in 0..half {
                        let value = self.spectra[spectrum_offset + frequency];
                        scratch.left[frequency] = value;
                        scratch.left[self.polynomial_size - 1 - frequency] = value.conj();
                    }
                    plan.inverse
                        .process_with_scratch(&mut scratch.left, &mut scratch.fft_scratch);
                    let scale = self.polynomial_size as f64;
                    let polynomial = ((ggsw * self.digit_count + digit) * self.output_count
                        + component)
                        * self.polynomial_size;
                    for coefficient in 0..self.polynomial_size {
                        let centered = ((scratch.left[coefficient]
                            * plan.inverse_twist[coefficient])
                            .re
                            / scale)
                            .round() as i64;
                        output[polynomial + coefficient] = centered as u32;
                    }
                }
            }
        }
        true
    }
}

fn checked_product(values: &[usize]) -> Option<usize> {
    values
        .iter()
        .try_fold(1usize, |product, value| product.checked_mul(*value))
}

fn polynomial_log2(size: usize) -> Option<usize> {
    if size < 2 || !size.is_power_of_two() {
        None
    } else {
        Some(size.trailing_zeros() as usize)
    }
}

fn modulus_switch(value: u32, log_modulus: usize) -> u32 {
    let modulus = 1u64 << log_modulus;
    ((((value as u64) * modulus + 0x8000_0000u64) >> 32) % modulus) as u32
}

fn rotate_negacyclic(input: &[u32], polynomial_size: usize, rotation: i64, output: &mut [u32]) -> bool {
    if polynomial_size == 0 || input.len() != output.len() || input.len() % polynomial_size != 0 {
        return false;
    }
    let period = (2 * polynomial_size) as i64;
    let normalized = rotation.rem_euclid(period) as usize;
    for component in 0..input.len() / polynomial_size {
        let offset = component * polynomial_size;
        for source in 0..polynomial_size {
            let exponent = source + normalized;
            let wraps = exponent / polynomial_size;
            let destination = exponent % polynomial_size;
            output[offset + destination] = if wraps & 1 == 0 {
                input[offset + source]
            } else {
                input[offset + source].wrapping_neg()
            };
        }
    }
    true
}

fn signed_gadget_decompose_into(value: u32, base_log: usize, digits: &mut [i32]) -> bool {
    let total_bits = match base_log.checked_mul(digits.len()) {
        Some(value) if base_log > 0 && base_log < 31 && !digits.is_empty() && value <= 32 => value,
        _ => return false,
    };
    let discarded_bits = 32 - total_bits;
    let rounded = if discarded_bits == 0 {
        value
    } else {
        value.wrapping_add(1u32 << (discarded_bits - 1))
    };
    let state = if discarded_bits == 0 {
        rounded
    } else {
        rounded >> discarded_bits
    };
    let base = 1i32 << base_log;
    let half = base / 2;
    let mask = (base - 1) as u32;
    let mut carry = 0i32;
    for offset in 0..digits.len() {
        let index = digits.len() - 1 - offset;
        let unsigned_digit = ((state >> (offset * base_log)) & mask) as i32 + carry;
        if unsigned_digit >= half {
            digits[index] = unsigned_digit - base;
            carry = 1;
        } else {
            digits[index] = unsigned_digit;
            carry = 0;
        }
    }
    true
}

impl NativePbsContext {
    #[allow(clippy::too_many_arguments)]
    fn new(
        polynomial_size: usize,
        input_dimension: usize,
        glwe_dimension: usize,
        pbs_base_log: usize,
        pbs_level: usize,
        ksk_input_dimension: usize,
        ksk_output_dimension: usize,
        ksk_base_log: usize,
        ksk_level: usize,
        order: u32,
        coefficients: &[u32],
        ksk: &[u32],
    ) -> Option<Self> {
        let mut context = Self::new_empty(
            polynomial_size,
            input_dimension,
            glwe_dimension,
            pbs_base_log,
            pbs_level,
            ksk_input_dimension,
            ksk_output_dimension,
            ksk_base_log,
            ksk_level,
            order,
            ksk,
        )?;
        if coefficients.len() != context.coefficient_count() {
            return None;
        }
        let control_size = context.control_coefficient_count();
        for index in 0..input_dimension {
            let start = index * control_size;
            if !context.set_control(index, &coefficients[start..start + control_size]) {
                return None;
            }
        }
        Some(context)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_empty(
        polynomial_size: usize,
        input_dimension: usize,
        glwe_dimension: usize,
        pbs_base_log: usize,
        pbs_level: usize,
        ksk_input_dimension: usize,
        ksk_output_dimension: usize,
        ksk_base_log: usize,
        ksk_level: usize,
        order: u32,
        ksk: &[u32],
    ) -> Option<Self> {
        let columns = glwe_dimension.checked_add(1)?;
        let digit_count = pbs_level.checked_mul(columns)?;
        let ksk_count = checked_product(&[
            ksk_input_dimension,
            ksk_level,
            ksk_output_dimension.checked_add(1)?,
        ])?;
        if input_dimension == 0
            || glwe_dimension == 0
            || pbs_base_log == 0
            || pbs_base_log.checked_mul(pbs_level)? > 32
            || ksk_base_log == 0
            || ksk_base_log.checked_mul(ksk_level)? > 32
            || ksk_input_dimension != glwe_dimension.checked_mul(polynomial_size)?
            || ksk_output_dimension != input_dimension
            || order > 1
            || ksk.len() != ksk_count
        {
            return None;
        }
        let plan = FftPlan::new(polynomial_size)?;
        let scratch = plan.new_scratch(digit_count, columns)?;
        let key = FourierBootstrapKey::new(&plan, input_dimension, digit_count, columns)?;
        let glwe_size = columns.checked_mul(polynomial_size)?;
        Some(Self {
            plan,
            scratch,
            key,
            ksk: ksk.to_vec(),
            input_dimension,
            glwe_dimension,
            pbs_base_log,
            pbs_level,
            ksk_input_dimension,
            ksk_output_dimension,
            ksk_base_log,
            ksk_level,
            order,
            state_a: vec![0; glwe_size],
            state_b: vec![0; glwe_size],
            rotated: vec![0; glwe_size],
            difference: vec![0; glwe_size],
            digits: vec![0; digit_count * polynomial_size],
            decomposition_digits: vec![0; pbs_level.max(ksk_level)],
            extracted: vec![0; ksk_input_dimension + 1],
            ksk_result: vec![0; ksk_output_dimension + 1],
            switched_input: vec![0; (ksk_input_dimension + 1).max(ksk_output_dimension + 1)],
            initialized_controls: vec![false; input_dimension],
            last_key_switch_ns: 0,
            last_external_product_ns: 0,
            last_external_product_count: 0,
            last_blind_rotation_ns: 0,
            last_sample_extraction_ns: 0,
            busy: AtomicBool::new(false),
        })
    }

    fn control_coefficient_count(&self) -> usize {
        self.key.digit_count * self.key.output_count * self.key.polynomial_size
    }

    fn set_control(&mut self, index: usize, coefficients: &[u32]) -> bool {
        if self.busy.load(Ordering::Acquire)
            || index >= self.input_dimension
            || self.initialized_controls[index]
            || coefficients.len() != self.control_coefficient_count()
        {
            return false;
        }
        if !self
            .key
            .convert_control(&self.plan, index, coefficients, &mut self.scratch)
        {
            return false;
        }
        self.initialized_controls[index] = true;
        true
    }

    fn ready(&self) -> bool {
        self.initialized_controls.iter().all(|value| *value)
    }

    fn input_size(&self) -> usize {
        if self.order == 0 {
            self.ksk_input_dimension + 1
        } else {
            self.input_dimension + 1
        }
    }

    fn output_size(&self) -> usize {
        if self.order == 0 {
            self.ksk_input_dimension + 1
        } else {
            self.ksk_output_dimension + 1
        }
    }

    fn decompose_glwe(&mut self) -> bool {
        let columns = self.glwe_dimension + 1;
        let n = self.plan.polynomial_size;
        for component in 0..columns {
            for coefficient in 0..n {
                if !signed_gadget_decompose_into(
                    self.difference[component * n + coefficient],
                    self.pbs_base_log,
                    &mut self.decomposition_digits[..self.pbs_level],
                ) {
                    return false;
                }
                for level in 0..self.pbs_level {
                    let row = level * columns + component;
                    self.digits[row * n + coefficient] =
                        self.decomposition_digits[level] as u32;
                }
            }
        }
        true
    }

    fn key_switch_inner(&mut self, input: &[u32]) -> bool {
        if input.len() != self.ksk_input_dimension + 1 {
            return false;
        }
        self.ksk_result.fill(0);
        self.ksk_result[self.ksk_output_dimension] = input[self.ksk_input_dimension];
        let ciphertext_size = self.ksk_output_dimension + 1;
        for index in 0..self.ksk_input_dimension {
            if !signed_gadget_decompose_into(
                input[index],
                self.ksk_base_log,
                &mut self.decomposition_digits[..self.ksk_level],
            ) {
                return false;
            }
            for level in 0..self.ksk_level {
                let digit = self.decomposition_digits[level];
                if digit != 0 {
                    let offset = (index * self.ksk_level + level) * ciphertext_size;
                    for word in 0..ciphertext_size {
                        self.ksk_result[word] = self.ksk_result[word]
                            .wrapping_sub(self.ksk[offset + word].wrapping_mul(digit as u32));
                    }
                }
            }
        }
        true
    }

    fn key_switch(&mut self, input: &[u32]) -> bool {
        let start = Instant::now();
        let result = self.key_switch_inner(input);
        self.last_key_switch_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        result
    }

    fn blind_rotate(&mut self, input: &[u32], accumulator: &[u32]) -> bool {
        let blind_rotation_start = Instant::now();
        let mut external_product_ns = 0u128;
        let mut external_product_count = 0u64;
        let n = self.plan.polynomial_size;
        let log_modulus = match polynomial_log2(n) {
            Some(value) => value + 1,
            None => return false,
        };
        if input.len() != self.input_dimension + 1 || accumulator.len() != self.state_a.len() {
            return false;
        }
        let initial_rotation = modulus_switch(input[self.input_dimension], log_modulus) as i64;
        if !rotate_negacyclic(accumulator, n, initial_rotation, &mut self.state_a) {
            return false;
        }
        let mut active_a = true;
        for index in 0..self.input_dimension {
            let switched = modulus_switch(input[index], log_modulus);
            if switched != 0 {
                if active_a {
                    if !rotate_negacyclic(
                        &self.state_a,
                        n,
                        -(switched as i64),
                        &mut self.rotated,
                    ) {
                        return false;
                    }
                    for word in 0..self.difference.len() {
                        self.difference[word] =
                            self.rotated[word].wrapping_sub(self.state_a[word]);
                    }
                } else {
                    if !rotate_negacyclic(
                        &self.state_b,
                        n,
                        -(switched as i64),
                        &mut self.rotated,
                    ) {
                        return false;
                    }
                    for word in 0..self.difference.len() {
                        self.difference[word] =
                            self.rotated[word].wrapping_sub(self.state_b[word]);
                    }
                }
                if !self.decompose_glwe() {
                    return false;
                }
                let external_product_start = Instant::now();
                let product_ok = if active_a {
                    self.key.external_product_add(
                        &self.plan,
                        &mut self.scratch,
                        index,
                        &self.digits,
                        &self.state_a,
                        &mut self.state_b,
                    )
                } else {
                    self.key.external_product_add(
                        &self.plan,
                        &mut self.scratch,
                        index,
                        &self.digits,
                        &self.state_b,
                        &mut self.state_a,
                    )
                };
                external_product_ns += external_product_start.elapsed().as_nanos();
                external_product_count += 1;
                if !product_ok {
                    return false;
                }
                active_a = !active_a;
            }
        }
        self.last_external_product_ns = external_product_ns.min(u64::MAX as u128) as u64;
        self.last_external_product_count = external_product_count;
        self.last_blind_rotation_ns = blind_rotation_start
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        let extraction_start = Instant::now();
        let final_state = if active_a { &self.state_a } else { &self.state_b };
        for flat_index in 0..self.ksk_input_dimension {
            let component = flat_index / n;
            let coefficient = flat_index % n;
            self.extracted[flat_index] = if coefficient == 0 {
                final_state[component * n]
            } else {
                final_state[component * n + n - coefficient].wrapping_neg()
            };
        }
        self.extracted[self.ksk_input_dimension] =
            final_state[self.ksk_input_dimension];
        self.last_sample_extraction_ns = extraction_start
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        true
    }

    fn evaluate(&mut self, input: &[u32], accumulator: &[u32], output: &mut [u32]) -> i32 {
        if !self.ready() {
            return FFT_INVALID_SIZE;
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return FFT_BUSY;
        }
        let _guard = BusyGuard(&self.busy);
        if input.len() != self.input_size()
            || output.len() != self.output_size()
            || accumulator.len() != self.state_a.len()
        {
            return FFT_INVALID_SIZE;
        }
        let ok = if self.order == 0 {
            if !self.key_switch(input) {
                false
            } else {
                self.switched_input[..self.ksk_result.len()].copy_from_slice(&self.ksk_result);
                let switched_ptr = self.switched_input.as_ptr();
                let switched_len = self.ksk_result.len();
                // The workspace buffer is disjoint from every buffer mutated by blind rotation.
                let switched = unsafe { slice::from_raw_parts(switched_ptr, switched_len) };
                self.blind_rotate(switched, accumulator)
            }
        } else if !self.blind_rotate(input, accumulator) {
            false
        } else {
            self.switched_input[..self.extracted.len()].copy_from_slice(&self.extracted);
            let extracted_ptr = self.switched_input.as_ptr();
            let extracted_len = self.extracted.len();
            // The workspace buffer is disjoint from KSK output and decomposition storage.
            let extracted = unsafe { slice::from_raw_parts(extracted_ptr, extracted_len) };
            self.key_switch(extracted)
        };
        if !ok {
            return FFT_INVALID_SIZE;
        }
        if self.order == 0 {
            output.copy_from_slice(&self.extracted);
        } else {
            output.copy_from_slice(&self.ksk_result);
        }
        FFT_OK
    }

    fn coefficient_count(&self) -> usize {
        self.key.ggsw_count
            * self.key.digit_count
            * self.key.output_count
            * self.key.polynomial_size
    }

    fn export_coefficients(&mut self, output: &mut [u32]) -> bool {
        self.ready()
            && self
                .key
                .export_coefficients(&self.plan, &mut self.scratch, output)
    }

    fn export_ksk(&self, output: &mut [u32]) -> bool {
        if output.len() != self.ksk.len() {
            false
        } else {
            output.copy_from_slice(&self.ksk);
            true
        }
    }

    fn fourier_key_bytes(&self) -> usize {
        self.key.spectra.len() * std::mem::size_of::<Complex<f64>>()
    }

    fn ksk_bytes(&self) -> usize {
        self.ksk.len() * std::mem::size_of::<u32>()
    }

    fn workspace_bytes(&self) -> usize {
        self.plan.resident_bytes()
            + self.scratch.resident_bytes()
            + (self.state_a.len()
                + self.state_b.len()
                + self.rotated.len()
                + self.difference.len()
                + self.digits.len()
                + self.extracted.len()
                + self.ksk_result.len()
                + self.switched_input.len())
                * std::mem::size_of::<u32>()
            + self.decomposition_digits.len() * std::mem::size_of::<i32>()
            + self.initialized_controls.len() * std::mem::size_of::<bool>()
    }

    fn resident_bytes(&self) -> usize {
        self.fourier_key_bytes() + self.ksk_bytes() + self.workspace_bytes()
    }

    fn memory_metric(&self, metric: u32) -> usize {
        match metric {
            0 => self.resident_bytes(),
            1 => self.fourier_key_bytes(),
            2 => self.ksk_bytes(),
            3 => self.workspace_bytes(),
            _ => 0,
        }
    }

    #[cfg(feature = "allocation-counter")]
    fn measure_allocations(
        &mut self,
        input: &[u32],
        accumulator: &[u32],
        output: &mut [u32],
        iterations: usize,
    ) -> Option<usize> {
        if iterations == 0 {
            return None;
        }
        allocation_counter::start();
        for _ in 0..iterations {
            if self.evaluate(input, accumulator, output) != FFT_OK {
                allocation_counter::stop();
                return None;
            }
        }
        Some(allocation_counter::stop())
    }

    fn stage_metric(&self, metric: u32) -> u64 {
        match metric {
            0 => self.last_key_switch_ns,
            1 => self.last_external_product_ns,
            2 => self.last_external_product_count,
            3 => self.last_blind_rotation_ns,
            4 => self.last_sample_extraction_ns,
            _ => 0,
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
pub unsafe extern "C" fn fourier_bsk_external_product_into(
    plan: *const FftPlan,
    key: *const FourierBootstrapKey,
    scratch: *mut FftScratch,
    ggsw_index: u32,
    digits: *const u32,
    digit_count: usize,
    output: *mut u32,
    output_count: usize,
) -> i32 {
    indexed_ggsw_external_product_u32(
        plan,
        key,
        scratch,
        ggsw_index,
        digits,
        digit_count,
        output,
        output_count,
    )
}

#[no_mangle]
pub unsafe extern "C" fn fourier_bsk_external_product_batch(
    plan: *const FftPlan,
    key: *const FourierBootstrapKey,
    scratch: *mut FftScratch,
    ggsw_indices: *const u32,
    batch_count: usize,
    digits: *const u32,
    digit_count: usize,
    output: *mut u32,
    output_count: usize,
) -> i32 {
    if plan.is_null()
        || key.is_null()
        || scratch.is_null()
        || ggsw_indices.is_null()
        || digits.is_null()
        || output.is_null()
    {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let plan = &*plan;
        let key = &*key;
        let scratch = &mut *scratch;
        let digits_per_batch = match key.digit_count.checked_mul(plan.polynomial_size) {
            Some(value) => value,
            None => return FFT_INVALID_SIZE,
        };
        let output_per_batch = match key.output_count.checked_mul(plan.polynomial_size) {
            Some(value) => value,
            None => return FFT_INVALID_SIZE,
        };
        if batch_count == 0
            || digit_count != batch_count.saturating_mul(digits_per_batch)
            || output_count != batch_count.saturating_mul(output_per_batch)
        {
            return FFT_INVALID_SIZE;
        }
        let indices = slice::from_raw_parts(ggsw_indices, batch_count);
        let digits = slice::from_raw_parts(digits, digit_count);
        let output = slice::from_raw_parts_mut(output, output_count);
        for batch in 0..batch_count {
            if !key.external_product(
                plan,
                scratch,
                indices[batch] as usize,
                &digits[batch * digits_per_batch..(batch + 1) * digits_per_batch],
                &mut output[batch * output_per_batch..(batch + 1) * output_per_batch],
            ) {
                return FFT_INVALID_SIZE;
            }
        }
        FFT_OK
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn fourier_blind_rotation_step(
    plan: *const FftPlan,
    key: *const FourierBootstrapKey,
    scratch: *mut FftScratch,
    ggsw_index: u32,
    digits: *const u32,
    digit_count: usize,
    addend: *const u32,
    addend_count: usize,
    output: *mut u32,
    output_count: usize,
) -> i32 {
    if plan.is_null()
        || key.is_null()
        || scratch.is_null()
        || digits.is_null()
        || addend.is_null()
        || output.is_null()
    {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if (&*key).external_product_add(
            &*plan,
            &mut *scratch,
            ggsw_index as usize,
            slice::from_raw_parts(digits, digit_count),
            slice::from_raw_parts(addend, addend_count),
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
pub unsafe extern "C" fn fourier_accumulator_add_in_place(
    accumulator: *mut u32,
    accumulator_count: usize,
    addend: *const u32,
    addend_count: usize,
) -> i32 {
    if accumulator.is_null() || addend.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if accumulator_count != addend_count {
            return FFT_INVALID_SIZE;
        }
        let accumulator = slice::from_raw_parts_mut(accumulator, accumulator_count);
        let addend = slice::from_raw_parts(addend, addend_count);
        for (value, addend) in accumulator.iter_mut().zip(addend.iter()) {
            *value = value.wrapping_add(*addend);
        }
        FFT_OK
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn fourier_workspace_reset(scratch: *mut FftScratch) -> i32 {
    if scratch.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        (&mut *scratch).reset();
        FFT_OK
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn native_pbs_context_new(
    polynomial_size: u32,
    input_dimension: u32,
    glwe_dimension: u32,
    pbs_base_log: u32,
    pbs_level: u32,
    ksk_input_dimension: u32,
    ksk_output_dimension: u32,
    ksk_base_log: u32,
    ksk_level: u32,
    order: u32,
    coefficients: *const u32,
    coefficient_count: usize,
    ksk: *const u32,
    ksk_count: usize,
) -> *mut NativePbsContext {
    if coefficients.is_null() || ksk.is_null() {
        return ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        NativePbsContext::new(
            polynomial_size as usize,
            input_dimension as usize,
            glwe_dimension as usize,
            pbs_base_log as usize,
            pbs_level as usize,
            ksk_input_dimension as usize,
            ksk_output_dimension as usize,
            ksk_base_log as usize,
            ksk_level as usize,
            order,
            slice::from_raw_parts(coefficients, coefficient_count),
            slice::from_raw_parts(ksk, ksk_count),
        )
    })) {
        Ok(Some(context)) => Box::into_raw(Box::new(context)),
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn native_pbs_context_new_empty(
    polynomial_size: u32,
    input_dimension: u32,
    glwe_dimension: u32,
    pbs_base_log: u32,
    pbs_level: u32,
    ksk_input_dimension: u32,
    ksk_output_dimension: u32,
    ksk_base_log: u32,
    ksk_level: u32,
    order: u32,
    ksk: *const u32,
    ksk_count: usize,
) -> *mut NativePbsContext {
    if ksk.is_null() {
        return ptr::null_mut();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        NativePbsContext::new_empty(
            polynomial_size as usize,
            input_dimension as usize,
            glwe_dimension as usize,
            pbs_base_log as usize,
            pbs_level as usize,
            ksk_input_dimension as usize,
            ksk_output_dimension as usize,
            ksk_base_log as usize,
            ksk_level as usize,
            order,
            slice::from_raw_parts(ksk, ksk_count),
        )
    })) {
        Ok(Some(context)) => Box::into_raw(Box::new(context)),
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_set_control(
    context: *mut NativePbsContext,
    index: u32,
    coefficients: *const u32,
    coefficient_count: usize,
) -> i32 {
    if context.is_null() || coefficients.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if (&mut *context).set_control(
            index as usize,
            slice::from_raw_parts(coefficients, coefficient_count),
        ) {
            FFT_OK
        } else {
            FFT_INVALID_SIZE
        }
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_ready(
    context: *const NativePbsContext,
) -> i32 {
    if context.is_null() {
        0
    } else if (&*context).ready() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_valid(context: *const NativePbsContext) -> i32 {
    if context.is_null() {
        0
    } else {
        1
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_input_size(context: *const NativePbsContext) -> usize {
    if context.is_null() {
        0
    } else {
        (&*context).input_size()
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_output_size(context: *const NativePbsContext) -> usize {
    if context.is_null() {
        0
    } else {
        (&*context).output_size()
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_coefficient_count(
    context: *const NativePbsContext,
) -> usize {
    if context.is_null() {
        0
    } else {
        (&*context).coefficient_count()
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_ksk_count(context: *const NativePbsContext) -> usize {
    if context.is_null() {
        0
    } else {
        (&*context).ksk.len()
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_resident_bytes(
    context: *const NativePbsContext,
) -> usize {
    if context.is_null() {
        0
    } else {
        (&*context).resident_bytes()
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_memory_metric(
    context: *const NativePbsContext,
    metric: u32,
) -> usize {
    if context.is_null() {
        0
    } else {
        (&*context).memory_metric(metric)
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_measure_allocations(
    context: *mut NativePbsContext,
    input: *const u32,
    input_count: usize,
    accumulator: *const u32,
    accumulator_count: usize,
    output: *mut u32,
    output_count: usize,
    iterations: usize,
) -> u64 {
    if context.is_null()
        || input.is_null()
        || accumulator.is_null()
        || output.is_null()
        || iterations == 0
    {
        return u64::MAX;
    }
    #[cfg(feature = "allocation-counter")]
    {
        return catch_unwind(AssertUnwindSafe(|| {
            (&mut *context).measure_allocations(
                slice::from_raw_parts(input, input_count),
                slice::from_raw_parts(accumulator, accumulator_count),
                slice::from_raw_parts_mut(output, output_count),
                iterations,
            )
        }))
        .ok()
        .flatten()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(u64::MAX);
    }
    #[cfg(not(feature = "allocation-counter"))]
    {
        let _ = (
            input_count,
            accumulator_count,
            output_count,
            iterations,
        );
        u64::MAX
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_stage_metric(
    context: *const NativePbsContext,
    metric: u32,
) -> u64 {
    if context.is_null() {
        0
    } else {
        (&*context).stage_metric(metric)
    }
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_evaluate_lut(
    context: *mut NativePbsContext,
    input: *const u32,
    input_count: usize,
    accumulator: *const u32,
    accumulator_count: usize,
    output: *mut u32,
    output_count: usize,
) -> i32 {
    if context.is_null() || input.is_null() || accumulator.is_null() || output.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        (&mut *context).evaluate(
            slice::from_raw_parts(input, input_count),
            slice::from_raw_parts(accumulator, accumulator_count),
            slice::from_raw_parts_mut(output, output_count),
        )
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_export_coefficients(
    context: *mut NativePbsContext,
    output: *mut u32,
    output_count: usize,
) -> i32 {
    if context.is_null() || output.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if (&mut *context).export_coefficients(slice::from_raw_parts_mut(output, output_count)) {
            FFT_OK
        } else {
            FFT_INVALID_SIZE
        }
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_export_ksk(
    context: *const NativePbsContext,
    output: *mut u32,
    output_count: usize,
) -> i32 {
    if context.is_null() || output.is_null() {
        return FFT_NULL_POINTER;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if (&*context).export_ksk(slice::from_raw_parts_mut(output, output_count)) {
            FFT_OK
        } else {
            FFT_INVALID_SIZE
        }
    }))
    .unwrap_or(FFT_PANIC)
}

#[no_mangle]
pub unsafe extern "C" fn native_pbs_context_free(context: *mut NativePbsContext) {
    if !context.is_null() {
        drop(Box::from_raw(context));
    }
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
    fn fourier_bsk_full_width_roundtrip_standard_sizes() {
        for polynomial_size in [512usize, 1024usize] {
            let plan = FftPlan::new(polynomial_size).unwrap();
            let mut scratch = plan.new_scratch(2, 2).unwrap();
            let mut key = FourierBootstrapKey::new(&plan, 1, 2, 2).unwrap();
            let mut state = 0x9e37_79b9u32;
            let coefficients: Vec<u32> = (0..4 * polynomial_size)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state
                })
                .collect();
            assert!(key.convert(&plan, &coefficients, &mut scratch));
            let mut restored = vec![0u32; coefficients.len()];
            assert!(key.export_coefficients(&plan, &mut scratch, &mut restored));
            assert_eq!(restored, coefficients);
        }
    }

    #[test]
    fn native_pbs_context_evaluates_and_exports_without_secret_material() {
        let polynomial_size = 8usize;
        let input_dimension = 2usize;
        let glwe_dimension = 1usize;
        let pbs_level = 8usize;
        let columns = glwe_dimension + 1;
        let coefficient_count =
            input_dimension * pbs_level * columns * columns * polynomial_size;
        let ksk_input_dimension = glwe_dimension * polynomial_size;
        let ksk_output_dimension = input_dimension;
        let ksk_level = 8usize;
        let ksk_count = ksk_input_dimension * ksk_level * (ksk_output_dimension + 1);
        let coefficients = vec![0u32; coefficient_count];
        let ksk = vec![0u32; ksk_count];
        let mut context = NativePbsContext::new(
            polynomial_size,
            input_dimension,
            glwe_dimension,
            4,
            pbs_level,
            ksk_input_dimension,
            ksk_output_dimension,
            4,
            ksk_level,
            1,
            &coefficients,
            &ksk,
        )
        .unwrap();
        let mut input = vec![0u32; input_dimension + 1];
        input[0] = 0x2000_0000;
        let mut accumulator = vec![0u32; columns * polynomial_size];
        accumulator[glwe_dimension * polynomial_size] = 0x2000_0000;
        let mut output = vec![0u32; ksk_output_dimension + 1];
        assert_eq!(context.evaluate(&input, &accumulator, &mut output), FFT_OK);
        assert!(context.stage_metric(0) > 0);
        assert!(context.stage_metric(1) > 0);
        assert!(context.stage_metric(2) > 0);
        assert!(context.stage_metric(3) > 0);
        assert!(context.stage_metric(4) > 0);
        assert_eq!(output, vec![0, 0, 0x2000_0000]);
        assert_eq!(context.evaluate(&input, &accumulator, &mut output), FFT_OK);
        let mut restored_coefficients = vec![0u32; coefficient_count];
        assert!(context.export_coefficients(&mut restored_coefficients));
        assert_eq!(restored_coefficients, coefficients);
        let mut restored_ksk = vec![0u32; ksk_count];
        assert!(context.export_ksk(&mut restored_ksk));
        assert_eq!(restored_ksk, ksk);
        assert!(context.resident_bytes() > coefficient_count * std::mem::size_of::<u32>());
    }

    #[test]
    fn native_pbs_context_streams_controls_without_a_coefficient_bsk() {
        let polynomial_size = 32usize;
        let input_dimension = 3usize;
        let glwe_dimension = 1usize;
        let pbs_level = 4usize;
        let columns = glwe_dimension + 1;
        let control_size = pbs_level * columns * columns * polynomial_size;
        let ksk_input_dimension = glwe_dimension * polynomial_size;
        let ksk_output_dimension = input_dimension;
        let ksk_level = 4usize;
        let ksk = vec![0u32; ksk_input_dimension * ksk_level * (ksk_output_dimension + 1)];
        let mut context = NativePbsContext::new_empty(
            polynomial_size,
            input_dimension,
            glwe_dimension,
            8,
            pbs_level,
            ksk_input_dimension,
            ksk_output_dimension,
            8,
            ksk_level,
            1,
            &ksk,
        )
        .unwrap();
        assert!(!context.ready());
        let input = vec![0u32; input_dimension + 1];
        let accumulator = vec![0u32; columns * polynomial_size];
        let mut output = vec![0u32; ksk_output_dimension + 1];
        assert_eq!(
            context.evaluate(&input, &accumulator, &mut output),
            FFT_INVALID_SIZE
        );
        let control = vec![0u32; control_size];
        for index in 0..input_dimension {
            assert!(context.set_control(index, &control));
            assert!(!context.set_control(index, &control));
        }
        assert!(context.ready());
        assert_eq!(context.evaluate(&input, &accumulator, &mut output), FFT_OK);
        let mut restored = vec![1u32; input_dimension * control_size];
        assert!(context.export_coefficients(&mut restored));
        assert_eq!(restored, vec![0u32; input_dimension * control_size]);
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
