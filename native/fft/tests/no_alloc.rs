use moontfhe_fft::{
    fft_plan_free, fft_plan_new, fft_scratch_free, fft_scratch_new, fourier_bsk_convert,
    fourier_bsk_free, fourier_bsk_new, indexed_ggsw_external_product_u32,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(pointer, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn external_product_hot_path_performs_no_allocations() {
    let n = 32usize;
    let ggsw_count = 2usize;
    let digit_count = 3usize;
    let output_count = 2usize;
    let plan = fft_plan_new(n as u32);
    let scratch = unsafe { fft_scratch_new(plan, digit_count as u32, output_count as u32) };
    let key = unsafe {
        fourier_bsk_new(
            plan,
            ggsw_count as u32,
            digit_count as u32,
            output_count as u32,
        )
    };
    assert!(!plan.is_null());
    assert!(!scratch.is_null());
    assert!(!key.is_null());

    let coefficients: Vec<u32> = (0..ggsw_count * digit_count * output_count * n)
        .map(|index| (index as u32).wrapping_mul(0x9e37_79b9) ^ 0xf000_0001)
        .collect();
    let digits: Vec<u32> = (0..digit_count * n)
        .map(|index| ((index as i32 % 17) - 8) as u32)
        .collect();
    let mut output = vec![0u32; output_count * n];
    assert_eq!(
        unsafe {
            fourier_bsk_convert(plan, key, scratch, coefficients.as_ptr(), coefficients.len())
        },
        0
    );

    ALLOCATIONS.store(0, Ordering::SeqCst);
    COUNTING.store(true, Ordering::SeqCst);
    for _ in 0..1_000 {
        let status = unsafe {
            indexed_ggsw_external_product_u32(
                plan,
                key,
                scratch,
                1,
                digits.as_ptr(),
                digits.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(status, 0);
    }
    COUNTING.store(false, Ordering::SeqCst);
    assert_eq!(ALLOCATIONS.load(Ordering::SeqCst), 0);

    unsafe {
        fourier_bsk_free(key);
        fft_scratch_free(scratch);
        fft_plan_free(plan);
    }
}
