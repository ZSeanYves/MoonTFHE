use std::hint::black_box;
use std::time::Instant;

use tfhe::boolean::client_key::ClientKey;
use tfhe::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
};
use tfhe::boolean::server_key::ServerKey;
use tfhe::boolean::prelude::BinaryBooleanGates;

const ITERATIONS: usize = 10;

fn elapsed_us(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000_000.0
}

fn measure(parameter_name: &str, parameters: &BooleanParameters) {
    let keygen_start = Instant::now();
    let client = ClientKey::new(parameters);
    let server = ServerKey::new(&client);
    let keygen_us = elapsed_us(keygen_start);
    let left = client.encrypt(true);
    let right = client.encrypt(true);
    let nand_start = Instant::now();
    let mut output = server.nand(&left, &right);
    for _ in 1..ITERATIONS {
        output = black_box(server.nand(black_box(&left), black_box(&right)));
    }
    let nand_us = elapsed_us(nand_start) / ITERATIONS as f64;
    let and_start = Instant::now();
    let mut and_output = server.and(&left, &right);
    for _ in 1..ITERATIONS {
        and_output = black_box(server.and(black_box(&left), black_box(&right)));
    }
    let and_us = elapsed_us(and_start) / ITERATIONS as f64;
    let or_start = Instant::now();
    let mut or_output = server.or(&left, &right);
    for _ in 1..ITERATIONS {
        or_output = black_box(server.or(black_box(&left), black_box(&right)));
    }
    let or_us = elapsed_us(or_start) / ITERATIONS as f64;
    let xor_start = Instant::now();
    let mut xor_output = server.xor(&left, &right);
    for _ in 1..ITERATIONS {
        xor_output = black_box(server.xor(black_box(&left), black_box(&right)));
    }
    let xor_us = elapsed_us(xor_start) / ITERATIONS as f64;
    let xnor_start = Instant::now();
    let mut xnor_output = server.xnor(&left, &right);
    for _ in 1..ITERATIONS {
        xnor_output = black_box(server.xnor(black_box(&left), black_box(&right)));
    }
    let xnor_us = elapsed_us(xnor_start) / ITERATIONS as f64;
    let mux_start = Instant::now();
    let mut mux_output = server.mux(&left, &right, &left);
    for _ in 1..ITERATIONS {
        mux_output = black_box(server.mux(black_box(&left), black_box(&right), black_box(&left)));
    }
    let mux_us = elapsed_us(mux_start) / ITERATIONS as f64;
    assert!(!client.decrypt(&output));
    assert!(client.decrypt(&and_output));
    assert!(client.decrypt(&or_output));
    assert!(!client.decrypt(&xor_output));
    assert!(client.decrypt(&xnor_output));
    assert!(client.decrypt(&mux_output));
    let server_key_bytes = bincode::serialize(&server).expect("serialize server key").len();
    let ciphertext_bytes = bincode::serialize(&left).expect("serialize ciphertext").len();
    println!(
        "{{\"schema_version\":2,\"implementation\":\"tfhe-rs\",\"parameter\":\"{}\",\"iterations\":{},\"keygen_us\":{},\"nand_us\":{},\"server_key_bytes\":{},\"ciphertext_bytes\":{},\"stage_metrics\":{{\"key_generation_us\":{},\"pbs_with_ks_us\":null,\"pbs_without_ks_us\":null,\"ksk_generation_us\":null,\"ksk_apply_us\":null,\"bsk_coefficient_generation_us\":null,\"bsk_fourier_conversion_us\":null,\"polynomial_multiplication_us\":null,\"external_product_us\":null,\"blind_rotation_us\":null,\"sample_extraction_us\":null,\"nand_us\":{},\"and_us\":{},\"or_us\":{},\"xor_us\":{},\"xnor_us\":{},\"mux_us\":{}}},\"allocation_metrics\":{{\"available\":false,\"steady_state_heap_allocations\":null,\"workspace_peak_bytes\":null}},\"memory_metrics\":{{\"peak_rss_kib\":null,\"server_key_bytes\":{},\"ciphertext_bytes\":{}}}}}",
        parameter_name,
        ITERATIONS,
        keygen_us,
        nand_us,
        server_key_bytes,
        ciphertext_bytes,
        keygen_us,
        nand_us,
        and_us,
        or_us,
        xor_us,
        xnor_us,
        mux_us,
        server_key_bytes,
        ciphertext_bytes,
    );
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("boolean-110") => measure("boolean-110", &DEFAULT_PARAMETERS),
        Some("boolean-128") => measure(
            "boolean-128",
            &PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
        ),
        None => {
            measure("boolean-110", &DEFAULT_PARAMETERS);
            measure(
                "boolean-128",
                &PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
            );
        }
        Some(other) => panic!("unsupported parameter: {other}"),
    }
}
