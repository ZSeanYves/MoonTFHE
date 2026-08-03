use std::hint::black_box;
use std::time::Instant;

use tfhe::boolean::client_key::ClientKey;
use tfhe::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
};
use tfhe::boolean::prelude::BinaryBooleanGates;
use tfhe::boolean::server_key::ServerKey;

const WARMUP: usize = 100;
const ITERATIONS: usize = 100;

fn elapsed_us(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000_000.0
}

fn measure_gate<F>(mut operation: F) -> f64
where
    F: FnMut(),
{
    for _ in 0..WARMUP {
        operation();
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        operation();
    }
    elapsed_us(start) / ITERATIONS as f64
}

fn measure(parameter_name: &str, parameters: &BooleanParameters) {
    let keygen_start = Instant::now();
    let client = ClientKey::new(parameters);
    let server = ServerKey::new(&client);
    let keygen_us = elapsed_us(keygen_start);
    let left = client.encrypt(true);
    let right = client.encrypt(true);
    let mut nand_output = server.nand(&left, &right);
    let nand_us = measure_gate(|| {
        nand_output = black_box(server.nand(black_box(&left), black_box(&right)));
    });
    let mut and_output = server.and(&left, &right);
    let and_us = measure_gate(|| {
        and_output = black_box(server.and(black_box(&left), black_box(&right)));
    });
    let mut or_output = server.or(&left, &right);
    let or_us = measure_gate(|| {
        or_output = black_box(server.or(black_box(&left), black_box(&right)));
    });
    let mut xor_output = server.xor(&left, &right);
    let xor_us = measure_gate(|| {
        xor_output = black_box(server.xor(black_box(&left), black_box(&right)));
    });
    let mut xnor_output = server.xnor(&left, &right);
    let xnor_us = measure_gate(|| {
        xnor_output = black_box(server.xnor(black_box(&left), black_box(&right)));
    });
    let mut mux_output = server.mux(&left, &right, &left);
    let mux_us = measure_gate(|| {
        mux_output = black_box(server.mux(black_box(&left), black_box(&right), black_box(&left)));
    });
    assert!(!client.decrypt(&nand_output));
    assert!(client.decrypt(&and_output));
    assert!(client.decrypt(&or_output));
    assert!(!client.decrypt(&xor_output));
    assert!(client.decrypt(&xnor_output));
    assert!(client.decrypt(&mux_output));
    println!(
        "{{\"schema_version\":3,\"kind\":\"performance\",\"implementation\":\"tfhe-rs\",\"parameter\":\"{}\",\"warmup\":{},\"iterations\":{},\"keygen_us\":{},\"pbs_us\":{},\"nand_us\":{},\"stage_metrics\":{{\"key_generation_us\":{},\"pbs_with_ks_us\":{},\"pbs_without_ks_us\":null,\"ksk_generation_us\":null,\"ksk_apply_us\":null,\"bsk_coefficient_generation_us\":null,\"bsk_fourier_conversion_us\":null,\"polynomial_multiplication_us\":null,\"external_product_us\":null,\"blind_rotation_us\":null,\"sample_extraction_us\":null,\"nand_us\":{},\"and_us\":{},\"or_us\":{},\"xor_us\":{},\"xnor_us\":{},\"mux_us\":{}}}}}",
        parameter_name, WARMUP, ITERATIONS, keygen_us, nand_us, nand_us,
        keygen_us, nand_us, nand_us, and_us, or_us, xor_us, xnor_us, mux_us,
    );
}

fn measure_serialized_size(parameter_name: &str, parameters: &BooleanParameters) {
    let client = ClientKey::new(parameters);
    let server = ServerKey::new(&client);
    let left = client.encrypt(true);
    let server_key_bytes = bincode::serialize(&server)
        .expect("serialize server key")
        .len();
    let ciphertext_bytes = bincode::serialize(&left)
        .expect("serialize ciphertext")
        .len();
    println!(
        "{{\"schema_version\":3,\"kind\":\"serialized-size\",\"implementation\":\"tfhe-rs\",\"parameter\":\"{}\",\"server_key_bytes\":{},\"ciphertext_bytes\":{}}}",
        parameter_name, server_key_bytes, ciphertext_bytes,
    );
}

fn parameter(name: &str) -> &BooleanParameters {
    match name {
        "boolean-110" => &DEFAULT_PARAMETERS,
        "boolean-128" => &PARAMETERS_ERROR_PROB_2_POW_MINUS_165,
        other => panic!("unsupported parameter: {other}"),
    }
}

fn main() {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "boolean-110".to_string());
    let mode_arg = std::env::args().nth(2);
    let mode = mode_arg.as_deref().unwrap_or("performance");
    let params = parameter(&name);
    match mode {
        "performance" => measure(&name, params),
        "serialized-size" => measure_serialized_size(&name, params),
        other => panic!("unsupported benchmark mode: {other}"),
    }
}
