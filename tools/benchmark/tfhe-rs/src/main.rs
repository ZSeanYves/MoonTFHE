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
    assert!(!client.decrypt(&output));
    let server_key_bytes = bincode::serialize(&server).expect("serialize server key").len();
    let ciphertext_bytes = bincode::serialize(&left).expect("serialize ciphertext").len();
    println!(
        "{{\"schema_version\":1,\"implementation\":\"tfhe-rs\",\"parameter\":\"{}\",\"iterations\":{},\"keygen_us\":{},\"nand_us\":{},\"server_key_bytes\":{},\"ciphertext_bytes\":{}}}",
        parameter_name,
        ITERATIONS,
        keygen_us,
        nand_us,
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
