use std::{str::FromStr, time::Duration};

use ascon_aead128::{
    aead::{Aead, KeyInit},
    AsconAead128, AsconAead128Key, AsconAead128Nonce,
};
//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
use clap::Parser;
use zenoh::{key_expr::KeyExpr, query::QueryTarget, Config};
use zenoh_examples::CommonArgs;

#[tokio::main]
async fn main() {
    // Initiate logging
    zenoh::init_log_from_env_or("error");

    let (config, key_expr) = parse_args();

    println!("Opening session...");
    let session = zenoh::open(config).await.unwrap();

    let selector = KeyExpr::from_str("demo/keys").unwrap();
    let mut builder = session
        .get(&selector)
        // // By default get receives replies from a FIFO.
        // // Uncomment this line to use a ring channel instead.
        // // More information on the ring channel are available in the z_pull example.
        // .with(zenoh::handlers::RingChannel::default())
        // Refer to z_bytes.rs to see how to serialize different types of message
        .target(QueryTarget::All)
        .timeout(Duration::from_secs(1));

    let replies = builder.await.unwrap();
    let mut key = Vec::new();
    while let Ok(reply) = replies.recv_async().await {
        match reply.result() {
            Ok(sample) => {
                // Refer to z_bytes.rs to see how to deserialize different types of message
                key = sample.payload().to_bytes().into_owned();
                println!(
                    ">> Received ('{}': '{:?}')",
                    sample.key_expr().as_str(),
                    key,
                );
            }
            Err(err) => {
                key = err.payload().to_bytes().into_owned();
                println!(">> Received (ERROR: '{:?}')", key);
            }
        }
    }

    let nonce = AsconAead128Nonce::from([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    println!("Secret key is: {:?}", &key);

    let key_array: [u8; 16] = key.try_into().unwrap();
    let cipher = AsconAead128::new(&key_array.into());

    println!("Declaring Subscriber on '{}'...", &key_expr);
    let subscriber = session.declare_subscriber(&key_expr).await.unwrap();

    println!("Press CTRL-C to quit...");
    while let Ok(sample) = subscriber.recv_async().await {
        // Refer to z_bytes.rs to see how to deserialize different types of message
        let payload = sample
            .payload()
            .try_to_string()
            .unwrap_or_else(|e| e.to_string().into());

        let payload_vec: Vec<u8> = sample.payload().to_bytes().into_owned();
        let payload_bytes: &[u8] = &payload_vec;
        println!("Received raw bytes length: {:?}", payload_bytes);

        match cipher.decrypt(&nonce, payload_bytes) {
            Ok(plaintext) => {
                let message = String::from_utf8_lossy(&plaintext);

                println!(
                    ">> [Subscriber] Received {} ('{}': '{}')",
                    sample.kind(),
                    sample.key_expr().as_str(),
                    message
                );
            }
            Err(e) => {
                eprintln!("Error decrypting: {}", e);
                println!("Raw payload (hex): {:x?}", payload_bytes);
            }
        }

        if let Some(att) = sample.attachment() {
            let att_bytes = att.to_bytes().into_owned();
            let att = String::from_utf8_lossy(&att_bytes);
            print!("({})", att)
        }
        println!();

        if let Some(att) = sample.attachment() {
            let att = att.try_to_string().unwrap_or_else(|e| e.to_string().into());
            print!(" ({att})");
        }
        println!();
    }
}

#[derive(clap::Parser, Clone, PartialEq, Eq, Hash, Debug)]
struct SubArgs {
    #[arg(short, long, default_value = "demo/secret")]
    /// The Key Expression to subscribe to.
    key: KeyExpr<'static>,
    #[command(flatten)]
    common: CommonArgs,
}

fn parse_args() -> (Config, KeyExpr<'static>) {
    let args = SubArgs::parse();
    (args.common.into(), args.key)
}
