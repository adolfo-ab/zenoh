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
use std::{str::FromStr, time::Duration};

use ascon_aead128::{
    aead::{Aead, KeyInit},
    AsconAead128, AsconAead128Nonce,
};
use clap::Parser;
use zenoh::{bytes::Encoding, key_expr::KeyExpr, query::QueryTarget, Config};
use zenoh_examples::CommonArgs;

#[tokio::main]
async fn main() {
    // Initiate logging
    zenoh::init_log_from_env_or("error");

    let (config, key_expr, payload, attachment, add_matching_listener) = parse_args();

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
    let mut key = String::new();
    while let Ok(reply) = replies.recv_async().await {
        match reply.result() {
            Ok(sample) => {
                // Refer to z_bytes.rs to see how to deserialize different types of message
                key = sample
                    .payload()
                    .try_to_string()
                    .unwrap_or_else(|e| e.to_string().into())
                    .to_string();
                println!(">> Received ('{}': '{}')", sample.key_expr().as_str(), key,);
            }
            Err(err) => {
                key = err
                    .payload()
                    .try_to_string()
                    .unwrap_or_else(|e| e.to_string().into())
                    .to_string();
                println!(">> Received (ERROR: '{key}')");
            }
        }
    }

    let nonce = AsconAead128Nonce::from([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    println!("Secret key is: {:?}", &key);

    let key_array: [u8; 16] = key.as_bytes().try_into().unwrap();
    let cipher = AsconAead128::new(&key_array.into());

    let ciphertext = cipher
        .encrypt(&nonce, b"hi mum".as_ref())
        .expect("Failed to encrypt");
    println!("Encrypted message: {:?}", ciphertext);

    println!("Declaring Publisher on '{key_expr}'...");
    let publisher = session.declare_publisher(&key_expr).await.unwrap();

    if add_matching_listener {
        publisher
            .matching_listener()
            .callback(|matching_status| {
                if matching_status.matching() {
                    println!("Publisher has matching subscribers.");
                } else {
                    println!("Publisher has NO MORE matching subscribers.");
                }
            })
            .background()
            .await
            .unwrap();
    }

    println!("Press CTRL-C to quit...");
    println!("Putting Data ('{}': '{:?}')...", &key_expr, &ciphertext);
    // Refer to z_bytes.rs to see how to serialize different types of message
    publisher
        .put(ciphertext)
        .encoding(Encoding::TEXT_PLAIN) // Optionally set the encoding metadata 
        .attachment(attachment.clone()) // Optionally add an attachment
        .await
        .unwrap();
}

#[derive(clap::Parser, Clone, PartialEq, Eq, Hash, Debug)]
struct Args {
    #[arg(short, long, default_value = "demo/secret")]
    /// The key expression to write to.
    key: KeyExpr<'static>,
    #[arg(short, long, default_value = "Pub from Rust!")]
    /// The payload to write.
    payload: String,
    #[arg(short, long)]
    /// The attachments to add to each put.
    attach: Option<String>,
    /// Enable matching listener.
    #[arg(long)]
    add_matching_listener: bool,
    #[command(flatten)]
    common: CommonArgs,
}

fn parse_args() -> (Config, KeyExpr<'static>, String, Option<String>, bool) {
    let args = Args::parse();
    (
        args.common.into(),
        args.key,
        args.payload,
        args.attach,
        args.add_matching_listener,
    )
}
