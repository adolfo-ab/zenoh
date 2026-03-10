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
    AsconAead128, AsconAead128Key, AsconAead128Nonce,
};
use clap::Parser;
use zenoh::{
    bytes::{Encoding, ZBytes},
    key_expr::KeyExpr,
    Config,
};
use zenoh_examples::CommonArgs;
#[tokio::main]
async fn main() {
    // Initiate logging
    zenoh::init_log_from_env_or("error");

    let (config, key_expr, payload, attachment, add_matching_listener) = parse_args();

    println!("Opening session...");
    let session = zenoh::open(config).await.unwrap();

    println!("Declaring Publisher on '{key_expr}'...");
    let publisher = session.declare_publisher(&key_expr).await.unwrap();

    println!("Generating secret key...");
    let my_secret = b"ilovetorrijas";
    let key_bytes: [u8; 16] = {
        let mut buf = [0u8; 16];
        buf[..my_secret.len()].copy_from_slice(my_secret);
        buf
    };

    let key = ZBytes::from(key_bytes);
    let nonce = AsconAead128Nonce::from([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    println!("Secret key is: {:?}", &key);
    /*
    let cipher = AsconAead128::new(&key);

    let ciphertext = cipher
        .encrypt(&nonce, b"hi mum", payload.as_ref())
        .expect("Failed to encrypt");
    println!("Encrypted message: {:?}", ciphertext);

    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("Error decrypting message");
    println!(
        "Decrypted message: {:?}",
        String::from_utf8(plaintext).unwrap()
    );
    */

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

    publisher
        .put(key.clone())
        .encoding(Encoding::TEXT_PLAIN) // Optionally set the encoding metadata 
        .attachment(attachment.clone()) // Optionally add an attachment
        .await
        .unwrap();

    println!("Successfully published secret key: {:?}", &key)
}

#[derive(clap::Parser, Clone, PartialEq, Eq, Hash, Debug)]
struct Args {
    #[arg(short, long, default_value = "demo/example/zenoh-rs-pub")]
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
        KeyExpr::from_str("demo/keys").unwrap(),
        args.payload,
        args.attach,
        args.add_matching_listener,
    )
}
