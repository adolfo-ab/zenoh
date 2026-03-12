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

use clap::Parser;

use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Serialize;
use zenoh::{bytes::Encoding, key_expr::KeyExpr, open, Config};
use zenoh_examples::{mls_utils::create_mls_client, CommonArgs};

#[tokio::main]
async fn main() {
    // Initiate logging
    zenoh::init_log_from_env_or("error");

    let (config, key_expr, payload, attachment, add_matching_listener) = parse_args();

    println!("Opening session...");
    let session = zenoh::open(config).await.unwrap();

    // Put the keys into the KeyPackage storage
    let provider = OpenMlsRustCrypto::default();
    let identity = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let (signature_keys, keypackage) = create_mls_client(provider, identity);
    let keypackage_bytes = keypackage.key_package().tls_serialize_detached().unwrap();

    let openmls_keypackage_keyexpr = KeyExpr::from_str("mls/keypackages").unwrap();

    session
        .put(&openmls_keypackage_keyexpr, keypackage_bytes)
        .await
        .unwrap();

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
    for idx in 0..u32::MAX {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let buf = format!("[{idx:4}] {payload}");
        println!("Putting Data ('{}': '{}')...", &key_expr, buf);
        // Refer to z_bytes.rs to see how to serialize different types of message
        publisher
            .put(buf)
            .encoding(Encoding::TEXT_PLAIN) // Optionally set the encoding metadata 
            .attachment(attachment.clone()) // Optionally add an attachment
            .await
            .unwrap();
    }
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
        args.key,
        args.payload,
        args.attach,
        args.add_matching_listener,
    )
}
