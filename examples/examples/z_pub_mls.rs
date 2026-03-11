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
use std::time::Duration;

use clap::Parser;
use openmls::{
    group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig},
    prelude::{
        BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey, Extension,
        ExtensionType, Extensions, ExternalSender, KeyPackage, SenderRatchetConfiguration,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use zenoh::{bytes::Encoding, key_expr::KeyExpr, Config};
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

fn setup_mls_group(
    provider: OpenMlsRustCrypto,
    credential_with_key: CredentialWithKey,
    ciphersuite: Ciphersuite,
    signature_keys: SignatureKeyPair,
) {
    let mls_group_config = MlsGroupJoinConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .use_ratchet_tree_extension(true)
        .build();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(10)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .with_group_context_extensions(
            Extensions::single(Extension::ExternalSenders(vec![ExternalSender::new(
                credential_with_key.signature_key.clone(),
                credential_with_key.credential.clone(),
            )]))
            .expect("failed to create single-element extension list"),
        )
        .ciphersuite(ciphersuite)
        .capabilities(Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::Unknown(0xff00)]),
            None,
            Some(&[CredentialType::Basic]),
        ))
        .use_ratchet_tree_extension(true)
        .build();

    let mls_test_group = MlsGroup::new(
        &provider,
        &signature_keys,
        &mls_group_create_config,
        credential_with_key.clone(),
    )
    .expect("An unexpected error occurrred.");
}

fn setup_mls_user() {
    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let identity: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let credential = BasicCredential::new(identity);

    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("Error generating signature key pair");
    signature_keys.store(provider.storage()).unwrap();

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };

    let keypackage = KeyPackage::builder()
        .build(
            ciphersuite,
            &provider,
            &signature_keys,
            credential_with_key.clone(),
        )
        .unwrap();
}

fn add_member() {
    let a = 1;
}
