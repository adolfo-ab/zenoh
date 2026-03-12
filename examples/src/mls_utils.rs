use openmls::{
    group::{MlsGroup, MlsGroupCreateConfig},
    prelude::{
        BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey, Extension,
        ExtensionType, Extensions, ExternalSender, KeyPackage, KeyPackageBundle,
        SenderRatchetConfiguration,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub fn create_mls_group(
    provider: OpenMlsRustCrypto,
    credential_with_key: CredentialWithKey,
    signature_keys: SignatureKeyPair,
) -> MlsGroup {
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
        .ciphersuite(CIPHERSUITE)
        .capabilities(Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::Unknown(0xff00)]),
            None,
            Some(&[CredentialType::Basic]),
        ))
        .use_ratchet_tree_extension(true)
        .build();

    let mls_group = MlsGroup::new(
        &provider,
        &signature_keys,
        &mls_group_create_config,
        credential_with_key.clone(),
    )
    .expect("An unexpected error occurrred.");

    return mls_group;
}

pub fn create_mls_client(
    provider: OpenMlsRustCrypto,
    identity: Vec<u8>,
) -> (SignatureKeyPair, KeyPackageBundle) {
    let credential = BasicCredential::new(identity);

    let signature_keys = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .expect("Error generating signature key pair");
    signature_keys.store(provider.storage()).unwrap();

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };

    let keypackage = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &provider,
            &signature_keys,
            credential_with_key.clone(),
        )
        .unwrap();

    return (signature_keys, keypackage);
}
