use base64::{Engine as _, engine::general_purpose::STANDARD};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};
use thiserror::Error;
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// A fresh receiver keypair. The private serialization is erased on drop.
pub(crate) struct ServerKeyPair {
    pub(crate) private_key: Zeroizing<Vec<u8>>,
    pub(crate) public_key: Vec<u8>,
}

/// One HPKE base-mode ciphertext and the encapsulated key needed to open it.
pub(crate) struct SealedProviderSecret {
    pub(crate) encapsulated_key: Vec<u8>,
    pub(crate) ciphertext: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Error)]
pub(crate) enum ProviderSecretCryptoError {
    #[error("the provider-secret recipient public key is invalid")]
    InvalidRecipientPublicKey,
    #[error("the provider-secret recipient private key is invalid")]
    InvalidRecipientPrivateKey,
    #[error("the provider-secret encapsulated key is invalid")]
    InvalidEncapsulatedKey,
    #[error("provider-secret encryption failed")]
    EncryptionFailed,
    #[error("provider-secret decryption failed")]
    DecryptionFailed,
    #[error("the provider-secret wire value is not canonical base64")]
    InvalidBase64,
}

/// Generates an RFC 9180 DHKEM(X25519, HKDF-SHA256) receiver keypair.
pub(crate) fn generate_server_keypair() -> ServerKeyPair {
    let (private_key, public_key) = Kem::gen_keypair();

    // Avoid a second, non-zeroizing serialization of private key material.
    let mut private_key_bytes = Zeroizing::new(vec![
        0;
        <<Kem as KemTrait>::PrivateKey as Serializable>::size()
    ]);
    private_key.write_exact(private_key_bytes.as_mut_slice());

    let mut public_key_bytes = vec![0; <<Kem as KemTrait>::PublicKey as Serializable>::size()];
    public_key.write_exact(public_key_bytes.as_mut_slice());

    ServerKeyPair {
        private_key: private_key_bytes,
        public_key: public_key_bytes,
    }
}

/// Encrypts a secret with RFC 9180 base mode and the caller's canonical AAD.
///
/// The caller retains ownership of `plaintext` and is responsible for erasing
/// that input. The returned ciphertext buffer is erased on drop.
pub(crate) fn encrypt_provider_secret(
    recipient_public_key: &[u8],
    info: &[u8],
    canonical_aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedProviderSecret, ProviderSecretCryptoError> {
    let public_key = <Kem as KemTrait>::PublicKey::from_bytes(recipient_public_key)
        .map_err(|_| ProviderSecretCryptoError::InvalidRecipientPublicKey)?;
    let (encapsulated_key, ciphertext) = single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &public_key,
        info,
        plaintext,
        canonical_aad,
    )
    .map_err(|_| ProviderSecretCryptoError::EncryptionFailed)?;

    let mut encapsulated_key_bytes =
        vec![0; <<Kem as KemTrait>::EncappedKey as Serializable>::size()];
    encapsulated_key.write_exact(encapsulated_key_bytes.as_mut_slice());

    Ok(SealedProviderSecret {
        encapsulated_key: encapsulated_key_bytes,
        ciphertext: Zeroizing::new(ciphertext),
    })
}

/// Opens an RFC 9180 base-mode ciphertext with the caller's canonical AAD.
pub(crate) fn decrypt_provider_secret(
    recipient_private_key: &[u8],
    info: &[u8],
    canonical_aad: &[u8],
    encapsulated_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProviderSecretCryptoError> {
    let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(recipient_private_key)
        .map_err(|_| ProviderSecretCryptoError::InvalidRecipientPrivateKey)?;
    let encapsulated_key = <Kem as KemTrait>::EncappedKey::from_bytes(encapsulated_key)
        .map_err(|_| ProviderSecretCryptoError::InvalidEncapsulatedKey)?;

    single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encapsulated_key,
        info,
        ciphertext,
        canonical_aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| ProviderSecretCryptoError::DecryptionFailed)
}

/// Encodes one wire field with the padded RFC 4648 standard alphabet.
pub(crate) fn encode_canonical_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes only padded, canonical RFC 4648 standard-base64 wire values.
pub(crate) fn decode_canonical_base64(
    value: &str,
) -> Result<Zeroizing<Vec<u8>>, ProviderSecretCryptoError> {
    let decoded = STANDARD
        .decode(value.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| ProviderSecretCryptoError::InvalidBase64)?;
    if STANDARD.encode(decoded.as_slice()) != value {
        return Err(ProviderSecretCryptoError::InvalidBase64);
    }
    Ok(decoded)
}
