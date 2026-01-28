use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use tor_hscrypto::pk::HsIdKeypair;
use tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use zeroize::Zeroize;

/// Derive an `HsIdKeypair` from a BIP-39 mnemonic.
pub fn hsid_from_mnemonic(phrase: &str, passphrase: &str) -> Result<HsIdKeypair> {
    let mnemonic =
        Mnemonic::parse_in(Language::English, phrase).context("Invalid mnemonic phrase")?;

    let mut seed: [u8; 64] = mnemonic.to_seed(passphrase);

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&seed[..32]);

    let keypair = Keypair::from_bytes(&secret_bytes);
    let hs_keypair = HsIdKeypair::from(ExpandedKeypair::from(&keypair));

    secret_bytes.zeroize();
    seed.zeroize();

    Ok(hs_keypair)
}

/// Prompt user for a mnemonic (hidden input) and derive the HSID keypair.
pub fn hsid_from_user_mnemonic() -> Result<HsIdKeypair> {
    eprintln!("Enter mnemonic phrase (hidden):");
    let phrase = SecretString::new(
        read_password()
            .context("Failed to read mnemonic phrase")?
            .into(),
    );

    eprintln!("Enter optional BIP-39 passphrase (hidden, press Enter for none):");
    let passphrase = SecretString::new(
        read_password()
            .context("Failed to read passphrase")?
            .into(),
    );

    // Use only a borrowed reference; SecretString zeroizes on drop.
    hsid_from_mnemonic(phrase.expose_secret(), passphrase.expose_secret())
}
