use anyhow::{bail, Result};
use bip39::Mnemonic;
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::{rngs::OsRng, RngCore};
use slip10::{derive_key_from_path, BIP32Path, Curve};
use std::str::FromStr;

pub fn generate_mnemonic(c: usize) -> Result<String> {
    let byte_size = match c {
        12 => 16, // 128 位 = 16 字节
        24 => 32, // 256 位 = 32 字节
        _ => bail!("无效的助记词长度，必须是 12 或 24 个单词。"),
    };
    let mut random_bytes = vec![0u8; byte_size];
    OsRng.fill_bytes(&mut random_bytes);
    // 从随机字节生成助记词
    let mnemonic = Mnemonic::from_entropy(&random_bytes)?;
    // 确保生成的助记词的单词数正确
    if mnemonic.word_count() != c {
        bail!(
            "生成的助记词单词数量不正确。预期：{}，实际：{}",
            c,
            mnemonic.word_count()
        );
    }
    Ok(mnemonic.to_string())
}

fn get_seed(mne: &str, phrase: &str) -> Result<Vec<u8>> {
    let mnemonic = Mnemonic::parse(mne)?;
    Ok(mnemonic.to_seed(phrase).to_vec())
}

pub fn key_from_mne_ed25519(mne: &str, phrase: &str, index: usize) -> Result<(String, String)> {
    let path_buf = format!("m/44'/397'/{}'", index);
    // 解析助记词并生成主密钥种子
    let seed = get_seed(mne, phrase)?;
    // 解析BIP32路径
    let bip_path = BIP32Path::from_str(&path_buf).map_err(|e| anyhow::anyhow!(e))?;
    // 根据路径派生私钥
    let derived_private_key =
        derive_key_from_path(&seed, Curve::Ed25519, &bip_path).map_err(|e| anyhow::anyhow!(e))?;
    // 创建密钥对
    let secret_keypair = generate_keypair_from_private_key(&derived_private_key.key)?;
    // 生成公钥字符串
    let public_key_str = format!(
        "ed25519:{}",
        bs58::encode(secret_keypair.public).into_string()
    );
    // 生成私钥字符串
    let secret_keypair_str = format!(
        "ed25519:{}",
        bs58::encode(secret_keypair.to_bytes()).into_string()
    );

    Ok((public_key_str, secret_keypair_str))
}

// 从私钥字节生成密钥对的辅助函数
fn generate_keypair_from_private_key(private_key_bytes: &[u8]) -> Result<Keypair> {
    let secret = SecretKey::from_bytes(private_key_bytes)?;
    let public = PublicKey::from(&secret);
    Ok(Keypair { secret, public })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic(12).unwrap();
        println!("Mnemonic: {}", mnemonic.to_string());
    }
    #[test]
    fn test_get_key_with_mne_path() {
        for i in 0..10 {
            let s = key_from_mne_ed25519(
                "often toddler tobacco winter type analyst tourist dentist tackle arch trial fringe",
                "123456",i
            )
            .unwrap();
            println!("{:?}", s);
        }
    }
}
