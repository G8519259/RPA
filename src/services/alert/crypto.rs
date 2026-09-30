//! P13 —— 告警渠道密钥的 AES-256-GCM 加密（§14.2 密钥保护）。
//!
//! - 密钥来自 `config.toml [server] secret_key`（或环境变量 `RPA__SERVER__SECRET_KEY`），
//!   经 SHA-256 派生为 32 字节。
//! - 仅加密渠道配置 JSON 中的密钥字段：`bot_token`、`secret`、`password`。
//! - 密文格式：`enc:v1:` + base64(nonce(12) || ciphertext)，存回原字段。
//! - 未配置 secret_key 时保持明文（兼容旧库）；读取时自动识别 `enc:v1:` 前缀。

use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce};
use serde_json::Value;

/// 需要加密的渠道配置字段
pub const SECRET_FIELDS: &[&str] = &["bot_token", "secret", "password"];

/// 密文前缀
const PREFIX: &str = "enc:v1:";

pub fn key_bytes(secret: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(secret.as_bytes());
    h.finalize().into()
}

fn encrypt_str(plain: &str, key: &[u8; 32]) -> String {
    use aes_gcm::aead::rand_core::RngCore;
    let cipher = Aes256Gcm::new_from_slice(key).expect("key 长度固定 32");
    let mut nb = [0u8; 12];
    RngCore::fill_bytes(&mut OsRng, &mut nb);
    let nonce = Nonce::from_slice(&nb);
    let ct = cipher
        .encrypt(nonce, plain.as_bytes())
        .expect("AES-GCM 加密不应失败");
    let mut raw = Vec::with_capacity(12 + ct.len());
    raw.extend_from_slice(&nb);
    raw.extend_from_slice(&ct);
    format!("{PREFIX}{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw))
}

fn decrypt_str(enc: &str, key: &[u8; 32]) -> Option<String> {
    let b64 = enc.strip_prefix(PREFIX)?;
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).ok()?;
    if raw.len() < 13 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(&raw[..12]);
    let pt = cipher.decrypt(nonce, &raw[12..]).ok()?;
    String::from_utf8(pt).ok()
}

/// 写库前：把渠道配置中的密钥字段加密（未配置 secret_key 则原样返回）。
pub fn encrypt_config(cfg: &mut Value, secret_key: Option<&str>) {
    let Some(sk) = secret_key else { return };
    let key = key_bytes(sk);
    let Some(obj) = cfg.as_object_mut() else { return };
    for f in SECRET_FIELDS {
        if let Some(Value::String(s)) = obj.get(*f) {
            if !s.is_empty() && !s.starts_with(PREFIX) {
                obj.insert(f.to_string(), Value::String(encrypt_str(s, &key)));
            }
        }
    }
}

/// 读取后：把渠道配置中的 `enc:v1:` 密文解密（无密钥或解密失败则保持原样）。
pub fn decrypt_config(cfg: &Value, secret_key: Option<&str>) -> Value {
    let Some(sk) = secret_key else {
        return cfg.clone();
    };
    let key = key_bytes(sk);
    let mut out = cfg.clone();
    let Some(obj) = out.as_object_mut() else {
        return out;
    };
    for f in SECRET_FIELDS {
        if let Some(Value::String(s)) = obj.get(*f).cloned() {
            if s.starts_with(PREFIX) {
                if let Some(pt) = decrypt_str(&s, &key) {
                    obj.insert(f.to_string(), Value::String(pt));
                }
            }
        }
    }
    out
}

/// API 返回前对 admin 脱敏：密钥字段 → `******`。
pub fn mask_config(cfg: &mut Value) {
    let Some(obj) = cfg.as_object_mut() else { return };
    for f in SECRET_FIELDS {
        if let Some(Value::String(s)) = obj.get(*f) {
            if !s.is_empty() {
                obj.insert(f.to_string(), Value::String("******".to_string()));
            }
        }
    }
}

/// API 返回前对 viewer 隐藏：直接删除密钥字段。
pub fn strip_secrets(cfg: &mut Value) {
    let Some(obj) = cfg.as_object_mut() else { return };
    for f in SECRET_FIELDS {
        obj.remove(*f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = key_bytes("test-secret-key");
        let c = encrypt_str("hello-token", &key);
        assert!(c.starts_with(PREFIX));
        assert_eq!(decrypt_str(&c, &key).as_deref(), Some("hello-token"));
        // 换密钥解不开
        assert!(decrypt_str(&c, &key_bytes("other")).is_none());
    }

    #[test]
    fn config_roundtrip() {
        let mut cfg = serde_json::json!({"bot_token": "abc123", "chat_id": "-1001"});
        encrypt_config(&mut cfg, Some("sk"));
        assert!(cfg["bot_token"].as_str().unwrap().starts_with(PREFIX));
        assert_eq!(cfg["chat_id"].as_str().unwrap(), "-1001");
        let dec = decrypt_config(&cfg, Some("sk"));
        assert_eq!(dec["bot_token"].as_str().unwrap(), "abc123");
        // 不加密（无密钥）时原样
        let mut cfg2 = serde_json::json!({"secret": "s3"});
        encrypt_config(&mut cfg2, None);
        assert_eq!(cfg2["secret"].as_str().unwrap(), "s3");
    }
}
