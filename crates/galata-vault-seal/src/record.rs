//! Writing and reading signed records: the one place a record is
//! sealed and signed, and the one place it is verified and opened.
//!
//! Write: seal the value to the descriptor's key, encrypt the name under the
//! name key, sign the record context with the generation's writer key for the
//! kind. Read: verify the signature against the descriptor's writer key
//! (without decrypting), then decrypt the name and the value and check every
//! binding against the signed context and what the server reported.

use galata_vault_keys::{ConfigSecret, NameContext, NameKey, VaultSecret, WriterKey};
use galata_vault_proto::api::{
    DeleteRecordRequest, PutSecretRequest, SecretListItem, SecretVersion, VersionMeta,
};
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::{B64, Hash32, Key32, NameHmac, Sig64};
use galata_vault_proto::integrity::IntegrityError;
use galata_vault_proto::record::{RecordContext, RecordKind};
use zeroize::Zeroizing;

use crate::SealError;
use crate::envelope::{
    ConfigFormat, EnvelopeContext, open_config, open_value, seal_config, seal_value,
};

/// A record ready to send: a write, or a tombstone (`value_ct = None`).
#[derive(Debug, Clone)]
pub struct WrittenRecord {
    pub kind: RecordKind,
    pub name_hmac: NameHmac,
    pub name_ct: Vec<u8>,
    pub value_ct: Option<Vec<u8>>,
    pub generation: u32,
    pub version: u64,
    pub written_at: i64,
    pub sig: Sig64,
}

impl WrittenRecord {
    /// The `PUT` body. `None` for a tombstone.
    pub fn put_request(&self) -> Option<PutSecretRequest> {
        Some(PutSecretRequest::new(
            B64(self.name_ct.clone()),
            B64(self.value_ct.clone()?),
            self.generation,
            self.version,
            self.written_at,
            self.sig,
        ))
    }

    /// The `DELETE` body. `None` unless this is a tombstone.
    pub fn delete_request(&self) -> Option<DeleteRecordRequest> {
        self.value_ct.is_none().then(|| {
            DeleteRecordRequest::new(
                B64(self.name_ct.clone()),
                self.generation,
                self.version,
                self.written_at,
                self.sig,
            )
        })
    }
}

/// What a writer needs: the verified descriptor, the generation's name key,
/// and the writer key for the kind. The writer key must be the one the
/// descriptor names.
pub struct Writer<'a> {
    pub descriptor: &'a Descriptor,
    pub name_key: &'a NameKey,
    pub writer: &'a WriterKey,
}

/// The key that verifies `kind`'s records in `descriptor`'s generation. A
/// kind this build does not know has none: nothing is signed or trusted.
fn writer_pub(descriptor: &Descriptor, kind: RecordKind) -> Result<&Key32, SealError> {
    match kind {
        RecordKind::Secret => Ok(&descriptor.secret_writer_pub),
        RecordKind::Config => Ok(&descriptor.config_writer_pub),
        other => Err(SealError::UnsupportedByClient(format!(
            "record kind {} is not one this client knows",
            other.code()
        ))),
    }
}

impl Writer<'_> {
    fn check(&self, kind: RecordKind) -> Result<(), SealError> {
        if self.writer.public() != *writer_pub(self.descriptor, kind)? {
            return Err(IntegrityError::KeyMismatch("writer key").into());
        }
        Ok(())
    }

    fn name_ctx(&self, kind: RecordKind) -> NameContext {
        NameContext {
            vault_id: self.descriptor.vault_id,
            generation: self.descriptor.generation,
            kind,
        }
    }

    fn envelope_ctx(&self, version: u64, written_at: i64) -> EnvelopeContext {
        EnvelopeContext {
            vault_id: self.descriptor.vault_id,
            generation: self.descriptor.generation,
            version,
            written_at,
        }
    }

    fn finish(
        &self,
        kind: RecordKind,
        name: &str,
        value_ct: Option<Vec<u8>>,
        version: u64,
        written_at: i64,
    ) -> Result<WrittenRecord, SealError> {
        let name_hmac = self.name_key.index(kind, name);
        let name_ct = self.name_key.encrypt_name(&self.name_ctx(kind), name)?;
        let ctx = RecordContext::new(
            self.descriptor.vault_id,
            self.descriptor.generation,
            kind,
            name_hmac,
            version,
            written_at,
            &name_ct,
            value_ct.as_deref(),
        );
        Ok(WrittenRecord {
            kind,
            name_hmac,
            name_ct,
            value_ct,
            generation: self.descriptor.generation,
            version,
            written_at,
            sig: self.writer.sign(&ctx),
        })
    }

    /// Seal and sign a secret as `version`.
    pub fn secret(
        &self,
        name: &str,
        value: &[u8],
        version: u64,
        written_at: i64,
    ) -> Result<WrittenRecord, SealError> {
        self.check(RecordKind::Secret)?;
        let ct = seal_value(
            &self.descriptor.vault_pub,
            &self.envelope_ctx(version, written_at),
            name,
            value,
        )?;
        self.finish(RecordKind::Secret, name, Some(ct), version, written_at)
    }

    /// Seal and sign a config document as `version`.
    pub fn config(
        &self,
        name: &str,
        format: ConfigFormat,
        body: &[u8],
        version: u64,
        written_at: i64,
    ) -> Result<WrittenRecord, SealError> {
        self.check(RecordKind::Config)?;
        let ct = seal_config(
            &self.descriptor.config_pub,
            &self.envelope_ctx(version, written_at),
            name,
            format,
            body,
        )?;
        self.finish(RecordKind::Config, name, Some(ct), version, written_at)
    }

    /// Sign a tombstone as `version`.
    pub fn tombstone(
        &self,
        kind: RecordKind,
        name: &str,
        version: u64,
        written_at: i64,
    ) -> Result<WrittenRecord, SealError> {
        self.check(kind)?;
        self.finish(kind, name, None, version, written_at)
    }
}

fn check_generation(descriptor: &Descriptor, generation: u32) -> Result<(), SealError> {
    if generation != descriptor.generation {
        return Err(SealError::StaleGeneration {
            bundle: descriptor.generation,
            vault: generation,
        });
    }
    Ok(())
}

/// Verify a full record's signature against the descriptor, without decrypting.
pub fn verify_version(
    descriptor: &Descriptor,
    kind: RecordKind,
    v: &SecretVersion,
) -> Result<(), SealError> {
    check_generation(descriptor, v.generation)?;
    if v.tombstone != v.value_ct.is_none() {
        return Err(IntegrityError::BindingMismatch("tombstone flag").into());
    }
    let ctx = RecordContext::new(
        descriptor.vault_id,
        v.generation,
        kind,
        v.name_hmac,
        v.version,
        v.written_at,
        &v.name_ct.0,
        v.value_ct.as_ref().map(|c| &c.0[..]),
    );
    ctx.verify(writer_pub(descriptor, kind)?, &v.sig)?;
    Ok(())
}

/// Verify a listed record's signature, from its hashes, without its value.
pub fn verify_listed(
    descriptor: &Descriptor,
    kind: RecordKind,
    item: &SecretListItem,
) -> Result<(), SealError> {
    check_generation(descriptor, item.generation)?;
    let ctx = RecordContext {
        vault_id: descriptor.vault_id,
        generation: item.generation,
        kind,
        name_index: item.name_hmac,
        version: item.version,
        written_at: item.written_at,
        tombstone: item.tombstone,
        value_ct_hash: item.value_ct_hash,
        name_ct_hash: Hash32::sha256(&item.name_ct.0),
    };
    ctx.verify(writer_pub(descriptor, kind)?, &item.sig)?;
    Ok(())
}

/// Verify one entry of a version history, from its hashes.
pub fn verify_meta(
    descriptor: &Descriptor,
    kind: RecordKind,
    name_hmac: &NameHmac,
    m: &VersionMeta,
) -> Result<(), SealError> {
    check_generation(descriptor, m.generation)?;
    let ctx = RecordContext {
        vault_id: descriptor.vault_id,
        generation: m.generation,
        kind,
        name_index: *name_hmac,
        version: m.version,
        written_at: m.written_at,
        tombstone: m.tombstone,
        value_ct_hash: m.value_ct_hash,
        name_ct_hash: m.name_ct_hash,
    };
    ctx.verify(writer_pub(descriptor, kind)?, &m.sig)?;
    Ok(())
}

/// Decrypt a verified record's name and check it against its index.
pub fn open_name(
    descriptor: &Descriptor,
    name_key: &NameKey,
    kind: RecordKind,
    name_hmac: &NameHmac,
    name_ct: &[u8],
) -> Result<String, SealError> {
    let ctx = NameContext {
        vault_id: descriptor.vault_id,
        generation: descriptor.generation,
        kind,
    };
    Ok(name_key.open_name(&ctx, name_hmac, name_ct)?)
}

/// A verified, opened record. `value` is `None` for a tombstone.
pub struct OpenedRecord {
    pub name: String,
    pub version: u64,
    pub written_at: i64,
    pub format: Option<ConfigFormat>,
    pub value: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for OpenedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedRecord")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("written_at", &self.written_at)
            .field("format", &self.format)
            .field(
                "value",
                &self.value.as_ref().map(|v| format!("<{} bytes>", v.len())),
            )
            .finish()
    }
}

fn envelope_ctx(descriptor: &Descriptor, v: &SecretVersion) -> EnvelopeContext {
    EnvelopeContext {
        vault_id: descriptor.vault_id,
        generation: v.generation,
        version: v.version,
        written_at: v.written_at,
    }
}

/// Verify and open a secret record.
pub fn open_secret(
    descriptor: &Descriptor,
    name_key: &NameKey,
    vault_secret: &VaultSecret,
    v: &SecretVersion,
) -> Result<OpenedRecord, SealError> {
    verify_version(descriptor, RecordKind::Secret, v)?;
    let name = open_name(
        descriptor,
        name_key,
        RecordKind::Secret,
        &v.name_hmac,
        &v.name_ct.0,
    )?;
    let value = match &v.value_ct {
        None => None,
        Some(ct) => {
            Some(open_value(vault_secret, &envelope_ctx(descriptor, v), &name, &ct.0)?.value)
        }
    };
    Ok(OpenedRecord {
        name,
        version: v.version,
        written_at: v.written_at,
        format: None,
        value,
    })
}

/// Verify and open a config record.
pub fn open_config_record(
    descriptor: &Descriptor,
    name_key: &NameKey,
    config_secret: &ConfigSecret,
    v: &SecretVersion,
) -> Result<OpenedRecord, SealError> {
    verify_version(descriptor, RecordKind::Config, v)?;
    let name = open_name(
        descriptor,
        name_key,
        RecordKind::Config,
        &v.name_hmac,
        &v.name_ct.0,
    )?;
    let (format, value) = match &v.value_ct {
        None => (None, None),
        Some(ct) => {
            let opened = open_config(config_secret, &envelope_ctx(descriptor, v), &name, &ct.0)?;
            (Some(opened.format), Some(opened.body))
        }
    };
    Ok(OpenedRecord {
        name,
        version: v.version,
        written_at: v.written_at,
        format,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use galata_vault_keys::{FullBundle, NodeKey};
    use galata_vault_proto::audit::Actor;

    fn as_version(w: &WrittenRecord) -> SecretVersion {
        SecretVersion::new(
            w.name_hmac,
            w.version,
            B64(w.name_ct.clone()),
            w.value_ct.clone().map(B64),
            w.generation,
            w.written_at,
            Actor::Owner,
            w.value_ct.is_none(),
            w.sig,
        )
    }

    fn setup() -> (FullBundle, Descriptor) {
        let owner = NodeKey::generate().owner();
        let full = FullBundle::generate(1);
        let d = full.descriptor(owner.vault_id(), Hash32([0; 32]), 0);
        (full, d)
    }

    #[test]
    fn a_written_secret_verifies_and_opens() {
        let (full, d) = setup();
        let w = Writer {
            descriptor: &d,
            name_key: &full.name_key,
            writer: &full.secret_writer,
        };
        let rec = w.secret("DB", b"postgres://x", 1, 100).unwrap();
        let opened =
            open_secret(&d, &full.name_key, &full.vault_secret, &as_version(&rec)).unwrap();
        assert_eq!(opened.name, "DB");
        assert_eq!(opened.value.unwrap().as_slice(), b"postgres://x");
    }

    #[test]
    fn a_config_writer_cannot_write_a_secret() {
        let (full, d) = setup();
        let w = Writer {
            descriptor: &d,
            name_key: &full.name_key,
            writer: &full.config_writer,
        };
        assert!(w.secret("DB", b"x", 1, 0).is_err());
        assert!(w.config("app", ConfigFormat::Toml, b"a=1", 1, 0).is_ok());
    }

    #[test]
    fn forged_moved_and_rolled_back_records_are_refused() {
        let (full, d) = setup();
        let w = Writer {
            descriptor: &d,
            name_key: &full.name_key,
            writer: &full.secret_writer,
        };
        let good = as_version(&w.secret("DB", b"v2", 2, 100).unwrap());
        // Signed by a key the descriptor does not name.
        let rogue = WriterKey::generate();
        let forged = {
            let mut v = good.clone();
            let ctx = RecordContext::new(
                d.vault_id,
                1,
                RecordKind::Secret,
                v.name_hmac,
                2,
                100,
                &v.name_ct.0,
                v.value_ct.as_ref().map(|c| &c.0[..]),
            );
            v.sig = rogue.sign(&ctx);
            v
        };
        assert!(verify_version(&d, RecordKind::Secret, &forged).is_err());
        // The server reports a different version than was signed.
        let renumbered = {
            let mut patched = good.clone();
            patched.version = 1;
            patched
        };
        assert!(verify_version(&d, RecordKind::Secret, &renumbered).is_err());
        // Presented as a config.
        assert!(verify_version(&d, RecordKind::Config, &good).is_err());
        // A tombstone flag that does not match the value.
        let flipped = {
            let mut patched = good.clone();
            patched.tombstone = true;
            patched
        };
        assert!(verify_version(&d, RecordKind::Secret, &flipped).is_err());
    }

    #[test]
    fn tombstones_and_listings_verify_without_decrypting() {
        let (full, d) = setup();
        let w = Writer {
            descriptor: &d,
            name_key: &full.name_key,
            writer: &full.secret_writer,
        };
        let t = w.tombstone(RecordKind::Secret, "OLD", 3, 5).unwrap();
        assert!(t.put_request().is_none());
        let v = as_version(&t);
        verify_version(&d, RecordKind::Secret, &v).unwrap();
        let rec = w.secret("DB", b"x", 1, 0).unwrap();
        let item = SecretListItem::new(
            rec.name_hmac,
            B64(rec.name_ct.clone()),
            1,
            0,
            0,
            false,
            1,
            Hash32::sha256(rec.value_ct.as_ref().unwrap()),
            rec.sig,
        );
        verify_listed(&d, RecordKind::Secret, &item).unwrap();
        let bad = {
            let mut patched = item;
            patched.value_ct_hash = Hash32([0; 32]);
            patched
        };
        assert!(verify_listed(&d, RecordKind::Secret, &bad).is_err());
    }
}
