//! `galata_vault._native`: the Python binding of the `galata-vault` SDK, and
//! the bundled `gv` command. Every vault operation is the SDK's public API,
//! so Python and Rust share one client and one table of error codes. There
//! is no second implementation of any format, signature or check.
//!
//! Every failure is raised as `NativeError(kind, code, message)`: the code
//! is the SDK's, the kind comes from the SDK's `kind_of`, and the Python
//! layer maps the kind to its exception classes (`integrity` included).
//! Messages are the SDK's allow-listed ones: never a token, a key, a value or
//! a config body.
//!
//! Network calls release the GIL, and the SDK's `Vault` is `Send + Sync`, so
//! a `Vault` may be shared between threads. Expiry is data here (the SDK's
//! `Vault::expiry()`), and the Python layer decides when to warn.

use std::path::PathBuf;

use galata_vault::{ChainHead, ConfigFormat, EXPIRY_WARNING_SECS, Error, NewConfig, Vault, code};
use galata_vault_proto::ids::Hash32;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

create_exception!(
    _native,
    NativeError,
    PyException,
    "A galata-vault failure: args are (kind, code, message)."
);

fn native_error(kind: &str, code: &str, message: String) -> PyErr {
    NativeError::new_err((kind.to_owned(), code.to_owned(), message))
}

fn raise(e: Error) -> PyErr {
    native_error(e.kind().as_str(), e.code(), e.message().to_owned())
}

/// An audit head is opaque to Python: `"<seq>:<hash hex>"`.
fn head_to_str(head: ChainHead) -> String {
    format!("{}:{}", head.seq, head.hash.to_hex())
}

fn head_from_str(s: &str) -> PyResult<ChainHead> {
    let bad = || {
        native_error(
            "invalid",
            code::INVALID_AUDIT_HEAD,
            "not an audit head returned by verify_audit".to_owned(),
        )
    };
    let (seq, hash) = s.split_once(':').ok_or_else(bad)?;
    Ok(ChainHead::new(
        seq.parse().map_err(|_| bad())?,
        Hash32::from_hex(hash).map_err(|_| bad())?,
    ))
}

/// One vault, opened with a token.
#[pyclass(name = "Vault", module = "galata_vault._native", frozen)]
struct PyVault {
    inner: Vault,
}

#[pymethods]
impl PyVault {
    #[new]
    fn new(py: Python<'_>, token: &str, server: &str) -> PyResult<Self> {
        let token = Zeroizing::new(token.to_owned());
        let server = server.to_owned();
        let inner = py.detach(|| Vault::new(&token, &server)).map_err(raise)?;
        Ok(PyVault { inner })
    }

    /// Open the vault of the token in `path`: mode 0600 or 0400, checked
    /// before the file is read, and exactly one token.
    #[staticmethod]
    fn from_token_file(py: Python<'_>, path: PathBuf, server: &str) -> PyResult<Self> {
        let server = server.to_owned();
        let inner = py
            .detach(move || Vault::from_token_file(&path, &server))
            .map_err(raise)?;
        Ok(PyVault { inner })
    }

    /// meta, append, read, admin, config or config-write.
    #[getter]
    fn scope(&self) -> String {
        self.inner.scope().to_string()
    }

    #[getter]
    fn vault_id(&self) -> String {
        self.inner.vault_id()
    }

    /// The vault expiry the server reported on the latest response (Unix
    /// seconds).
    #[getter]
    fn last_expires_at(&self) -> Option<i64> {
        self.inner.expiry().vault_expires_at
    }

    #[pyo3(signature = (name, version=None))]
    fn get_bytes<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        version: Option<u64>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let value = py
            .detach(|| match version {
                None => self.inner.secret(name),
                Some(v) => self.inner.secret_version(name, v),
            })
            .map_err(raise)?;
        Ok(PyBytes::new(py, value.expose()))
    }

    /// `(name, version, updated_at, size)` for every live user secret.
    fn list(&self, py: Python<'_>) -> PyResult<Vec<(String, u64, i64, u32)>> {
        let entries = py.detach(|| self.inner.list()).map_err(raise)?;
        Ok(entries
            .into_iter()
            .map(|e| (e.name, e.version, e.updated_at, e.size))
            .collect())
    }

    /// Create or update `name`; returns the new version.
    fn set(&self, py: Python<'_>, name: &str, value: &[u8]) -> PyResult<u64> {
        let value = Zeroizing::new(value.to_vec());
        py.detach(|| self.inner.set_secret(name, &value))
            .map_err(raise)
    }

    /// `(name, value)` for every live secret this token may read, or just
    /// `only` (each of which must exist). Every value is verified.
    #[pyo3(signature = (only=None))]
    fn load_items<'py>(
        &self,
        py: Python<'py>,
        only: Option<Vec<String>>,
    ) -> PyResult<Vec<(String, Bound<'py, PyBytes>)>> {
        // The SDK's readable set: all or nothing.
        let set = py
            .detach(move || {
                let only: Option<Vec<&str>> = only
                    .as_ref()
                    .map(|o| o.iter().map(String::as_str).collect());
                self.inner.readable(only.as_deref())
            })
            .map_err(raise)?;
        Ok(set
            .iter()
            .map(|v| (v.name().to_owned(), PyBytes::new(py, v.expose())))
            .collect())
    }

    /// `(name, version, format, body)` of a config document.
    #[pyo3(signature = (name, version=None))]
    fn get_config<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        version: Option<u64>,
    ) -> PyResult<(String, u64, &'static str, Bound<'py, PyBytes>)> {
        let doc = py
            .detach(|| match version {
                None => self.inner.config(name),
                Some(v) => self.inner.config_version(name, v),
            })
            .map_err(raise)?;
        Ok((
            doc.name().to_owned(),
            doc.version(),
            doc.format().as_str(),
            PyBytes::new(py, doc.expose()),
        ))
    }

    /// `(name, version, updated_at, size)` for every live config.
    fn list_configs(&self, py: Python<'_>) -> PyResult<Vec<(String, u64, i64, u32)>> {
        let entries = py.detach(|| self.inner.list_configs()).map_err(raise)?;
        Ok(entries
            .into_iter()
            .map(|e| (e.name, e.version, e.updated_at, e.size))
            .collect())
    }

    /// Write config `name`; returns the new version. The SDK checks the
    /// body's format and refuses credential literals before any request.
    // One parameter per Python keyword argument.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (name, body, format, allow_literals=false, expect_version=None, expect_absent=false))]
    fn set_config(
        &self,
        py: Python<'_>,
        name: &str,
        body: &[u8],
        format: &str,
        allow_literals: bool,
        expect_version: Option<u64>,
        expect_absent: bool,
    ) -> PyResult<u64> {
        let format = ConfigFormat::parse(format).ok_or_else(|| {
            native_error(
                "invalid",
                code::UNSUPPORTED_FORMAT,
                format!("{format:?} is not a config format; use toml, json, yaml or text"),
            )
        })?;
        let mut config = NewConfig::new(format, body.to_vec());
        if allow_literals {
            config = config.allow_literals();
        }
        if expect_absent {
            config = config.expect_absent();
        }
        if let Some(v) = expect_version {
            config = config.expect_version(v);
        }
        py.detach(|| self.inner.set_config(name, config))
            .map_err(raise)
    }

    /// Verify the vault's audit chain, from `known` (a head an earlier call
    /// returned) or from the first row served. Returns the new head, opaque,
    /// and, when the chain continues in a row format this build does not
    /// know, `(first unverifiable seq, its format)`; the Python wrapper
    /// warns about it.
    #[pyo3(signature = (known=None))]
    #[allow(clippy::type_complexity)]
    fn verify_audit(
        &self,
        py: Python<'_>,
        known: Option<&str>,
    ) -> PyResult<(Option<String>, Option<(Option<u64>, u64)>)> {
        let known = known.map(head_from_str).transpose()?;
        let report = py
            .detach(|| self.inner.verify_audit(known))
            .map_err(raise)?;
        Ok((
            report.head.map(head_to_str),
            report.unverifiable.map(|u| (u.from_seq, u.format)),
        ))
    }

    fn __repr__(&self) -> String {
        format!(
            "<galata_vault._native.Vault scope={} vault_id={}>",
            self.scope(),
            self.vault_id()
        )
    }
}

/// Private and unsupported: run one protocol test-vector case with this
/// wheel's Rust code, returning what it observed as JSON
/// (`docs/spec/README.md#5`). Pure: no key is held, nothing is read or
/// written.
#[pyfunction]
fn _vectors_run(construct: &str, case: &str) -> PyResult<String> {
    let case: serde_json::Value = serde_json::from_str(case)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(galata_vault::__vectors::run(construct, &case).to_string())
}

/// Run the `gv` command with `args` (the first is the program name);
/// returns its exit status.
#[pyfunction]
fn run_cli(py: Python<'_>, args: Vec<String>) -> u8 {
    py.detach(|| galata_vault_cli::run(args))
}

#[pymodule]
#[pyo3(name = "_native")]
fn native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("EXPIRY_WARNING_SECS", EXPIRY_WARNING_SECS)?;
    m.add("NativeError", m.py().get_type::<NativeError>())?;
    m.add_class::<PyVault>()?;
    m.add_function(wrap_pyfunction!(run_cli, m)?)?;
    m.add_function(wrap_pyfunction!(_vectors_run, m)?)?;
    Ok(())
}
