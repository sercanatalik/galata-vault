//! Kit files. The SDK renders and parses kits; the CLI writes them to new
//! 0600 files and refuses to read one anyone else could read.

use std::path::Path;

use crate::owner::Kit;
use anyhow::Context as _;
use zeroize::Zeroizing;

use crate::cli::branding::Branding;
use crate::cli::fsutil::{create_private, require_private};

/// Write `kit` to a new 0600 file, headed with the branding's product name.
pub fn write(branding: &Branding, kit: &Kit, path: &Path) -> anyhow::Result<()> {
    let text = kit.render_with_header(branding.kit_header)?;
    create_private(path, text.as_bytes(), false)
}

/// Read the kit in `path`, refusing a file with a mode other than 0600 or
/// 0400.
pub fn read(path: &Path) -> anyhow::Result<Kit> {
    require_private(path)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    );
    Kit::parse(&text).with_context(|| format!("reading the kit {}", path.display()))
}
