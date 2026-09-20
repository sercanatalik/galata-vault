#!/usr/bin/env bash
# Build the site into site/_build (site/README.md):
#   _build/index.html  the landing page
#   _build/assets/     the logo files
#   _build/docs/       the mdBook book, staged by stage.py
# Needs python3 and mdbook on PATH. Pass --serve to open the book locally.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

python3 stage.py
rm -rf _build
mkdir -p _build
mdbook build
# The "Suggest an edit" links carry the staged path (_src/...); the staged
# tree mirrors the repository, so the repository path is the same minus the
# prefix. perl -pi works the same on macOS and Linux.
find _build/docs -name '*.html' -exec perl -pi -e 's{/edit/main/_src/}{/edit/main/}g' {} +
cp index.html _build/index.html
cp -R assets _build/assets
echo "built $here/_build"

if [[ "${1:-}" == "--serve" ]]; then
  # mdbook serve rebuilds the book on change; the landing page is static.
  exec mdbook serve --open
fi
