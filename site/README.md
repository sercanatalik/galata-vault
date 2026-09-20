# The site

The project's website: a landing page, the documentation as an
[mdBook](https://rust-lang.github.io/mdBook/), and the logo. It is published
to GitHub Pages by `.github/workflows/pages.yml` on every push to `main`, at
`https://sercanatalik.github.io/galata-vault/`.

## What is here

| Path | Role |
|---|---|
| `index.html` | The landing page. Static, self-contained, links into the book. |
| `assets/` | The logo: `logo.svg` (ink), `logo-on-dark.svg`, `wordmark.svg`, `favicon.svg`, `favicon-32.png`. |
| `book.toml` | The mdBook configuration. |
| `stage.py` | Stages the book's sources under `_src/` (below). |
| `build.sh` | Builds everything into `_build/`. |
| `theme/` | mdBook theme overrides: `css/variables.css` (the two colour themes) and the favicons. |
| `galata.css`, `galata.js` | Typography and chrome on top of the theme; the mark in the menu bar. |

`_src/` and `_build/` are generated and ignored.

## How the book is assembled

The documentation lives where it always has: `README.md`, `docs/`, the crate
READMEs, `deploy/README.md` and the project files at the root. Nothing is
duplicated for the site. `stage.py` copies those files to the same relative
paths under `_src/`, so every relative link between them keeps working, and
adds two things:

- **`SUMMARY.md`**, the book's table of contents, generated from a curated
  table in the script. An entry whose file does not exist is skipped, so
  removing a document from the tree needs no change here. Markdown under
  `docs/` that the table does not name is appended under "More", so a new
  document is never silently missing. To reorder or rename entries, edit the
  table.
- **Links out of the book** (source files, licences, scripts, test data) are
  rewritten to `https://github.com/sercanatalik/galata-vault/blob/main/...`,
  so the site has no dead links.

The build output is `_build/index.html` (the landing page), `_build/assets/`
and `_build/docs/` (the book). Inside the book, a source at `docs/spec/keys.md`
renders at `docs/docs/spec/keys.html`, and a `README.md` renders as its
directory's `index.html`.

## Building locally

```sh
cargo install mdbook --locked   # 0.5.x; the workflow pins 0.5.4
site/build.sh                   # writes site/_build
site/build.sh --serve           # rebuilds the book on change and opens it
```

The landing page does not hot-reload under `--serve`; open
`site/_build/index.html` directly.

## Publishing

The site lives at `https://sercanatalik.github.io/galata-vault/`. The
workflow builds on every push to `main` and deploys with
`actions/deploy-pages`; the book is at `/docs/` under that address. Two
repository settings were needed once, and are set:

1. Actions enabled for the repository.
2. Settings, Pages, "Build and deployment", source: **GitHub Actions**
   (`gh api -X POST repos/sercanatalik/galata-vault/pages -f build_type=workflow`).

To redeploy without a push, run the same workflow by hand:
`gh workflow run pages.yml`. There is no other deploy path.

## The logo

The mark is the Galata Tower drawn on a 64-unit grid: the conical roof, the
wider gallery with its three arched windows, the shaft, and a keyhole where
the door would be. It is one `evenodd` path plus the finial, filled with a
single colour, so the same file serves light and dark backgrounds and the
favicon. The wordmark sets "galata vault" in Newsreader Medium.

Palette: stone `#F5F3EE` and ink `#1A1917` for the ground and text,
Bosphorus `#0E5E68` for links and actions (`#6CC3CC` on dark), copper
`#8A4B2A` only for the unaudited notice, night `#17181A` for the dark theme.
Type: Newsreader for headings, IBM Plex Sans for text, IBM Plex Mono for
code.
