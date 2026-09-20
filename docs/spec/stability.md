# Stability

Status: **draft** (docs/spec/README.md#1).

What may change, how, and what a release promises to read. Conventions are
in [README.md#3](README.md#3).

<a id="1"></a>
## 1. Versions belong to formats

Every stored or signed format carries its own version marker, independent of
the version of any crate or package.

A crate's semantic version describes its programming interface, which will
change for reasons that have nothing to do with bytes on disk: a crate may
reach 2.0 while every format it writes is unchanged. Stored data outlives any
interface: a vault written today is read by releases years from now. So a
release states which format versions it reads and writes ([§5](#5)), and a
format's version changes only when its bytes do.

<a id="2"></a>
## 2. Version markers

| Format | Marker | Current | Read by this release |
|---|---|---|---|
| Node key string ([formats.md#2.3](formats.md#2.3)) | prefix | `gvk1_` | `gvk1_` |
| Token string ([formats.md#2.4](formats.md#2.4)) | prefix | `gvt1_` | `gvt1_` |
| Key derivations ([keys.md#2](keys.md#2)) | HKDF salt | `galata-vault/v1` | `galata-vault/v1` |
| Framed inputs ([keys.md#3](keys.md#3)) | label prefix | `gv/v1/` | `gv/v1/` |
| Generation descriptor ([records.md#1](records.md#1)) | version byte | 1 | 1 |
| Bundle ([records.md#2](records.md#2)) | version byte | 1 | 1 |
| Record envelope ([records.md#3](records.md#3)) | version byte | 1 | 1 |
| Children record ([records.md#5](records.md#5)) | `v` | 1 | 1 |
| Kit ([records.md#6](records.md#6)) | `v` | 1 | 1 |
| Audit row ([audit.md#4](audit.md#4)) | `v` | 1 | 1 |
| Request signature ([signatures.md#2](signatures.md#2)) | `GV-Sig v=` | 1 | 1 |
| Value ciphertext ([records.md#3](records.md#3)) | age header | `age-encryption.org/v1` | age v1 |
| HTTP API ([http-api.md#1](http-api.md#1)) | path prefix | `/v1` | `/v1` |
| Capabilities ([http-api.md#6](http-api.md#6)) | `protocols` | `["1"]` | a server listing `"1"`; a document without the field is read as `["1"]` |

A server advertises the format versions it implements in its capabilities
(`formats`, [http-api.md#6](http-api.md#6)).

Any change to bytes that a test vector covers MUST come with a new value of
that format's marker ([README.md#7](README.md#7)). CI regenerates the
vectors from the independent generator and fails on any difference, so a
silent change cannot pass.

<a id="3"></a>
## 3. Before 1.0

- The specification is marked **draft** ([README.md#1](README.md#1)).
- A format MAY change incompatibly, but only under a new version marker:
  never by changing the bytes an existing marker names. A reader that does
  not know the new marker refuses it as `unknown_version`.
- The changelog of every 0.x release SHALL name the format versions it reads
  and writes ([§5](#5)).

<a id="4"></a>
## 4. From 1.0

- The version markers of [§2](#2), as they stand at 1.0, are frozen. Every
  1.x release SHALL read every one of them: data written by 1.0 opens and
  verifies under any later 1.x release exactly as it did under 1.0.
- New constructs SHALL be additive, as new kinds or new versions under new
  markers. A reader that meets a kind or version it does not know MUST refuse
  it cleanly, as `unknown_kind` or `unknown_version`, and MUST NOT guess.
- A 1.x minor release MAY stop *writing* an old version, but SHALL keep
  reading it.
- Dropping the ability to *read* a format version SHALL require a major
  release.

<a id="5"></a>
## 5. The changelog rule

Every release's changelog SHALL list, for each format in [§2](#2), the
versions the release reads and the version it writes, and SHALL call out any
change to either. A change that adds a marker names the marker, the format
and the reason.

<a id="6"></a>
## 6. The wire API

The HTTP API evolves under the forward-compatibility rules of
[http-api.md#7](http-api.md#7): requests stay strict, responses are read
tolerantly, and a client never acts on a value it does not understand. Error
codes are only ever added, never renamed or reused
([http-api.md#5](http-api.md#5)). A new request field is sent only to a
server whose capabilities advertise it.
