# IVXV vote verifier

An independent cast-as-intended verification tool for IVXV.
It is built on top of the [pyivxv](https://github.com/takakv/pyivxv) library.

The source code for the official Android & iOS verification applications can be found at:

- [valimised/ivotingverification](https://github.com/valimised/ivotingverification) — Android
- [valimised/ios-ivotingverification](https://github.com/valimised/ios-ivotingverification) — iOS

See the official [website](https://www.valimised.ee/en/internet-voting/guidelines/checking-i-vote) for links to the applications and verification instructions. 

Another independent vote verification tool is [infoaed/kryptogramm](https://github.com/infoaed/kryptogramm).

See [takakv/ivxv-decproof-verifier](https://github.com/takakv/ivxv-decproof-verifier) for an independent tool for verifying the zero-knowledge proofs of correct decryption.

## Requirements

The tool is written in Python 3.
The intended package manager is [uv](https://docs.astral.sh/uv/getting-started/installation/) although it is not strictly necessary.

The tool requires `zbar`, which can be installed e.g. using

- `brew install zbar`
  > Note: When using `uv`, you may then need to set `DYLD_LIBRARY_PATH=$(brew --prefix zbar)/lib`.
- `apt-get install libzbar0`

On Windows, no additional installation should be necessary.

## Usage

The tool can be run directly with

```
uv run verify.py
```

Alternatively, to set up and activate the project environment manually, execute:

```
uv sync
source .venv/bin/activate
python verify.py
```

The usage parameters are

```text
usage: verify.py [-h] [-c CONFIG] [-i] datafile

positional arguments:
  datafile             the saved vote JSON or the QR code

options:
  -h, --help           show this help message and exit
  -c, --config CONFIG  the verifier's configuration file (default: config.json)
  -i, --ignore-errors  continue verification even if a check fails (default: False)
```

The official verification configuration is typically stored at
[valimised.ee/verify/config.json](https://www.valimised.ee/verify/config.json).
You can download it with

```
curl -O https://www.valimised.ee/verify/config.json
```

or

```
wget https://www.valimised.ee/verify/config.json
```

### Usage examples

Download and verify a vote using the verification QR code:

```
verify.py qr.png
```

Verify a vote already downloaded with this tool:

```
verify.py data/3R1qg_eHAmznrc2lduJBXw==.json
```

The `migrate_json.py` script can be used to migrate the JSON accepted by this tool before 2026 to the current format.
