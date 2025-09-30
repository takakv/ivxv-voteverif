# IVXV vote verifier

An independent cast-as-intended verification tool for IVXV.

The official application can be found at:

- [valimised/ivotingverification](https://github.com/valimised/ivotingverification) — Android
- [valimised/ios-ivotingverification](https://github.com/valimised/ios-ivotingverification) — iOS

## Usage

Install the required dependencies with

```
pip install -r requirements.txt
```

The usage parameters are

```text
usage: verify.py [-h] [--config CONFIG] datafile

positional arguments:
  datafile         the saved vote JSON or the QR code

options:
  -h, --help       show this help message and exit
  --config CONFIG  the verifier's configuration file (default: config.json)
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
python3 verify.py qr.png
```

Verify a vote already downloaded with this tool:

```
python3 verify.py data/3R1qg_eHAmznrc2lduJBXw==.json
```
