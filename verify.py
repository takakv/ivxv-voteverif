import argparse
import base64
import json
import platform
import sys
from typing import NamedTuple

from PIL import Image
from pyasice import Container, SignatureVerificationError
from pyivxv.crypto.ciphertext import ElGamalCiphertext
from pyivxv.crypto.keys import PublicKey
from pyivxv.encoding.message import decode_from_point
from pyzbar import pyzbar

from archived_ballot import ArchivedBallot
from config import VerifierConfig
from rpc import RPCClient

OS_STRING = f"takakv/ivxv-voteverif ({platform.system()} {platform.release()}) Python/{platform.python_version()}"


class QRData(NamedTuple):
    session_id: str
    enc_rand: str
    vote_id: str


def parse_qr(qr_file: str) -> QRData:
    qr_obj = pyzbar.decode(Image.open(qr_file), symbols=[pyzbar.ZBarSymbol.QRCODE])

    if len(qr_obj) != 1:
        print("Wrong")
        sys.exit(1)

    qr_data: list[bytes] = qr_obj[0].data.split(b"\n")
    if len(qr_data) != 3:
        print("Wrong")
        sys.exit(1)

    session_id = qr_data[0].decode()
    enc_rand = qr_data[1].decode()
    vote_id = qr_data[2].decode()

    return QRData(session_id, enc_rand, vote_id)


def canonicalize_vote_id(vote_id: str) -> str:
    return base64.urlsafe_b64encode(base64.b64decode(vote_id)).decode()


def fetch_and_store(qr_data: QRData, config: VerifierConfig) -> str:
    client = RPCClient(config.collector_urls, config.verification_sni, OS_STRING)
    verify_result = client.verify(qr_data.session_id, qr_data.vote_id)

    assert qr_data.session_id == verify_result.session_id

    safe_vote_id = canonicalize_vote_id(verify_result.vote_id)
    with open(f"data/{safe_vote_id}.bdoc", "wb") as f:
        f.write(base64.b64decode(verify_result.vote))

    with open(f"data/{safe_vote_id}.json", "w") as f:
        data = {"sessionId": qr_data.session_id, "voteId": qr_data.vote_id, "rand": qr_data.enc_rand,
                "ocsp": verify_result.qual.ocsp, "tspreg": verify_result.qual.tspreg}
        f.write(json.dumps(data, indent=2))

    return f"data/{safe_vote_id}.json"


def main(f_data: str, config: VerifierConfig):
    file_extension = f_data.split(".")[-1]

    if file_extension != "json":
        f_data = fetch_and_store(parse_qr(f_data), config)

    with open(f_data, "r") as f:
        ballot_data = ArchivedBallot(**json.loads(f.read()))

    pk = PublicKey.from_public_bytes(config.public_key_pem.encode())

    safe_vote_id = canonicalize_vote_id(ballot_data.vote_id)
    container = Container.open(f"data/{safe_vote_id}.bdoc")

    try:
        container.verify_signatures()
    except SignatureVerificationError:
        print("[-] Signature verification failed")
        sys.exit(1)

    data_files = container.data_file_names
    if len(data_files) != 1:
        print("[-] Container contents are incorrect")

    with container.open_file(data_files[0]) as f:
        ct = ElGamalCiphertext.from_bytes(f.read())

    r = int.from_bytes(base64.b64decode(ballot_data.random), byteorder="big")
    if pk.curve.G * r != ct.U:
        print("[-] Invalid random value")

    unblinded = ct.unblind(pk.H, r=r)

    print(decode_from_point(unblinded, pk.curve))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("datafile", help="the saved vote JSON or the QR code", type=str)
    parser.add_argument(
        "--config",
        help="the verifier's configuration file",
        default="config.json"
    )

    print(OS_STRING)

    args = parser.parse_args()

    with open(args.config, "r") as config_file:
        config_json = json.loads(config_file.read())
        vc = VerifierConfig(**config_json)

    main(args.datafile, vc)
