import json
import socket
import ssl
import sys

from pydantic import BaseModel, Field


class Qualification(BaseModel):
    ocsp: str = Field(..., alias="ocsp")
    tspreg: str = Field(..., alias="tspreg")


class RPCVerifyResult(BaseModel):
    qual: Qualification = Field(..., alias="Qualification")
    session_id: str = Field(..., alias="SessionID")
    type: str = Field(..., alias="Type")
    vote: str = Field(..., alias="Vote")
    choices_list: str = Field(..., alias="ChoicesList")


class RPCClient:
    def __init__(self, collector_urls: list[str], verification_sni: str, os_string: str):
        host_port = collector_urls[0].split(":")

        self.host = host_port[0]
        self.port = int(host_port[1])

        self.sni = verification_sni
        self.os = os_string

    def send_rpc(self, message) -> bytes:
        rpc_message = json.dumps(message).encode()

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.load_default_certs()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        response = bytearray()
        with socket.create_connection((self.host, self.port)) as sock, \
                ssl_context.wrap_socket(sock, server_hostname=self.sni) as ssock:
            ssock.sendall(rpc_message)

            while chunk := ssock.recv(4096):
                response.extend(chunk)

        return bytes(response)

    def verify(self, session_id: str, vote_id: str) -> RPCVerifyResult:
        rpc_verify = {
            "id": 1,
            "method": "RPC.Verify",
            "params": [{
                "OS": self.os,
                "SessionID": session_id,
                "VoteID": vote_id
            }],
        }

        response = self.send_rpc(rpc_verify)
        response_json = json.loads(response.decode())

        error = response_json["error"]
        if error:
            match error:
                case "BAD_REQUEST":
                    print("[-] Vigane päring")
                case "INTERNAL_SERVER_ERROR":
                    print("[-] Viga serveri sisemises töös")
                case "VOTING_END":
                    print("[-] Hääletusperiood on lõppenud")
                case _:
                    print("[!] Ebaootuspärane vastus:", error)
            sys.exit(1)

        return RPCVerifyResult(**response_json["result"])
