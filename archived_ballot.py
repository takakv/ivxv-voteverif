from pydantic import BaseModel, Field

from rpc import RPCVerifyResult


class ArchivedBallot(BaseModel):
    ephemeral: str
    vote_id: str = Field(..., alias="voteId")
    result: RPCVerifyResult

    @property
    def ocsp(self) -> str:
        return self.result.qual.ocsp

    @property
    def tspreg(self) -> str:
        return self.result.qual.tspreg

    @property
    def choices_list(self) -> str:
        return self.result.choices_list
