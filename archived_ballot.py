from pydantic import BaseModel, Field


class ArchivedBallot(BaseModel):
    session_id: str = Field(..., alias="sessionId")
    vote_id: str = Field(..., alias="voteId")
    random: str = Field(..., alias="rand")
    ocsp: str = Field(..., alias="ocsp")
    tspreg: str = Field(..., alias="tspreg")
