import json
from typing import Dict

from pydantic import BaseModel, Field, field_validator


class Params(BaseModel):
    collector_urls: list[str] = Field(..., alias="verification_url")
    public_key: str = Field(..., alias="public_key")
    verification_sni: str = Field(..., alias="verification_sni")
    tspreg_client_cert: str = Field(..., alias="tspreg_client_cert")
    tspreg_service_cert: str = Field(..., alias="tspreg_service_cert")


class AppConfig(BaseModel):
    params: Params = Field(..., alias="params")
    elections: Dict[str, str] = Field(..., alias="elections")

    # noinspection PyMethodParameters
    @field_validator("elections")
    def allow_single(cls, v: Dict[str, str]) -> Dict[str, str]:
        if len(v) != 1:
            raise ValueError("`elections` must contain exactly one key-value pair")
        return v

    @property
    def question_id(self) -> str:
        return next(iter(self.elections.items()))[0]


class VerifierConfig(BaseModel):
    raw: AppConfig = Field(..., alias="appConfig")

    @property
    def collector_urls(self) -> list[str]:
        return self.raw.params.collector_urls

    @property
    def verification_sni(self) -> str:
        return self.raw.params.verification_sni

    @property
    def question_id(self) -> str:
        return self.raw.question_id

    @property
    def public_key_pem(self) -> str:
        return self.raw.params.public_key

    @property
    def collector_cert(self) -> str:
        return self.raw.params.tspreg_client_cert

    @property
    def tspreg_cert(self) -> str:
        return self.raw.params.tspreg_service_cert


if __name__ == "__main__":
    with open("config.json", "r") as f:
        config_json = json.loads(f.read())
        config = VerifierConfig(**config_json)

    print(config)
    print(config.question_id)
