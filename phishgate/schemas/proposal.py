"""Seam S3 contract: what the action agent may propose to the gate.

Every argument is typed and closed. `notify` takes a template id and allow-listed
fields only, so no attacker-written string can reach a message.

"""
from __future__ import annotations

from enum import Enum
from typing import Literal, Union

from pydantic import BaseModel, ConfigDict, Field


class ActionName(str, Enum):
    QUARANTINE = "quarantine"
    SEARCH_SENDER = "search_sender"
    NOTIFY = "notify"


class QuarantineArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["quarantine"] = "quarantine"
    message_ids: list[str] = Field(min_length=1, max_length=50)


class SearchSenderArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["search_sender"] = "search_sender"
    sender_address: str = Field(max_length=254)


class NotifyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["notify"] = "notify"
    template_id: str = Field(pattern=r"^[a-z_]{1,40}$")
    # Values are restricted again by the gate against data/templates/<id>.json
    fields: dict[str, str] = Field(default_factory=dict)


ActionProposal = Union[QuarantineArgs, SearchSenderArgs, NotifyArgs]
