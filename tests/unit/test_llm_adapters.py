from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar, Literal, cast

import pytest
from pydantic import JsonValue, ValidationError

from evitriage.domain.alerts import RawResultReference
from evitriage.domain.triage import AnalystOutput, TriageTarget
from evitriage.errors import ConfigurationError, ModelError, ModelResponseError, ReplayMissError
from evitriage.llm import (
    DeepSeekLLM,
    FakeLLM,
    InvocationContext,
    LLMProfile,
    ReplayLLM,
    ScriptedResponse,
    canonical_request_sha256,
)


def _profile(
    provider: Literal["fake", "replay", "deepseek"] = "replay",
) -> LLMProfile:
    if provider == "deepseek":
        return LLMProfile(
            id="deepseek-v4-pro",
            provider=provider,
            model_id="deepseek-v4-pro",
            data_policy="remote_llm_allowed",
        )
    return LLMProfile(
        id=f"{provider}-v0.1",
        provider=provider,
        model_id="offline-fixture",
    )


def _context(profile: LLMProfile) -> InvocationContext:
    return InvocationContext(
        run_id="gate-d-adapter-test",
        target=TriageTarget(
            alert_fingerprint="b" * 64,
            raw_result_reference=RawResultReference(
                raw_sarif_sha256="a" * 64,
                run_index=0,
                result_index=0,
            ),
        ),
        agent_role="analyst",
        attempt=0,
        profile=profile,
    )


def _response() -> dict[str, JsonValue]:
    return {
        "schema_version": "1.0",
        "claims": [],
        "unknowns": [],
    }


def test_canonical_request_hash_covers_payload_schema_prompt_and_profile() -> None:
    profile = _profile()
    context = _context(profile)
    first = canonical_request_sha256(
        system_prompt="bounded analyst",
        user_payload={"b": 2, "a": 1},
        response_model=AnalystOutput,
        invocation_context=context,
    )
    reordered = canonical_request_sha256(
        system_prompt="bounded analyst",
        user_payload={"a": 1, "b": 2},
        response_model=AnalystOutput,
        invocation_context=context,
    )
    changed = canonical_request_sha256(
        system_prompt="different prompt",
        user_payload={"a": 1, "b": 2},
        response_model=AnalystOutput,
        invocation_context=context,
    )

    assert first == reordered
    assert first != changed
    assert len(first) == 64


def test_replay_llm_reads_only_exact_hash_and_rejects_symlinks(tmp_path: Path) -> None:
    profile = _profile()
    context = _context(profile)
    payload = {"target": "fixture"}
    prompt = "bounded analyst"
    request_sha256 = canonical_request_sha256(
        system_prompt=prompt,
        user_payload=payload,
        response_model=AnalystOutput,
        invocation_context=context,
    )
    entry = tmp_path / f"{request_sha256}.json"
    entry.write_text(json.dumps(_response()), encoding="utf-8")
    replay = ReplayLLM(profile, tmp_path)

    result = replay.complete(
        system_prompt=prompt,
        user_payload=payload,
        response_model=AnalystOutput,
        invocation_context=context,
    )

    assert result.claims == ()
    with pytest.raises(ReplayMissError) as missing:
        replay.complete(
            system_prompt="cache miss",
            user_payload=payload,
            response_model=AnalystOutput,
            invocation_context=context,
        )
    assert len(cast(str, missing.value.details["request_sha256"])) == 64

    linked_prompt = "linked cache entry"
    linked_hash = canonical_request_sha256(
        system_prompt=linked_prompt,
        user_payload=payload,
        response_model=AnalystOutput,
        invocation_context=context,
    )
    (tmp_path / f"{linked_hash}.json").symlink_to(entry)
    with pytest.raises(ModelError, match="symbolic link"):
        replay.complete(
            system_prompt=linked_prompt,
            user_payload=payload,
            response_model=AnalystOutput,
            invocation_context=context,
        )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"1.0","claims":[],"unknowns":[],"unknowns":[]}',
        b'{"schema_version":"1.0","claims":[],"unknowns":[],"extra":true}',
        b'{"schema_version":"1.0","claims":[],"unknowns":[],"n":NaN}',
    ],
)
def test_fake_llm_rejects_duplicate_extra_and_non_finite_json(raw: bytes) -> None:
    profile = _profile("fake")
    fake = FakeLLM(profile, (ScriptedResponse("analyst", raw),))

    with pytest.raises(ModelResponseError) as raised:
        fake.complete(
            system_prompt="bounded analyst",
            user_payload={"target": "fixture"},
            response_model=AnalystOutput,
            invocation_context=_context(profile),
        )

    assert len(cast(str, raised.value.details["response_sha256"])) == 64
    assert "response_model" in raised.value.details


def test_fake_llm_enforces_scripted_role_and_profile() -> None:
    profile = _profile("fake")
    wrong_role = FakeLLM(
        profile,
        (ScriptedResponse("judge", cast(JsonValue, _response())),),
    )
    with pytest.raises(ModelError, match="role does not match"):
        wrong_role.complete(
            system_prompt="bounded analyst",
            user_payload={},
            response_model=AnalystOutput,
            invocation_context=_context(profile),
        )

    different_profile = _profile("replay")
    mismatch = FakeLLM(
        profile,
        (ScriptedResponse("analyst", cast(JsonValue, _response())),),
    )
    with pytest.raises(ModelError, match="profile does not match"):
        mismatch.complete(
            system_prompt="bounded analyst",
            user_payload={},
            response_model=AnalystOutput,
            invocation_context=_context(different_profile),
        )

    with pytest.raises(ConfigurationError, match="provider=fake"):
        FakeLLM(different_profile, ())
    with pytest.raises(ConfigurationError, match="provider=replay"):
        ReplayLLM(profile, Path.cwd())


class _FakeDeepSeekResponse:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def read(self, maximum_bytes: int) -> bytes:
        return self._payload[:maximum_bytes]


class _FakeDeepSeekConnection:
    response = _FakeDeepSeekResponse(b"{}")
    captured: ClassVar[dict[str, object]] = {}

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        self.captured.clear()
        self.captured.update({"host": host, "port": port, "timeout": timeout})

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        self.captured.update({"method": method, "path": path, "body": body, "headers": headers})

    def getresponse(self) -> _FakeDeepSeekResponse:
        return self.response

    def close(self) -> None:
        self.captured["closed"] = True


def test_deepseek_v4_uses_official_https_json_endpoint_without_persisting_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_key = "test-only-deepseek-key"
    monkeypatch.setenv("DEEPSEEK_API_KEY", api_key)
    monkeypatch.setattr(
        "evitriage.llm.structured.http.client.HTTPSConnection",
        _FakeDeepSeekConnection,
    )
    envelope = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"content": json.dumps(_response())},
            }
        ]
    }
    _FakeDeepSeekConnection.response = _FakeDeepSeekResponse(json.dumps(envelope).encode())
    profile = _profile("deepseek")
    context = _context(profile)

    result = DeepSeekLLM.from_environment(profile).complete(
        system_prompt="Return JSON only.",
        user_payload={"target": "fixture"},
        response_model=AnalystOutput,
        invocation_context=context,
    )

    assert result.claims == ()
    captured = _FakeDeepSeekConnection.captured
    assert (captured["host"], captured["port"], captured["timeout"]) == (
        "api.deepseek.com",
        443,
        120,
    )
    assert (captured["method"], captured["path"], captured["closed"]) == (
        "POST",
        "/chat/completions",
        True,
    )
    headers = cast(dict[str, str], captured["headers"])
    assert headers["Authorization"] == f"Bearer {api_key}"
    body = json.loads(cast(bytes, captured["body"]))
    assert body["model"] == "deepseek-v4-pro"
    assert body["response_format"] == {"type": "json_object"}
    assert body["thinking"] == {"type": "disabled"}
    user_content = json.loads(body["messages"][1]["content"])
    assert user_content["task_payload"] == {"target": "fixture"}
    assert "properties" in user_content["response_schema"]
    assert api_key not in cast(bytes, captured["body"]).decode()


def test_deepseek_key_and_error_body_never_enter_structured_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile("deepseek")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(ConfigurationError) as missing:
        DeepSeekLLM.from_environment(profile)
    assert "DEEPSEEK_API_KEY" in str(missing.value)

    api_key = "test-only-secret-key"
    echoed_payload = "provider-sensitive-content"
    monkeypatch.setenv("DEEPSEEK_API_KEY", api_key)
    monkeypatch.setattr(
        "evitriage.llm.structured.http.client.HTTPSConnection",
        _FakeDeepSeekConnection,
    )
    _FakeDeepSeekConnection.response = _FakeDeepSeekResponse(
        echoed_payload.encode(),
        status=401,
    )
    with pytest.raises(ModelError) as raised:
        DeepSeekLLM.from_environment(profile).complete(
            system_prompt="Return JSON only.",
            user_payload={"target": "fixture"},
            response_model=AnalystOutput,
            invocation_context=_context(profile),
        )

    serialized = json.dumps(raised.value.as_dict())
    assert raised.value.details["http_status"] == 401
    assert api_key not in serialized
    assert echoed_payload not in serialized


def test_llm_profile_requires_explicit_remote_policy_for_deepseek() -> None:
    with pytest.raises(ValidationError, match="remote_llm_allowed"):
        LLMProfile(
            id="deepseek-v4-pro",
            provider="deepseek",
            model_id="deepseek-v4-pro",
        )
    with pytest.raises(ValidationError, match="supported V4"):
        LLMProfile(
            id="deepseek-v5",
            provider="deepseek",
            model_id="deepseek-v5",
            data_policy="remote_llm_allowed",
        )
    with pytest.raises(ValidationError, match="offline_only"):
        LLMProfile(
            id="replay-v0.1",
            provider="replay",
            model_id="fixture",
            data_policy="remote_llm_allowed",
        )
