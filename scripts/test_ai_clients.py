#!/usr/bin/env python3
"""Exercise a temporary loopback AI sensor with official SDKs and fake keys.

Install requirements-ai-smoke.txt into a venv and pass a built Helix binary.
No provider calls, inherited Helix config, model backend or GPU is used.
"""
import argparse
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import anthropic
import httpx
import ollama
import openai

TEXT = "Hello! How can I help you today?"
KEY = "synthetic-ai-smoke-key"
PROMPT = "PRIVATE-SMOKE-PROMPT"


def exercise(binary, authenticated):
    with tempfile.TemporaryDirectory(prefix="helix-ai-smoke-") as directory:
        root = Path(directory)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        url = "http://127.0.0.1:%d" % port
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HELIX_RUN_MODE": "ai",
            "HELIX_AI_HOST": "127.0.0.1",
            "HELIX_AI_PORT": str(port),
            "HELIX_CONFIG": str(root / "absent.toml"),
            "HELIX_AI_TOKEN": KEY if authenticated else "",
        }
        with (root / "events.jsonl").open("w+") as output:
            process = subprocess.Popen([binary], env=env, stdout=output, stderr=output)
            try:
                with httpx.Client(trust_env=False, timeout=3) as probe:
                    headers = {"Authorization": "Bearer " + KEY}
                    for _ in range(100):
                        if process.poll() is not None:
                            raise AssertionError("sensor exited before readiness")
                        try:
                            res = probe.get(url + "/api/version", headers=headers)
                            if res.status_code == 200:
                                break
                        except httpx.ConnectError:
                            pass
                        time.sleep(0.02)
                    else:
                        raise AssertionError("sensor not ready")
                    if authenticated:
                        assert probe.get(url + "/api/version").status_code == 401
                        assert probe.post(url + "/v1/messages", json={}, headers={"x-api-key": "wrong"}).status_code == 401
                    native = ollama.Client(host=url, headers=headers, trust_env=False, timeout=3)
                    assert native.list().models[0].model == "llama3.2:latest"
                    assert "completion" in native.show("llama3.2").capabilities
                    assert native.chat(model="llama3.2", messages=[{"role": "user", "content": PROMPT}]).message.content == TEXT
                    assert "".join(p.message.content for p in native.chat(model="llama3.2", messages=[{"role": "user", "content": PROMPT}], stream=True)) == TEXT
                    assert native.generate(model="llama3.2", prompt=PROMPT).response == TEXT
                    assert "".join(p.response for p in native.generate(model="llama3.2", prompt=PROMPT, stream=True)) == TEXT
                    assert probe.post(url + "/api/pull", headers=headers, json={"model": "https://127.0.0.1/must-not-fetch"}).status_code == 501
                    # No provider keys are read; both clients share a local transport.
                    client = openai.OpenAI(api_key=KEY, base_url=url + "/v1", http_client=probe, max_retries=0)
                    assert len(client.models.list().data) == 3
                    messages = [{"role": "user", "content": PROMPT}]
                    assert client.chat.completions.create(model="gpt-4o-mini", messages=messages).choices[0].message.content == TEXT
                    chunks = list(client.chat.completions.create(model="gpt-4o-mini", messages=messages, stream=True, stream_options={"include_usage": True}))
                    assert "".join(c.choices[0].delta.content or "" for c in chunks if c.choices) == TEXT
                    assert chunks[-1].usage.completion_tokens == 9
                    assert client.responses.create(model="gpt-4o-mini", input=PROMPT, store=False).output_text == TEXT
                    with client.responses.stream(model="gpt-4o-mini", input=PROMPT, store=False) as stream:
                        assert "".join(e.delta for e in stream if e.type == "response.output_text.delta") == TEXT
                        assert stream.get_final_response().output_text == TEXT
                    assert client.chat.completions.create(model="gpt-4o-mini", messages=messages, max_completion_tokens=1).choices[0].message.content == "Hello"
                    claude = anthropic.Anthropic(api_key=KEY, base_url=url, http_client=probe, max_retries=0)
                    args = {"model": "claude-3-5-sonnet-latest", "max_tokens": 64, "messages": messages}
                    assert claude.messages.create(**args).content[0].text == TEXT
                    with claude.messages.stream(**args) as stream:
                        assert "".join(stream.text_stream) == TEXT
                        assert stream.get_final_message().stop_reason == "end_turn"
                    assert claude.messages.count_tokens(model=args["model"], messages=messages).input_tokens == 1
                    assert claude.messages.create(**dict(args, max_tokens=1)).usage.output_tokens == 1
                    assert probe.post(url + "/v1/responses", headers=headers, json={"model": "gpt-4o-mini", "input": PROMPT, "previous_response_id": "resp_fake"}).status_code == 400
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            output.flush()
            output.seek(0)
            lines = output.read().splitlines()
            assert lines, "missing telemetry"
            events = [json.loads(line) for line in lines]
            assert all(e["sensor"] == "ai" for e in events)
            assert all(KEY not in line and PROMPT not in line for line in lines)
            assert any(e.get("outcome") == "refused" for e in events)
            assert all(e.get("session_id", "").startswith("ai-") for e in events)
            sessions = [e["session_id"] for e in events]
            assert len(set(sessions)) < len(sessions), "keepalive sessions not correlated"
            assert process.returncode == 0, "unclean shutdown"
        print("PASS official SDKs, %s, privacy and shutdown" % ("authenticated" if authenticated else "anonymous"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    exercise(binary, False)
    exercise(binary, True)
    print("SDK versions: openai=%s anthropic=%s ollama=0.6.3" % (openai.__version__, anthropic.__version__))
