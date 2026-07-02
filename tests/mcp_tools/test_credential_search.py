"""credential_search must find secrets but never persist them in the clear
(project rule: never store raw credentials in ChromaDB or logs)."""
import os

from mcp_servers.tools import _common
from mcp_servers.tools.credential_search import _redact, credential_search


def test_redact_masks_secret_value():
    assert _redact("hunter2password") == "hunt…[REDACTED]"
    assert _redact("abc") == "[REDACTED]"


def test_credential_search_missing_directory_returns_error():
    result = credential_search(directory="/no/such/dir")
    assert result["status"] == "error"


def test_credential_search_finds_and_redacts(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "WORKSPACE_DIR", str(tmp_path))
    secret = "supersecretpassword123"
    (tmp_path / "config.txt").write_text(f"password = {secret}\n")

    result = credential_search(directory=str(tmp_path))

    assert result["status"] == "success"
    assert result["files_scanned"] == 1
    assert len(result["matches"]) >= 1
    # The raw secret must NOT appear in any returned match snippet.
    for m in result["matches"]:
        assert secret not in m["match"]
        assert "[REDACTED]" in m["match"]


def test_credential_search_does_not_write_raw_secret_to_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "WORKSPACE_DIR", str(tmp_path))
    secret = "AKIAIOSFODNN7EXAMPLE"
    (tmp_path / "creds.env").write_text(f"AWS_KEY={secret}\n")

    result = credential_search(directory=str(tmp_path))

    # Every file written to the workspace (incl. the saved report) must be
    # free of the raw secret.
    for fname in os.listdir(tmp_path):
        content = (tmp_path / fname).read_text(errors="replace")
        if fname == "creds.env":
            continue  # the source file the user provided, not our output
        assert secret not in content, f"raw secret leaked into {fname}"
    assert "full_output_file" in result
