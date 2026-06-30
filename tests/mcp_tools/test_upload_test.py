from mcp_servers.tools import upload_test as upload_mod
from mcp_servers.tools.upload_test import upload_test


class _Fake:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def test_upload_test_requires_url():
    assert upload_test(url="")["status"] == "error"


def test_upload_test_flags_accepted_files(monkeypatch):
    monkeypatch.setattr(upload_mod.subprocess, "run", lambda cmd, **k: _Fake(stdout="200"))
    result = upload_test(url="http://localhost:8080/upload.php", field="file")
    assert result["status"] == "success"
    # Every probe returned 200 -> all test files reported accepted.
    assert "shell.php" in result["dangerous_accepted"]
    assert len(result["results"]) == len(upload_mod._TEST_FILES)


def test_upload_test_no_dangerous_accepted_when_rejected(monkeypatch):
    monkeypatch.setattr(upload_mod.subprocess, "run", lambda cmd, **k: _Fake(stdout="403"))
    result = upload_test(url="http://localhost:8080/upload.php")
    assert result["dangerous_accepted"] == []
    assert "No dangerous file types accepted" in result["summary"]
