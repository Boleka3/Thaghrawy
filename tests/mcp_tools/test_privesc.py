from mcp_servers.tools import privesc


class _Fake:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_privesc_runs_every_check(monkeypatch):
    monkeypatch.setattr(privesc.subprocess, "run", lambda cmd, **k: _Fake(stdout="uid=0(root)"))
    result = privesc.linux_privesc_check()
    assert result["status"] == "success"
    assert result["tool"] == "linux_privesc_check"
    assert len(result["findings"]) == len(privesc._CHECKS)
    assert result["findings"][0]["check"] == "whoami"
    assert result["findings"][0]["status"] == "ok"


def test_privesc_marks_missing_binary(monkeypatch):
    def raise_not_found(cmd, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(privesc.subprocess, "run", raise_not_found)
    result = privesc.linux_privesc_check()
    assert all(f["status"] == "not_found" for f in result["findings"])


def test_privesc_handles_nonzero_returncode(monkeypatch):
    monkeypatch.setattr(
        privesc.subprocess, "run",
        lambda cmd, **k: _Fake(stdout="", stderr="permission denied", returncode=1),
    )
    result = privesc.linux_privesc_check()
    assert all(f["status"] == "error" for f in result["findings"])
