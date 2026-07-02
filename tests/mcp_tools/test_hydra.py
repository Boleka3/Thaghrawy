from mcp_servers.tools.hydra import _parse_hydra, hydra_bruteforce

_HYDRA_STDOUT = (
    "[DATA] attacking ssh://10.0.0.5:22/\n"
    "[22][ssh] host: 10.0.0.5   login: admin   password: hunter2\n"
)


def test_hydra_bruteforce_requires_all_args():
    assert hydra_bruteforce(target="", service="ssh", user="root", wordlist="/wl.txt")["status"] == "error"


def test_hydra_bruteforce_strips_scheme_port_and_path(fake_subprocess):
    fake_subprocess.stdout = _HYDRA_STDOUT
    hydra_bruteforce(
        target="https://example.com:8080/login", service="http-get", user="admin", wordlist="/wl.txt"
    )
    assert fake_subprocess.last_call == [
        "hydra", "-l", "admin", "-P", "/wl.txt", "example.com", "http-get",
    ]


def test_hydra_bruteforce_with_bare_hostname(fake_subprocess):
    fake_subprocess.stdout = ""
    hydra_bruteforce(target="10.0.0.5", service="ssh", user="root", wordlist="/wl.txt")
    assert fake_subprocess.last_call == ["hydra", "-l", "root", "-P", "/wl.txt", "10.0.0.5", "ssh"]


def test_hydra_bruteforce_parses_recovered_credentials(fake_subprocess):
    fake_subprocess.stdout = _HYDRA_STDOUT
    result = hydra_bruteforce(target="10.0.0.5", service="ssh", user="admin", wordlist="/wl.txt")
    assert result["status"] == "success"
    assert result["credentials_found"] == 1
    assert result["credentials"][0] == {"host": "10.0.0.5", "login": "admin", "password": "hunter2"}


def test_parse_hydra_no_credentials():
    parsed = _parse_hydra("[DATA] 0 valid passwords found\n")
    assert parsed["credentials_found"] == 0
