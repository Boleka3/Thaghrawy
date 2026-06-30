FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

RUN for i in 1 2 3; do \
      apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nmap whatweb gobuster nikto sqlmap hydra ffuf \
        amass whois dnsutils ca-certificates git curl unzip \
        subfinder httpx-toolkit nuclei naabu dnsx assetfinder \
        wpscan testssl.sh wafw00f exploitdb masscan enum4linux \
        seclists wordlists \
        ruby ruby-dev build-essential libssl-dev && break || sleep 5; \
    done && \
    rm -rf /var/lib/apt/lists/*

# katana is not in Kali apt — install from GitHub releases. The release asset
# name carries the version (katana_<ver>_linux_amd64.zip), so resolve the
# latest asset URL via the GitHub API rather than a fixed /latest/download URL
# (which 404s). Best-effort with bounded retries and a non-fatal fallback so a
# transient GitHub hiccup or rate-limit can't kill the build — the agent
# degrades gracefully when a tool binary is absent (run_command returns a
# "binary not found" result for katana_crawl).
RUN url="$(curl -fsSL --connect-timeout 15 --retry 5 --retry-delay 5 \
        https://api.github.com/repos/projectdiscovery/katana/releases/latest \
        | grep -oE 'https://[^\"]*katana_[0-9.]+_linux_amd64\.zip' | head -1)"; \
    if [ -n "$url" ] && curl -fsSL --connect-timeout 15 --max-time 180 --retry 5 --retry-delay 5 \
            "$url" -o /tmp/katana.zip; then \
        cd /tmp && unzip -o katana.zip katana \
        && mv /tmp/katana /usr/local/bin/katana \
        && chmod +x /usr/local/bin/katana \
        && rm -f /tmp/katana.zip; \
    else \
        echo "WARNING: katana install skipped (asset unresolved or GitHub unreachable); katana_crawl unavailable"; \
    fi

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt arjun

COPY . .

EXPOSE 8000
CMD ["python3", "main.py"]
