FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

RUN for i in 1 2 3; do \
      apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-dev python3-venv \
        nmap whatweb gobuster nikto sqlmap hydra ffuf \
        amass whois dnsutils ca-certificates git curl unzip \
        subfinder httpx-toolkit nuclei naabu dnsx assetfinder \
        wpscan testssl.sh wafw00f exploitdb masscan enum4linux \
        wapiti \
        seclists wordlists \
        ruby ruby-dev build-essential libssl-dev && break || sleep 5; \
    done && \
    rm -rf /var/lib/apt/lists/*

# Kali's /usr/bin/amass is a wrapper script that runs `sudo libpostal_data download all`
# when /usr/share/libpostal/transliteration is missing, which fails in the container with
# "sudo: libpostal_data: command not found" and aborts every amass run. amass v4 doesn't
# need libpostal for passive/active enum, so point PATH at the real binary (/usr/local/bin
# is ahead of /usr/bin in _common.py's SUBPROCESS_ENV), bypassing the wrapper entirely.
RUN [ -x /usr/lib/amass/amass ] && ln -sf /usr/lib/amass/amass /usr/local/bin/amass || true

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

# dalfox (XSS scanner, OWASP A03) is not in Kali apt and there's no Go toolchain
# in the image, so install the prebuilt Linux binary from GitHub releases. Same
# best-effort pattern as katana: resolve the versioned asset via the API, bounded
# retries, non-fatal fallback (dalfox_scan degrades to "binary not found").
RUN url="$(curl -fsSL --connect-timeout 15 --retry 5 --retry-delay 5 \
        https://api.github.com/repos/hahwul/dalfox/releases/latest \
        | grep -oE 'https://[^\"]*dalfox-v[0-9.]+-linux-x86_64\.tar\.gz\"' \
        | tr -d '\"' | head -1)"; \
    if [ -n "$url" ] && curl -fsSL --connect-timeout 15 --max-time 240 --retry 5 --retry-delay 5 \
            "$url" -o /tmp/dalfox.tar.gz; then \
        cd /tmp && tar -xzf dalfox.tar.gz dalfox \
        && mv /tmp/dalfox /usr/local/bin/dalfox \
        && chmod +x /usr/local/bin/dalfox \
        && rm -f /tmp/dalfox.tar.gz; \
    else \
        echo "WARNING: dalfox install skipped (asset unresolved or GitHub unreachable); dalfox_scan unavailable"; \
    fi

WORKDIR /app

# Install our Python deps into an isolated virtualenv rather than over Kali's system
# Python. Kali ships several apt-managed modules (python3-requests, python3-cryptography,
# …) with no pip RECORD file, so pip can't uninstall them to honor our pinned versions and
# the build fails. A clean venv sidesteps that entire class of conflict. Kali's own CLI
# tools (nmap/sqlmap/wpscan/…) are invoked as subprocess binaries using /usr/bin/python3
# and are unaffected by this venv.
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# torch backend is modular so the same image builds for CPU, NVIDIA (CUDA), or AMD (ROCm).
# sentence-transformers pulls torch, and the default PyPI torch on linux-x86_64 is the
# multi-GB CUDA build — wasteful for CPU/AMD hosts. Install torch first from the wheel
# index matching COMPUTE_BACKEND so the later `-r requirements.txt` finds it already
# satisfied and never re-pulls the CUDA default.
#   cpu  (default) → CPU-only wheels (lean image, runs anywhere)
#   cuda           → NVIDIA GPU (default PyPI CUDA build)
#   rocm           → AMD GPU (ROCm wheels)
ARG COMPUTE_BACKEND=cpu
RUN case "$COMPUTE_BACKEND" in \
      cpu)  IDX="https://download.pytorch.org/whl/cpu" ;; \
      cuda) IDX="" ;; \
      rocm) IDX="https://download.pytorch.org/whl/rocm6.2" ;; \
      *) echo "unknown COMPUTE_BACKEND=$COMPUTE_BACKEND (use cpu|cuda|rocm)" >&2; exit 1 ;; \
    esac; \
    if [ -n "$IDX" ]; then \
      pip install --no-cache-dir --index-url "$IDX" torch; \
    else \
      pip install --no-cache-dir torch; \
    fi

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt arjun

COPY . .

EXPOSE 8000
CMD ["python3", "main.py"]
