FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

RUN for i in 1 2 3; do \
      apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nmap whatweb gobuster nikto sqlmap hydra ffuf \
        amass whois dnsutils ca-certificates git curl \
        subfinder httpx-toolkit nuclei naabu dnsx katana assetfinder \
        wpscan testssl.sh wafw00f exploitdb masscan enum4linux \
        seclists wordlists \
        ruby ruby-dev build-essential libssl-dev && break || sleep 5; \
    done && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt arjun

COPY . .

EXPOSE 8000
CMD ["python3", "main.py"]
