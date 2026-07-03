import os
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────
# LLM Provider
# ──────────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic").lower()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
# Set OPENAI_BASE_URL to point at an OpenAI-compatible endpoint (e.g. LM Studio).
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL") or None

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))

# Max assistant<->tool round-trips per user turn in the agent ReAct loop. A real
# multi-subdomain recon needs headroom; keep it bounded to cap runaway loops/cost.
MAX_TOOL_ITERATIONS = int(os.getenv("MAX_TOOL_ITERATIONS", "20"))

# ──────────────────────────────────────────────
# Context management
# ──────────────────────────────────────────────
MAX_FILTER_CHARS = int(os.getenv("MAX_FILTER_CHARS", "2000"))
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "16000"))

# ──────────────────────────────────────────────
# ChromaDB / memory layer
# ──────────────────────────────────────────────
CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
EMBEDDING_MODEL_PATH = os.getenv(
    "EMBEDDING_MODEL_PATH",
    "sentence-transformers/all-MiniLM-L6-v2",
)

# ──────────────────────────────────────────────
# Engagements / workspace
# ──────────────────────────────────────────────
ENGAGEMENTS_DIR = os.getenv("ENGAGEMENTS_DIR", "./engagements/sessions")
WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", "./engagements/sessions/_workspace")
REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")

for _dir in (ENGAGEMENTS_DIR, WORKSPACE_DIR, REPORTS_DIR):
    os.makedirs(_dir, exist_ok=True)

# ──────────────────────────────────────────────
# App
# ──────────────────────────────────────────────
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8000"))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# ──────────────────────────────────────────────
# Security
# ──────────────────────────────────────────────
MAX_SHELL_TIMEOUT = int(os.getenv("MAX_SHELL_TIMEOUT", "30"))
RECON_TIMEOUT = int(os.getenv("RECON_TIMEOUT", "180"))

# Colon-separated PATH prefixes for subprocess tool execution (tools like
# nmap, nuclei, httpx typically live in ~/go/bin or /usr/local/bin).
# Empty means the default: ["~/go/bin", "/usr/local/bin"]
TOOL_PATH_PREFIXES = os.getenv("TOOL_PATH_PREFIXES", "").split(":") if os.getenv("TOOL_PATH_PREFIXES") else []
DANGEROUS_COMMANDS_REQUIRE_CONFIRM = os.getenv(
    "DANGEROUS_COMMANDS_REQUIRE_CONFIRM", "true"
).lower() == "true"

# ──────────────────────────────────────────────
# Human-in-the-loop
# ──────────────────────────────────────────────
# Which tool calls pause for human approval during the COLLABORATION phase:
#   all       - every tool call (default; maximum oversight)
#   dangerous - only tools flagged dangerous=True (exploit tools + shell)
#   off        - never gate (fully autonomous even when collaborating)
# The enumeration phase is always approval-free; see core/control.py.
HUMAN_APPROVAL_MODE = os.getenv("HUMAN_APPROVAL_MODE", "all").lower()

DEFAULT_TARGET = os.getenv("TARGET", "")

# ──────────────────────────────────────────────
# Flag/secret detection
# ──────────────────────────────────────────────
FLAG_REGEX = os.getenv("FLAG_REGEX", "")
