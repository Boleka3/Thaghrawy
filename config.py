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
DANGEROUS_COMMANDS_REQUIRE_CONFIRM = os.getenv(
    "DANGEROUS_COMMANDS_REQUIRE_CONFIRM", "true"
).lower() == "true"

DEFAULT_TARGET = os.getenv("TARGET", "")
