"""Smoke tests for config.py defaults and types (env is set by conftest)."""
import os

import config


def test_directories_are_created():
    for d in (config.ENGAGEMENTS_DIR, config.WORKSPACE_DIR, config.REPORTS_DIR):
        assert os.path.isdir(d)


def test_numeric_settings_have_expected_types():
    assert isinstance(config.MAX_TOKENS, int)
    assert isinstance(config.TEMPERATURE, float)
    assert isinstance(config.RECON_TIMEOUT, int)
    assert isinstance(config.MAX_SHELL_TIMEOUT, int)


def test_provider_default_is_lowercased():
    assert config.LLM_PROVIDER == config.LLM_PROVIDER.lower()


def test_dangerous_confirm_flag_is_bool():
    assert isinstance(config.DANGEROUS_COMMANDS_REQUIRE_CONFIRM, bool)
