"""Tests for mcp_servers/report_server.render_to_files - the markdown -> md/pdf
renderer. Writes go to config.REPORTS_DIR, which conftest redirects to a tmp."""
import os

from mcp_servers.report_server import render_to_files


def test_render_to_files_writes_markdown_and_pdf():
    result = render_to_files("# Title\n\nSome **findings** here.", "test_report")
    assert "markdown" in result and "pdf" in result
    assert os.path.isfile(result["markdown"])
    assert os.path.isfile(result["pdf"])


def test_render_to_files_preserves_backslash_content():
    # Regression: the old code ran .replace('\\n','\n') which corrupted
    # legitimate backslash content. A Windows path must survive verbatim.
    result = render_to_files("Path: C:\\Users\\admin\\report", "test_report")
    content = open(result["markdown"], encoding="utf-8").read()
    assert "C:\\Users\\admin\\report" in content


def test_render_to_files_uses_prefix_in_filenames():
    result = render_to_files("# X", "my_custom_prefix")
    assert "my_custom_prefix" in os.path.basename(result["markdown"])
    assert result["markdown"].endswith(".md")
    assert result["pdf"].endswith(".pdf")
