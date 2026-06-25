import os
import datetime

import markdown as md
from mcp.server.fastmcp import FastMCP
from xhtml2pdf import pisa

import config

mcp = FastMCP("ReportServer")

_PDF_CSS = """
<style>
  body { font-family: Helvetica, Arial, sans-serif; font-size: 11pt; }
  h1 { font-size: 20pt; border-bottom: 2px solid #333; padding-bottom: 6px; }
  h2 { font-size: 15pt; margin-top: 18px; color: #222; }
  h3 { font-size: 12.5pt; margin-top: 14px; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0; }
  th, td { border: 1px solid #999; padding: 4px 8px; text-align: left; }
  code, pre { font-family: Courier, monospace; background-color: #f0f0f0; }
</style>
"""


def render_to_files(content_markdown: str, filename_prefix: str = "pentest_report") -> dict[str, str]:
    """Write `content_markdown` to a timestamped .md file and a matching
    properly-formatted .pdf (markdown -> HTML -> xhtml2pdf) under
    config.REPORTS_DIR. Returns the paths, or an "error" key on failure."""
    content_markdown = content_markdown.replace('\\n', '\n').replace('\\"', '"')

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    md_filename = f"{filename_prefix}_{timestamp}.md"
    pdf_filename = f"{filename_prefix}_{timestamp}.pdf"

    reports_dir = config.REPORTS_DIR
    os.makedirs(reports_dir, exist_ok=True)

    md_path = os.path.join(reports_dir, md_filename)
    pdf_path = os.path.join(reports_dir, pdf_filename)

    try:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(content_markdown)
    except Exception as e:
        return {"error": f"Error saving Markdown report: {str(e)}"}

    try:
        html_body = md.markdown(content_markdown, extensions=["extra", "sane_lists"])
        html = f"<html><head>{_PDF_CSS}</head><body>{html_body}</body></html>"
        with open(pdf_path, "wb") as f:
            result = pisa.CreatePDF(html, dest=f, encoding="utf-8")
        if result.err:
            return {"error": f"Markdown saved to {md_path}, but PDF generation failed", "markdown": md_path}
    except Exception as e:
        return {"error": f"Markdown saved to {md_path}, but PDF generation failed: {str(e)}", "markdown": md_path}

    return {"markdown": md_path, "pdf": pdf_path}


@mcp.tool()
def generate_report(content_markdown: str, filename_prefix: str = "pentest_report") -> str:
    """
    Generate a penetration testing report in Markdown and PDF formats from
    hand-written content. Kept for manual/ad-hoc use - the agent's main
    reporting tool is the data-driven generate_report registered in
    core/tools.py, which builds both a technical and an executive report
    from saved findings.
    :param content_markdown: The content of the report in Markdown format.
    :param filename_prefix: The prefix for the generated filenames.
    """
    paths = render_to_files(content_markdown, filename_prefix)
    if "error" in paths:
        return paths["error"]
    return f"Reports generated successfully:\nMarkdown: {paths['markdown']}\nPDF: {paths['pdf']}"


if __name__ == "__main__":
    mcp.run()
