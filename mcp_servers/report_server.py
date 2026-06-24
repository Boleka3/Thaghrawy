import os
import datetime

from mcp.server.fastmcp import FastMCP
from fpdf import FPDF

import config

mcp = FastMCP("ReportServer")


@mcp.tool()
def generate_report(content_markdown: str, filename_prefix: str = "pentest_report") -> str:
    """
    Generate a penetration testing report in Markdown and PDF formats.
    :param content_markdown: The content of the report in Markdown format.
    :param filename_prefix: The prefix for the generated filenames.
    """
    content_markdown = content_markdown.replace('\\n', '\n').replace('\\"', '"')

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    md_filename = f"{filename_prefix}_{timestamp}.md"
    pdf_filename = f"{filename_prefix}_{timestamp}.pdf"

    reports_dir = config.REPORTS_DIR
    os.makedirs(reports_dir, exist_ok=True)

    md_path = os.path.join(reports_dir, md_filename)
    pdf_path = os.path.join(reports_dir, pdf_filename)

    try:
        with open(md_path, "w") as f:
            f.write(content_markdown)
    except Exception as e:
        return f"Error saving Markdown report: {str(e)}"

    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        for line in content_markdown.split("\n"):
            clean_line = line.encode("latin-1", "replace").decode("latin-1")
            pdf.cell(200, 10, txt=clean_line, ln=True)
        pdf.output(pdf_path)
    except Exception as e:
        return f"Markdown saved to {md_path}, but PDF generation failed: {str(e)}"

    return f"Reports generated successfully:\nMarkdown: {md_path}\nPDF: {pdf_path}"


if __name__ == "__main__":
    mcp.run()
