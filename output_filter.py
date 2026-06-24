import re


class ToolOutputFilter:
    """
    Class to filter and truncate raw tool outputs to keep the LLM context window clean.
    """

    @staticmethod
    def filter_nmap(raw: str) -> list:
        """Extracts only lines containing open ports and services."""
        findings = []
        for line in raw.split("\n"):
            if "/tcp" in line and "open" in line:
                findings.append(line.strip())
        return findings

    @staticmethod
    def filter_sqlmap(raw: str) -> list:
        """Extracts only injectable/payload/title lines from sqlmap output."""
        findings = []
        pattern = re.compile(r"\[(INFO|CRITICAL)\].*?(injectable|payload|title|parameter):.*", re.IGNORECASE)
        for line in raw.split("\n"):
            if pattern.search(line):
                findings.append(line.strip())
        return findings

    @staticmethod
    def filter_nikto(raw: str) -> list:
        """Extracts only OSVDB and vulnerability lines from nikto output."""
        findings = []
        for line in raw.split("\n"):
            if "+ OSVDB" in line or "Vulnerability" in line:
                findings.append(line.strip())
        return findings

    @staticmethod
    def filter_generic(raw: str, max_chars: int = 2000) -> str:
        """Smart truncation: keeps the head and tail of the output if it's too long."""
        if len(raw) <= max_chars:
            return raw
        half = max_chars // 2
        head = raw[:half]
        tail = raw[-half:]
        return f"{head}\n\n[... TRUNCATED BY FILTER ...]\n\n{tail}"

    @classmethod
    def apply_filter(cls, tool_name: str, raw_output: str) -> dict:
        """
        Dispatches the raw output to the appropriate filter based on tool name.
        """
        tool_name = tool_name or ""
        data = []
        if "nmap" in tool_name.lower():
            data = cls.filter_nmap(raw_output)
        elif "sqlmap" in tool_name.lower():
            data = cls.filter_sqlmap(raw_output)
        elif "nikto" in tool_name.lower():
            data = cls.filter_nikto(raw_output)
        else:
            trunc = cls.filter_generic(raw_output)
            return {
                "raw_truncated": trunc,
                "summary": cls.filter_generic(raw_output, max_chars=500),
                "count": 1,
            }

        return {
            "findings": data,
            "count": len(data),
            "summary": cls.filter_generic(raw_output, max_chars=500),
        }
