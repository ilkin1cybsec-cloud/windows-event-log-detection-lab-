"""
Export Markdown documents in this project to simple PDFs.

This script uses only Python's standard library so the lab can run without
installing extra packages.
"""

from pathlib import Path
import textwrap


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPORTS = [
    (PROJECT_ROOT / "reports" / "detection_report.md", PROJECT_ROOT / "reports" / "detection_report.pdf"),
    (PROJECT_ROOT / "docs" / "interview_explanation.md", PROJECT_ROOT / "docs" / "interview_explanation.pdf"),
]


def escape_pdf_text(text):
    """Escape characters that have special meaning inside PDF text objects."""
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def clean_markdown_line(line):
    """Remove basic Markdown characters for cleaner PDF output."""
    line = line.strip()

    for heading in ("### ", "## ", "# "):
        if line.startswith(heading):
            return line.replace(heading, "")

    if line.startswith("- "):
        return "* " + line[2:]
    if line.startswith("> "):
        return line[2:]

    return line.replace("`", "")


def markdown_to_lines(markdown_text):
    """Convert Markdown text into wrapped PDF lines."""
    output_lines = []

    for raw_line in markdown_text.splitlines():
        line = clean_markdown_line(raw_line)

        if not line:
            output_lines.append("")
            continue

        output_lines.extend(textwrap.wrap(line, width=88))

    return output_lines


def build_pdf(lines):
    """Build a minimal readable PDF document."""
    lines_per_page = 44
    pages = [lines[index : index + lines_per_page] for index in range(0, len(lines), lines_per_page)]
    objects = []

    def add_object(content):
        objects.append(content)
        return len(objects)

    catalog_id = add_object("<< /Type /Catalog /Pages 2 0 R >>")
    pages_id = add_object("")
    font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids = []

    for page_lines in pages:
        text_commands = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]

        for line in page_lines:
            safe_line = escape_pdf_text(line.encode("latin-1", "replace").decode("latin-1"))
            text_commands.append(f"({safe_line}) Tj")
            text_commands.append("T*")

        text_commands.append("ET")
        stream = "\n".join(text_commands)
        content_id = add_object(f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream")
        page_id = add_object(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        )
        page_ids.append(page_id)

    objects[pages_id - 1] = (
        f"<< /Type /Pages /Count {len(page_ids)} /Kids "
        f"[{' '.join(f'{page_id} 0 R' for page_id in page_ids)}] >>"
    )

    pdf_parts = ["%PDF-1.4\n"]
    offsets = [0]

    for object_id, content in enumerate(objects, start=1):
        offsets.append(sum(len(part.encode("latin-1")) for part in pdf_parts))
        pdf_parts.append(f"{object_id} 0 obj\n{content}\nendobj\n")

    xref_offset = sum(len(part.encode("latin-1")) for part in pdf_parts)
    pdf_parts.append(f"xref\n0 {len(objects) + 1}\n")
    pdf_parts.append("0000000000 65535 f \n")

    for offset in offsets[1:]:
        pdf_parts.append(f"{offset:010d} 00000 n \n")

    pdf_parts.append(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    )

    return "".join(pdf_parts).encode("latin-1")


def export_markdown_to_pdf(markdown_file, pdf_file):
    """Read one Markdown file and write one PDF file."""
    markdown_text = markdown_file.read_text(encoding="utf-8")
    lines = markdown_to_lines(markdown_text)
    pdf_file.write_bytes(build_pdf(lines))
    print(f"PDF created: {pdf_file}")


def main():
    """Export all configured Markdown files to PDF."""
    for markdown_file, pdf_file in EXPORTS:
        if markdown_file.exists():
            export_markdown_to_pdf(markdown_file, pdf_file)


if __name__ == "__main__":
    main()
