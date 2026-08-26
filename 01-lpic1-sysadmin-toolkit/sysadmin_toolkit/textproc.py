"""Text processing/filter utilities. LPIC-1 topic 103.7 (text streams and filters)."""

import re
from collections import Counter
from pathlib import Path

WORD_RE = re.compile(r"[A-Za-z']+")


def word_frequency(path, top_n=10):
    text = Path(path).read_text()
    words = (w.lower() for w in WORD_RE.findall(text))
    return Counter(words).most_common(top_n)


def dedupe_lines(path):
    """Remove duplicate lines, keeping the first occurrence and original order.
    Different from `sort -u` which reorders."""
    seen = set()
    result = []
    for line in Path(path).read_text().splitlines():
        if line not in seen:
            seen.add(line)
            result.append(line)
    return result


def grep_lines(pattern, path, context=0, ignore_case=False):
    """Return matching lines with optional context, similar to grep -C.

    Each result is a dict with the matched line number (1-indexed), the line
    itself, and before/after context lines.
    """
    flags = re.IGNORECASE if ignore_case else 0
    regex = re.compile(pattern, flags)
    lines = Path(path).read_text().splitlines()

    results = []
    for i, line in enumerate(lines):
        if regex.search(line):
            before = lines[max(0, i - context):i]
            after = lines[i + 1:i + 1 + context]
            results.append({
                "line_number": i + 1,
                "line": line,
                "before": before,
                "after": after,
            })
    return results


def extract_column(path, delimiter, field, skip_header=False):
    """Like `cut -d<delimiter> -f<field>`, field is 1-indexed."""
    lines = Path(path).read_text().splitlines()
    if skip_header and lines:
        lines = lines[1:]

    values = []
    for line in lines:
        parts = line.split(delimiter)
        if field - 1 < len(parts):
            values.append(parts[field - 1])
    return values
