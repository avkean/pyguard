#!/usr/bin/env python3
# Minify a Python source file by stripping comments, docstrings, and blank
# lines. Preserves semantics (and line semantics: indentation, line-continuation,
# triple-quoted non-docstring strings, f-strings, etc.).
#
# Used by scripts/gen-interpreter-src.mjs to shrink lib/v5/runtime_interp.py
# before it is embedded into stubs. Shaves ~40% off the interpreter source,
# which directly shrinks the encrypted stage2 ciphertext and therefore the
# generated stub.
#
# Usage: python3 minify_py.py < input.py > output.py
#
# The minifier is intentionally conservative: it only removes things that
# are known-safe (comments, blank lines, module/class/function docstrings).
# It does not rename identifiers, collapse indentation, or join lines.

import ast
import io
import sys
import tokenize


def collect_docstring_lines(src: str) -> set:
    """Return the set of 1-based line numbers occupied by docstring Expr
    statements in module/class/def bodies. A docstring is defined as the
    first statement of a body when that statement is an Expr wrapping a
    Constant string."""
    tree = ast.parse(src)
    out = set()
    for node in ast.walk(tree):
        if not isinstance(
            node,
            (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr):
            continue
        val = first.value
        if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
            continue
        # Must not be the sole statement — if we stripped it the body would
        # become empty and Python would reject it. Caller already verified
        # this isn't the case for our interpreter source; we still guard to
        # avoid producing broken output on unexpected inputs.
        if len(body) == 1:
            continue
        start = first.lineno
        end = getattr(first, "end_lineno", start)
        for ln in range(start, end + 1):
            out.add(ln)
    return out


def strip_comments(src: str) -> list:
    """Return a list of source lines with COMMENT tokens erased.

    We use tokenize so that a `#` inside a string literal is correctly
    left alone.
    """
    lines = src.splitlines(keepends=True)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except tokenize.TokenizeError:
        return lines
    # Walk in reverse so that per-line column offsets remain valid as we
    # erase spans.
    for tok in reversed(tokens):
        if tok.type != tokenize.COMMENT:
            continue
        (sl, sc) = tok.start
        (_, ec) = tok.end
        line = lines[sl - 1]
        # Keep everything up to the comment, strip trailing whitespace from
        # the remainder (to avoid leaving a line full of spaces), preserve
        # the newline at the end.
        before = line[:sc].rstrip()
        after = line[ec:]
        # If the line had only the comment plus a newline, leave just the
        # newline — the downstream blank-line filter will drop it.
        if before == "":
            lines[sl - 1] = after if after.endswith("\n") else after + "\n"
        else:
            # Preserve indentation on the kept prefix; re-attach newline.
            nl = "\n" if line.endswith("\n") else ""
            lines[sl - 1] = before + nl
    return lines


def minify(src: str) -> str:
    docstring_lines = collect_docstring_lines(src)
    lines = strip_comments(src)
    out = []
    for i, line in enumerate(lines, start=1):
        if i in docstring_lines:
            continue
        if line.strip() == "":
            continue
        out.append(line if line.endswith("\n") else line + "\n")
    return "".join(out)


def main() -> None:
    data = sys.stdin.buffer.read().decode("utf-8")
    sys.stdout.write(minify(data))


if __name__ == "__main__":
    main()
