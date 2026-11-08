#!/usr/bin/env python3
"""Repository convention checks (spec section 7).

Not a correctness checker: it only enforces conventions that NASM does not.
Prints one line per problem as path:line: message and exits 1 if any.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

ASM_DIRS = ("src", "include")
PY_DIRS = ("tests", "scripts")

# Fields every exported symbol's header comment must have (spec section 9).
DOC_FIELDS = (
    "Purpose",
    "Args",
    "Returns",
    "Modifies",
    "Preserves",
    "Stack",
    "Inputs",
    "Overlap",
)

GNU_STACK_RE = re.compile(r"^\s*section\s+\.note\.GNU-stack\b", re.IGNORECASE)
GLOBAL_RE = re.compile(r"^\s*global\s+(.+?)\s*(;.*)?$", re.IGNORECASE)
LABEL_RE = re.compile(r"^([A-Za-z_.][\w.]*):")
EQU_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s+equ\b", re.IGNORECASE)
LABEL_NAME_RE = re.compile(r"^\.?[a-z_][a-z0-9_]*$")
CONSTANT_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

problems = []


def report(path, line_no, message):
    problems.append(f"{path.relative_to(ROOT)}:{line_no}: {message}")


def files(dirs, patterns):
    for d in dirs:
        for pattern in patterns:
            yield from sorted((ROOT / d).rglob(pattern))


def check_whitespace(path, text):
    for no, line in enumerate(text.splitlines(), 1):
        if line != line.rstrip():
            report(path, no, "trailing whitespace")
    if text and not text.endswith("\n"):
        report(path, len(text.splitlines()), "missing final newline")


def comment_block_above(lines, index):
    """Contiguous ';' comment lines directly above lines[index]."""
    block = []
    i = index - 1
    while i >= 0 and lines[i].lstrip().startswith(";"):
        block.append(lines[i])
        i -= 1
    return "\n".join(reversed(block))


def check_asm(path, text, exports):
    lines = text.splitlines()

    if path.suffix == ".asm" and not any(GNU_STACK_RE.match(l) for l in lines):
        report(path, 1, "missing 'section .note.GNU-stack noalloc noexec nowrite progbits'")

    for i, line in enumerate(lines):
        no = i + 1

        label = LABEL_RE.match(line)
        if label and not LABEL_NAME_RE.match(label.group(1)):
            report(path, no, f"label '{label.group(1)}' is not snake_case")

        equ = EQU_RE.match(line)
        if equ and not CONSTANT_NAME_RE.match(equ.group(1)):
            report(path, no, f"constant '{equ.group(1)}' is not UPPER_CASE")

        glob = GLOBAL_RE.match(line)
        if not glob:
            continue
        doc = comment_block_above(lines, i)
        for name in glob.group(1).split(","):
            name = name.split(":")[0].strip()
            if name in exports:
                report(path, no, f"'{name}' already exported at {exports[name]}")
            else:
                exports[name] = f"{path.relative_to(ROOT)}:{no}"
            missing = [f for f in DOC_FIELDS if not re.search(rf"^\s*;\s*{f}:", doc, re.M)]
            if missing:
                report(path, no, f"'{name}' header comment lacks: {', '.join(missing)}")


def main():
    exports = {}
    for path in files(ASM_DIRS, ("*.asm", "*.inc")):
        text = path.read_text()
        check_whitespace(path, text)
        check_asm(path, text, exports)
    for path in files(PY_DIRS, ("*.py",)):
        check_whitespace(path, path.read_text())

    for line in problems:
        print(line)
    if problems:
        print(f"{len(problems)} problem(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
