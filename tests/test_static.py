"""Static boundaries: which modules may touch the network, and no private references."""

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "olc"
NETWORK = {"urllib", "http", "ssl", "socket", "ftplib", "smtplib", "asyncio", "selectors"}
EXECUTION = {"subprocess", "multiprocessing", "pty", "importlib", "runpy", "ctypes"}


def imports(path):
    names = set()
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names |= {f"{node.module}.{a.name}" for a in node.names}
    return names


class ImportBoundaryTests(unittest.TestCase):
    def test_only_net_imports_network_modules(self):
        for path in PACKAGE.rglob("*.py"):
            top = {n.split(".")[0] for n in imports(path)}
            if path.name == "net.py":
                continue
            self.assertFalse(top & NETWORK, f"{path.relative_to(ROOT)} imports {top & NETWORK}")

    def test_nothing_executes_code(self):
        for path in PACKAGE.rglob("*.py"):
            top = {n.split(".")[0] for n in imports(path)}
            self.assertFalse(top & EXECUTION, f"{path.relative_to(ROOT)} imports {top & EXECUTION}")
            text = path.read_text()
            for call in ("eval(", "exec(", "__import__(", "os.system", "os.popen", ".extractall("):
                self.assertNotIn(call, text, f"{path.relative_to(ROOT)} uses {call}")

    def test_inspection_never_reaches_the_network(self):
        offline = [PACKAGE / "inspect.py", PACKAGE / "archive.py", PACKAGE / "fonts.py",
                   PACKAGE / "pymeta.py", *(PACKAGE / "rules").glob("*.py")]
        for path in offline:
            self.assertNotIn("olc.net", imports(path), path.name)
            self.assertNotIn("olc.registry", " ".join(imports(path)), path.name)


# Assembled so this file does not match itself.
LEAK_PATTERNS = [re.compile(p) for p in (
    "LIC" + r"-\d{4}", "DEC" + r"-\d{4}", r"\bV" + r"-\d{4}", "regis" + "ter/",
    "opengeos-licensing" + "-private", "/home" + "/", "/mnt" + "/scratch")]
SKIP_DIRS = {".git", "__pycache__", ".venv", "build", "dist"}


class LeakTests(unittest.TestCase):
    def test_no_private_references(self):
        hits = []
        for path in ROOT.rglob("*"):
            if not path.is_file() or SKIP_DIRS & set(path.relative_to(ROOT).parts):
                continue
            if path.name == "AGENTS.md":  # local agent notes, reviewed separately before publication
                continue
            text = path.read_text(errors="replace")
            hits += [f"{path.relative_to(ROOT)}: {p.pattern}" for p in LEAK_PATTERNS
                     if p.search(text)]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
