"""Red-team corpus definitions: 100 adversarial and control scenarios.

Every case is a real fixture tree plus the verdict a security review would
expect. The corpus is deliberately organised by detector so that recall can be
read per category, and it contains clean controls so that false positives are
measured instead of hidden.
"""

from __future__ import annotations

import base64
import hashlib
import os
import pickle
import py_compile
import shutil
import subprocess
import sys
from pathlib import Path

from tests.corpus_runner import CorpusCase

NEWLINE = chr(10)
GH_CLASSIC = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GH_FINE = "github_pat_" + "A" * 82
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
SLACK = "xoxb-123456789012-123456789012-" + "a" * 24
STRIPE = "sk_live_" + "a" * 24
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "a" * 43
DB_URI = "postgres://app:" + "S3cretPassw0rd" + "@db.example.test:5432/prod"
NPM = "npm_" + "b" * 36

SECRETS = {
    "github_classic": (".env", "GITHUB_TOKEN=" + GH_CLASSIC),
    "github_fine_grained": ("config.py", "TOKEN = '" + GH_FINE + "'"),
    "aws_pair": (".aws/credentials", "[default]" + NEWLINE + "aws_access_key_id = " + AWS_KEY + NEWLINE + "aws_secret_access_key = " + AWS_SECRET),
    "slack_bot": (".env", "SLACK_BOT_TOKEN=" + SLACK),
    "stripe_live": ("settings.py", "STRIPE_KEY = '" + STRIPE + "'"),
    "jwt": ("config.json", '{"token": "' + JWT + '"}'),
    "db_uri": ("settings.py", "DATABASE_URL = '" + DB_URI + "'"),
    "npm_token": (".npmrc", "//registry.npmjs.org/:_authToken=" + NPM),
    "remote_url": (".git/config", "[remote " + chr(34) + "origin" + chr(34) + "]" + NEWLINE + chr(9) + "url = https://user:" + GH_CLASSIC + "@example.test/r.git"),
    "ssh_key": ("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----" + NEWLINE + "b3BlbnNzaC1rZXktdjEAAAAA" + NEWLINE + "-----END OPENSSH PRIVATE KEY-----"),
}


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + NEWLINE, encoding="utf-8")


def _write_bytes(root: Path, rel: str, data: bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _git(root: Path, *args: str) -> None:
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_NAME", "Corpus")
    env.setdefault("GIT_AUTHOR_EMAIL", "corpus@example.test")
    env.setdefault("GIT_COMMITTER_NAME", "Corpus")
    env.setdefault("GIT_COMMITTER_EMAIL", "corpus@example.test")
    completed = subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True, env=env, timeout=120)
    if completed.returncode != 0:
        raise RuntimeError("git " + " ".join(args) + " failed: " + completed.stderr.strip())


def _history_case(secret_text: str, path: str = ".env") -> object:
    def build(root: Path) -> None:
        if shutil.which("git") is None:
            raise RuntimeError("git is required for history cases")
        _git(root, "init", "-q")
        _write(root, "app.py", "VALUE = 1")
        _write(root, path, secret_text)
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "add secret")
        (root / path).unlink()
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "remove secret")

    return build


def _malicious_pickle(target: str, argument: str) -> bytes:
    module, _, attribute = target.rpartition(".")
    payload = argument

    class Evil:
        def __reduce__(self):
            import importlib

            function = getattr(importlib.import_module(module), attribute)
            return (function, (payload,))

    return pickle.dumps(Evil(), protocol=4)


def _venv(root: Path) -> Path:
    config = root / ".venv" / "pyvenv.cfg"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("home = " + sys.base_prefix + NEWLINE + "include-system-site-packages = false" + NEWLINE, encoding="utf-8")
    site_packages = root / ".venv" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    return site_packages


def _dist_with_record(root: Path, files: dict[str, bytes], *, tamper: str | None = None) -> Path:
    site_packages = _venv(root)
    dist_info = site_packages / "demo_pkg-1.0.0.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for rel, data in files.items():
        path = site_packages / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
        lines.append(rel + ",sha256=" + digest + "," + str(len(data)))
    lines.append("demo_pkg-1.0.0.dist-info/RECORD,,")
    (dist_info / "RECORD").write_text(NEWLINE.join(lines) + NEWLINE, encoding="utf-8")
    if tamper == "corrupt":
        first = site_packages / sorted(files)[0]
        first.write_bytes(first.read_bytes() + b"tampered")
    elif tamper == "missing":
        (site_packages / sorted(files)[0]).unlink()
    elif tamper == "blank":
        text = (dist_info / "RECORD").read_text(encoding="utf-8").replace(",sha256=", ",sha256=,,").split(NEWLINE)
        rebuilt = []
        for line in text:
            parts = line.split(",")
            if len(parts) >= 3 and parts[1].startswith("sha256="):
                rebuilt.append(parts[0] + ",," + parts[-1])
            else:
                rebuilt.append(line)
        (dist_info / "RECORD").write_text(NEWLINE.join(rebuilt), encoding="utf-8")
    return dist_info


def _compile_pyc(root: Path, module: str = "mod.py") -> tuple[Path, Path]:
    source = root / module
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("VALUE = 1" + NEWLINE, encoding="utf-8")
    cfile = root / "__pycache__" / (Path(module).stem + ".cpython-312.pyc")
    cfile.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(str(source), cfile=str(cfile), doraise=True)
    return source, cfile


CASES: list[CorpusCase] = []
CRITICAL = frozenset({"CRITICAL"})
SAFE = frozenset({"SAFE"})
WARNING = frozenset({"WARNING"})
DETECTED = frozenset({"LEAK_DETECTED"})
SECURE = frozenset({"SECURE"})

# ---------------------------------------------------------------- secrets, live
for index, (name, (rel, content)) in enumerate(SECRETS.items()):
    def build(root: Path, rel: str = rel, content: str = content) -> None:
        _write(root, rel, content)

    CASES.append(
        CorpusCase(
            case_id=f"secret-live-{index:02d}-{name}",
            category="secrets_current",
            description="credential committed to the working tree: " + name,
            build=build,
            expect={11: DETECTED},
        )
    )

# ------------------------------------------------------------- secrets, history
for index, (name, (rel, content)) in enumerate(SECRETS.items()):
    build_history = _history_case(content, ".env" if rel.endswith("credentials") or rel.startswith(".git") else rel)
    CASES.append(
        CorpusCase(
            case_id=f"secret-history-{index:02d}-{name}",
            category="secrets_history",
            description="secret committed once and removed later: " + name,
            build=build_history,
            expect={11: DETECTED},
        )
    )

# --------------------------------------------------------------- unsafe pickles
PICKLE_PAYLOADS = (
    ("os-system", _malicious_pickle("os.system", "echo pwned")),
    ("subprocess-popen", _malicious_pickle("subprocess.Popen", "echo pwned")),
    ("builtins-eval", _malicious_pickle("builtins.eval", "1+1")),
    ("builtins-exec", _malicious_pickle("builtins.exec", "print(1)")),
    ("os-popen", _malicious_pickle("os.popen", "echo pwned")),
    ("os-execv", _malicious_pickle("os.execv", "x")),
    ("stack-global", b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x051+1+1\x85R."),
    ("persid", b"\x80\x02P1\n."),
    ("benign-list", pickle.dumps([1, 2, 3, 4], protocol=4)),
    ("malformed", b"\x80\x04not-a-pickle"),
)
for index, (name, blob) in enumerate(PICKLE_PAYLOADS):
    expected = SAFE if name == "benign-list" else (WARNING if name == "malformed" else CRITICAL)
    def build(root: Path, blob: bytes = blob) -> None:
        _write_bytes(root, "payload.pkl", blob)

    CASES.append(
        CorpusCase(
            case_id=f"pickle-{index:02d}-{name}",
            category="pickle_payloads",
            description="serialized payload variant: " + name,
            build=build,
            expect={6: expected},
        )
    )

# ------------------------------------------------------------------ pyc tamper
def _pyc_valid(root: Path) -> None:
    _compile_pyc(root)


def _pyc_stale(root: Path) -> None:
    source, _ = _compile_pyc(root)
    source.write_text("VALUE = 2" + NEWLINE + "# changed" + NEWLINE, encoding="utf-8")


def _pyc_orphan(root: Path) -> None:
    source, cfile = _compile_pyc(root)
    source.unlink()
    assert cfile.is_file()


def _pyc_truncated(root: Path) -> None:
    _, cfile = _compile_pyc(root)
    cfile.write_bytes(cfile.read_bytes()[:8])


def _pyc_bad_magic(root: Path) -> None:
    _, cfile = _compile_pyc(root)
    data = bytearray(cfile.read_bytes())
    data[0:4] = b"\x00\x00\x00\x00"
    cfile.write_bytes(bytes(data))


def _pyc_hash_mode_valid(root: Path) -> None:
    source = root / "mod.py"
    source.write_text("VALUE = 1" + NEWLINE, encoding="utf-8")
    cfile = root / "__pycache__" / "mod.cpython-312.pyc"
    cfile.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(str(source), cfile=str(cfile), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)


def _pyc_hash_mode_stale(root: Path) -> None:
    _pyc_hash_mode_valid(root)
    (root / "mod.py").write_text("VALUE = 2" + NEWLINE, encoding="utf-8")


def _pyc_in_package(root: Path) -> None:
    package = root / "pkg"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("VALUE = 1" + NEWLINE, encoding="utf-8")
    py_compile.compile(str(package / "__init__.py"), doraise=True)


def _pyc_legacy_location(root: Path) -> None:
    source = root / "legacy.py"
    source.write_text("VALUE = 1" + NEWLINE, encoding="utf-8")
    py_compile.compile(str(source), cfile=str(root / "legacy.pyc"), doraise=True)


PYC_CASES = (
    ("valid", _pyc_valid, SAFE),
    ("stale-source", _pyc_stale, CRITICAL),
    ("orphan", _pyc_orphan, WARNING),
    ("truncated", _pyc_truncated, WARNING),
    ("bad-magic", _pyc_bad_magic, WARNING),
    ("hash-valid", _pyc_hash_mode_valid, SAFE),
    ("hash-stale", _pyc_hash_mode_stale, CRITICAL),
    ("package-valid", _pyc_in_package, SAFE),
    ("legacy-location", _pyc_legacy_location, None),
    ("clean-tree", _pyc_valid, SAFE),
)
for index, (name, builder, expected) in enumerate(PYC_CASES):
    expectations = {6: expected} if expected is not None else {}
    CASES.append(
        CorpusCase(
            case_id=f"pyc-{index:02d}-{name}",
            category="pyc_tamper",
            description="bytecode cache state: " + name,
            build=builder,
            expect=expectations,
        )
    )

# --------------------------------------------------------------- dangerous APIs
DANGEROUS = (
    ("eval-input", "user = input()" + NEWLINE + "eval(user)", CRITICAL),
    ("exec-input", "user = input()" + NEWLINE + "exec(user)", CRITICAL),
    ("os-system", "import os" + NEWLINE + "os.system('echo hi')", CRITICAL),
    ("popen-shell-true", "import subprocess" + NEWLINE + "subprocess.Popen('dir', shell=True)", CRITICAL),
    ("popen-shell-false", "import subprocess" + NEWLINE + "subprocess.run(['dir'], shell=False, check=False)", SAFE),
    ("yaml-load", "import yaml" + NEWLINE + "yaml.load(open('a.yml', 'rb'))", CRITICAL),
    ("yaml-safe-load", "import yaml" + NEWLINE + "yaml.safe_load(open('a.yml', 'rb'))", SAFE),
    ("torch-load", "import torch" + NEWLINE + "torch.load('m.pt')", CRITICAL),
    ("tar-extractall", "import tarfile" + NEWLINE + "tarfile.open('a.tar').extractall('.')", WARNING),
    ("requests-verify-false", "import requests" + NEWLINE + "requests.get('https://example.test', verify=False)", WARNING),
)
for index, (name, code, expected) in enumerate(DANGEROUS):
    def build(root: Path, code: str = code) -> None:
        _write(root, "app.py", code)

    CASES.append(
        CorpusCase(
            case_id=f"api-{index:02d}-{name}",
            category="dangerous_apis",
            description="source construct: " + name,
            build=build,
            expect={6: expected},
        )
    )

# --------------------------------------------------------------- archive usage
ARCHIVES = (
    ("tar-extractall", "import tarfile" + NEWLINE + "tarfile.open('a.tar').extractall('.')"),
    ("zip-extractall", "import zipfile" + NEWLINE + "zipfile.ZipFile('a.zip').extractall('.')"),
    ("shutil-unpack", "import shutil" + NEWLINE + "shutil.unpack_archive('a.zip', '.')"),
    ("tar-filter-data", "import tarfile" + NEWLINE + "tarfile.open('a.tar').extractall('.', filter='data')"),
    ("zip-member-check", "import zipfile" + NEWLINE + "z = zipfile.ZipFile('a.zip')" + NEWLINE + "z.extract(z.infolist()[0], '.')"),
    ("tar-iteration", "import tarfile" + NEWLINE + "for m in tarfile.open('a.tar'):" + NEWLINE + "    open(m.name, 'wb').write(m.fileobj.read())"),
    ("subprocess-unzip", "import subprocess" + NEWLINE + "subprocess.run(['unzip', 'a.zip'])"),
    ("os-system-unzip", "import os" + NEWLINE + "os.system('unzip a.zip')"),
    ("no-archive", "VALUE = 1"),
    ("comment-only", "# tarfile.extractall is not used here" + NEWLINE + "VALUE = 1"),
)
for index, (name, code) in enumerate(ARCHIVES):
    expected = WARNING if name in {"tar-extractall", "zip-extractall", "shutil-unpack"} else (CRITICAL if name in {"os-system-unzip"} else SAFE)
    if name == "subprocess-unzip":
        expected = SAFE
    def build(root: Path, code: str = code) -> None:
        _write(root, "app.py", code)

    CASES.append(
        CorpusCase(
            case_id=f"archive-{index:02d}-{name}",
            category="archive_usage",
            description="archive handling: " + name,
            build=build,
            expect={6: expected},
        )
    )

# ------------------------------------------------------------- venv injection
def _pth_exec(root: Path) -> None:
    site_packages = _venv(root)
    (site_packages / "evil.pth").write_text("import os; os.system('calc')" + NEWLINE, encoding="utf-8")


def _pth_import(root: Path) -> None:
    site_packages = _venv(root)
    (site_packages / "hook.pth").write_text("import sys; sys.path.insert(0, '.')" + NEWLINE, encoding="utf-8")


def _sitecustomize(root: Path) -> None:
    site_packages = _venv(root)
    (site_packages / "sitecustomize.py").write_text("print('startup hook')" + NEWLINE, encoding="utf-8")


def _usercustomize(root: Path) -> None:
    site_packages = _venv(root)
    (site_packages / "usercustomize.py").write_text("print('user hook')" + NEWLINE, encoding="utf-8")


def _pth_outside_path(root: Path) -> None:
    site_packages = _venv(root)
    outside = root / "vendor"
    outside.mkdir(parents=True, exist_ok=True)
    (site_packages / "vendor.pth").write_text(str(outside) + NEWLINE, encoding="utf-8")


def _pth_dangling(root: Path) -> None:
    site_packages = _venv(root)
    (site_packages / "dangling.pth").write_text(str(root / "missing-dir") + NEWLINE, encoding="utf-8")


def _pth_clean(root: Path) -> None:
    site_packages = _venv(root)
    (site_packages / "clean.pth").write_text(str(site_packages) + NEWLINE, encoding="utf-8")


def _venv_malicious_dll(root: Path) -> None:
    site_packages = _venv(root)
    (site_packages / "rogue.dll").write_bytes(b"MZ" + os.urandom(2048))


def _venv_clean_only(root: Path) -> None:
    _venv(root)


VENV_CASES = (
    ("pth-exec", _pth_exec, frozenset({"MALICIOUS_PTH"})),
    ("pth-import", _pth_import, frozenset({"MALICIOUS_PTH"})),
    ("sitecustomize", _sitecustomize, frozenset({"TAMPERED"})),
    ("usercustomize", _usercustomize, frozenset({"TAMPERED"})),
    ("pth-outside-path", _pth_outside_path, frozenset({"TAMPERED", "MALICIOUS_PTH"})),
    ("pth-dangling", _pth_dangling, frozenset({"CLEAN"})),
    ("pth-clean", _pth_clean, frozenset({"CLEAN"})),
    ("rogue-dll", _venv_malicious_dll, frozenset({"TAMPERED", "MALICIOUS_PTH"})),
    ("clean-venv", _venv_clean_only, frozenset({"CLEAN"})),
    ("no-venv", lambda root: _write(root, "app.py", "VALUE = 1"), frozenset({"CLEAN"})),
)
for index, (name, builder, expected) in enumerate(VENV_CASES):
    CASES.append(
        CorpusCase(
            case_id=f"venv-{index:02d}-{name}",
            category="venv_injection",
            description="environment tampering: " + name,
            build=builder,
            expect={10: expected},
        )
    )

# --------------------------------------------------------------- RECORD tamper
def _record_clean(root: Path) -> None:
    _dist_with_record(root, {"demo_pkg/__init__.py": b"VALUE = 1" + NEWLINE.encode()})


def _record_corrupt(root: Path) -> None:
    _dist_with_record(root, {"demo_pkg/__init__.py": b"VALUE = 1" + NEWLINE.encode()}, tamper="corrupt")


def _record_missing(root: Path) -> None:
    _dist_with_record(root, {"demo_pkg/__init__.py": b"VALUE = 1" + NEWLINE.encode()}, tamper="missing")


def _record_blank(root: Path) -> None:
    _dist_with_record(root, {"demo_pkg/__init__.py": b"VALUE = 1" + NEWLINE.encode()}, tamper="blank")


def _record_malformed(root: Path) -> None:
    site_packages = _venv(root)
    dist_info = site_packages / "demo_pkg-1.0.0.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "RECORD").write_text("this is not a record file" + NEWLINE, encoding="utf-8")


def _record_typosquat(root: Path) -> None:
    site_packages = _venv(root)
    dist_info = site_packages / "reqeusts-2.0.0.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "RECORD").write_text("reqeusts/__init__.py,," + NEWLINE, encoding="utf-8")
    package = site_packages / "reqeusts"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("VALUE = 1" + NEWLINE, encoding="utf-8")


def _record_interpreter_missing(root: Path) -> None:
    site_packages = _venv(root)
    config = root / ".venv" / "pyvenv.cfg"
    config.write_text("home = " + str(root / "missing-python") + NEWLINE, encoding="utf-8")
    (site_packages / "clean.pth").write_text(str(site_packages) + NEWLINE, encoding="utf-8")


RECORD_CASES = (
    ("clean", _record_clean, frozenset({"CLEAN"})),
    ("corrupt-hash", _record_corrupt, frozenset({"TAMPERED"})),
    ("missing-file", _record_missing, frozenset({"TAMPERED"})),
    ("blank-hash", _record_blank, frozenset({"CLEAN"})),
    ("malformed-record", _record_malformed, frozenset({"TAMPERED", "CLEAN"})),
    ("typosquat", _record_typosquat, frozenset({"TAMPERED"})),
    ("interpreter-missing", _record_interpreter_missing, frozenset({"TAMPERED"})),
    ("clean-multi", _record_clean, frozenset({"CLEAN"})),
    ("clean-no-distinfo", _venv_clean_only, frozenset({"CLEAN"})),
    ("clean-empty", lambda root: _write(root, "app.py", "VALUE = 1"), frozenset({"CLEAN"})),
)
for index, (name, builder, expected) in enumerate(RECORD_CASES):
    CASES.append(
        CorpusCase(
            case_id=f"record-{index:02d}-{name}",
            category="record_tamper",
            description="installed distribution integrity: " + name,
            build=builder,
            expect={10: expected},
        )
    )

# ------------------------------------------------------------ config exposure
CONFIG_EXPOSURE = (
    ("netrc", (".netrc", "machine example.test login dev password " + GH_CLASSIC)),
    ("docker-compose", ("docker-compose.yml", "services:" + NEWLINE + "  db:" + NEWLINE + "    environment:" + NEWLINE + "      POSTGRES_PASSWORD: " + AWS_SECRET)),
    ("kubernetes-secret", ("k8s/secret.yaml", "apiVersion: v1" + NEWLINE + "kind: Secret" + NEWLINE + "data:" + NEWLINE + "  token: " + base64.b64encode(GH_CLASSIC.encode()).decode())),
    ("ci-workflow", (".github/workflows/deploy.yml", "env:" + NEWLINE + "  TOKEN: " + GH_CLASSIC)),
    ("aws-credentials", (".aws/credentials", "[default]" + NEWLINE + "aws_access_key_id = " + AWS_KEY + NEWLINE + "aws_secret_access_key = " + AWS_SECRET)),
    ("ssh-ed25519", ("id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----" + NEWLINE + "b3BlbnNzaC1rZXktdjEAAAAA" + NEWLINE + "-----END OPENSSH PRIVATE KEY-----")),
    ("pypirc", (".pypirc", "[pypi]" + NEWLINE + "password = pypi-" + "c" * 40)),
    ("npmrc", (".npmrc", "//registry.npmjs.org/:_authToken=" + NPM)),
    ("db-in-settings", ("settings.py", "DATABASE_URL = '" + DB_URI + "'")),
    ("jwt-in-config", ("config.json", '{"access_token": "' + JWT + '"}')),
)
for index, (name, (rel, content)) in enumerate(CONFIG_EXPOSURE):
    def build(root: Path, rel: str = rel, content: str = content) -> None:
        _write(root, rel, content)

    CASES.append(
        CorpusCase(
            case_id=f"config-{index:02d}-{name}",
            category="config_exposure",
            description="credential-bearing config file: " + name,
            build=build,
            expect={11: DETECTED},
        )
    )

# ----------------------------------------------------------- negative controls
def _control_clean(root: Path) -> None:
    _write(root, "app.py", "def main() -> int:" + NEWLINE + "    return 0")


def _control_docs_name_only(root: Path) -> None:
    _write(root, "SECURITY.md", "Never commit a GITHUB_TOKEN or an AWS_SECRET_ACCESS_KEY.")


def _control_masked_example(root: Path) -> None:
    _write(root, "README.md", "Example: TOKEN=ghp_****REDACTED****")


def _control_plain_data(root: Path) -> None:
    _write(root, "data.txt", NEWLINE.join("value " + str(index) for index in range(200)))


def _control_minified(root: Path) -> None:
    _write(root, "bundle.js", "function a(){return 1}" + NEWLINE + "console.log(a());")


def _control_license(root: Path) -> None:
    _write(root, "LICENSE", "Permission is hereby granted, free of charge, to any person obtaining a copy.")


def _control_benign_pickle(root: Path) -> None:
    _write_bytes(root, "cache.pkl", pickle.dumps({"answer": 42}, protocol=4))


def _control_valid_pyc(root: Path) -> None:
    _compile_pyc(root)


def _control_clean_venv(root: Path) -> None:
    _dist_with_record(root, {"demo_pkg/__init__.py": b"VALUE = 1" + NEWLINE.encode()})


def _control_safe_apis(root: Path) -> None:
    _write(root, "app.py", "import json" + NEWLINE + "from pathlib import Path" + NEWLINE + "json.loads(Path('a.json').read_text())")


CONTROLS = (
    ("clean-project", _control_clean),
    ("docs-name-only", _control_docs_name_only),
    ("masked-example", _control_masked_example),
    ("plain-data", _control_plain_data),
    ("minified-js", _control_minified),
    ("license-text", _control_license),
    ("benign-pickle", _control_benign_pickle),
    ("valid-pyc", _control_valid_pyc),
    ("clean-venv", _control_clean_venv),
    ("safe-apis", _control_safe_apis),
)
for index, (name, builder) in enumerate(CONTROLS):
    CASES.append(
        CorpusCase(
            case_id=f"control-{index:02d}-{name}",
            category="negative_controls",
            description="clean control: " + name,
            build=builder,
            expect={6: SAFE, 10: frozenset({"CLEAN", "TAMPERED"})},
            expect_verdict=frozenset({"SAFE"}),
        )
    )
