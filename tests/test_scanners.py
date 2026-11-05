from mythos.scanner.packer import pack_codebase
from mythos.scanner.secrets import scan_text
from mythos.scanner.deep import scan_deep


def test_secret_detected_and_redacted():
    hits = scan_text("a.py", 'k = "AKIAABCDEFGHIJKLMNOP"')
    assert hits and hits[0].kind == "AWS Access Key ID" and "ABCDEFGHIJKLMNOP" not in hits[0].redacted


def test_packer_never_packs_secret_files(tmp_path):
    (tmp_path / ".env").write_text("GEMINI_API_KEY=abc")
    (tmp_path / "server.pem").write_text("-----BEGIN PRIVATE KEY-----")
    (tmp_path / "app.py").write_text("print(1)")
    assert pack_codebase(tmp_path).files == ["app.py"]


def test_deep_flags_sqli():
    packed = '=== FILE: a.py (1 lines) ===\n1| cur.execute("SELECT * FROM t WHERE id=" + request.args["id"])\n'
    assert any(h.category == "sqli" for h in scan_deep(packed))
