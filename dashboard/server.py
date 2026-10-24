"""
dashboard/server.py - Dashboard local cua AI-WhiteSec-CI (chi doc ket qua that, chi nghe 127.0.0.1).

  python dashboard/server.py                # mo http://127.0.0.1:8765/
  python dashboard/server.py --port 9000 --no-browser

Chi dung thu vien chuan Python (khong can cai them). Khong ghi file, khong chay scanner/model:
  GET /                     giao dien (dashboard/static)
  GET /api/data             toan bo ket qua da gom (collect.py), tu cap nhat khi file ket qua thay doi
  GET /api/source           doan ma nguon cua MOT don vi da quet (chi file nam trong lan quet do)
  GET /api/figure           anh trong reports/figures (vd. t-SNE cua C06)
"""
import argparse, json, mimetypes, sys, threading, webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".woff2": "font/woff2",
                ".png": "image/png", ".json": "application/json"}
SOURCE_EXT = {".py", ".java", ".js", ".jsx", ".ts", ".tsx", ".php", ".html", ".htm", ".inc"}
MAX_LINES = 400
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")


class Store:
    """Cache ket qua collect.build(); tinh lai khi bat ky file dau vao nao doi."""

    def __init__(self, root):
        self.root = Path(root)
        self.lock = threading.Lock()
        self.stamp, self.data, self.text, self.repos, self.version_text = None, None, None, {}, ""

    def fingerprint(self):
        pats = ["reports/targets/*.json", "reports/scans/*.json", "reports/*.json", "reports/c01_grid.csv",
                "models/*.json", "models/*/run_info.json", "targets/*/ground_truth.json",
                "security-config/semgrep/semgrep.yml", "security-config/semgrep/tools/ruleset.py",
                "security-config/semgrep/ruleset-manifest.json", "security-config/semgrep/reports/*.json",
                "security-config/semgrep/rules_disabled/*/*.yml", "security-config/semgrep/*.md",
                "reports/*.csv", "reports/*.txt", "rules/vuln_metadata.json", "data_versions/*/manifest.json"]
        items = []
        for pat in pats:
            for p in self.root.glob(pat):
                try:
                    st = p.stat()
                    items.append((p.as_posix(), st.st_mtime_ns, st.st_size))
                except OSError:
                    pass
        return hash(tuple(sorted(items)))

    def get(self):
        with self.lock:
            stamp = self.fingerprint()
            if stamp != self.stamp:
                self.data = collect.build(self.root)
                self.text = json.dumps(self.data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                self.repos = self._repos()
                self.stamp = stamp
                self.version_text = str(stamp)
            return self.data, self.text

    def version(self):
        with self.lock:
            return str(self.fingerprint())

    def _repos(self):
        """run id -> (thu muc ma nguon, tap file da quet). Chi dung de doc doan ma cua chinh lan quet do."""
        out = {}
        for r in self.data["runs"]:
            path = self.root / r["source_file"]
            scan = collect.read_json(path) or {}
            candidates = []
            if r["app"]:
                candidates.append(self.root / "targets" / r["app"] / "scan_src")
            if scan.get("repo"):
                candidates.append(Path(scan["repo"]))
            repo = next((c for c in candidates if c.is_dir()), None)
            out[r["id"]] = (repo.resolve() if repo else None, {u["file"] for u in r["units"]})
        return out


class Handler(BaseHTTPRequestHandler):
    server_version = "AIWS-Dashboard"
    sys_version = ""

    def log_message(self, fmt, *args):  # gon log
        if self.server.verbose:
            super().log_message(fmt, *args)

    # ---------------------------------------------------------- tien ich
    def send(self, status, body=b"", ctype="text/plain; charset=utf-8", cache="no-store", extra=None):
        self.send_response(status)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, obj, status=HTTPStatus.OK):
        self.send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
        return host in ("127.0.0.1", "localhost", "::1")  # chan DNS rebinding

    # ---------------------------------------------------------- routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.host_ok():
            return self.send(HTTPStatus.FORBIDDEN, b"Host khong hop le")
        url = urlparse(self.path)
        q = parse_qs(url.query)
        try:
            if url.path in ("/", "/index.html"):
                return self.static("index.html")
            if url.path.startswith("/assets/"):
                return self.static(url.path[len("/assets/"):])
            if url.path == "/api/data":
                _, text = self.server.store.get()
                return self.send(HTTPStatus.OK, text, "application/json; charset=utf-8",
                                 extra={"X-Data-Version": self.server.store.version_text})
            if url.path == "/api/version":
                return self.send_json({"version": self.server.store.version()})
            if url.path == "/api/source":
                return self.source(q)
            if url.path == "/api/figure":
                return self.figure(q)
            if url.path == "/favicon.ico":
                return self.static("favicon.svg")
        except Exception as exc:  # loi doc du lieu -> 500 co thong bao, khong lo traceback
            return self.send_json({"error": f"{type(exc).__name__}: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        return self.send(HTTPStatus.NOT_FOUND, b"Khong tim thay")

    def static(self, name):
        path = (STATIC / name).resolve()
        if not path.is_relative_to(STATIC.resolve()) or not path.is_file() or path.suffix not in STATIC_TYPES:
            return self.send(HTTPStatus.NOT_FOUND, b"Khong tim thay")
        cache = "no-cache" if path.suffix in (".html", ".js", ".css") else "max-age=86400"
        return self.send(HTTPStatus.OK, path.read_bytes(), STATIC_TYPES[path.suffix], cache)

    def source(self, q):
        self.server.store.get()
        run_id, file = (q.get("run") or [""])[0], (q.get("file") or [""])[0]
        repo, files = self.server.store.repos.get(run_id, (None, set()))
        if repo is None or file not in files:
            return self.send_json({"error": "Khong co ma nguon cho don vi nay"}, HTTPStatus.NOT_FOUND)
        path = (repo / file).resolve()
        if not path.is_relative_to(repo) or path.suffix.lower() not in SOURCE_EXT or not path.is_file():
            return self.send_json({"error": "Duong dan khong hop le"}, HTTPStatus.BAD_REQUEST)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        try:
            start = max(1, int((q.get("start") or ["1"])[0]))
            end = min(len(lines), int((q.get("end") or [str(start + 60)])[0]))
        except ValueError:
            return self.send_json({"error": "start/end phai la so"}, HTTPStatus.BAD_REQUEST)
        end = min(end, start + MAX_LINES - 1)
        return self.send_json({"file": file, "start": start, "end": end, "total": len(lines),
                               "lines": lines[start - 1:end]})

    def figure(self, q):
        name = (q.get("path") or [""])[0]
        root = self.server.store.root
        figs = (root / "reports" / "figures").resolve()
        path = (root / name).resolve()
        if not path.is_relative_to(figs) or path.suffix.lower() != ".png" or not path.is_file():
            return self.send(HTTPStatus.NOT_FOUND, b"Khong tim thay")
        return self.send(HTTPStatus.OK, path.read_bytes(), "image/png", "max-age=3600")


def make_server(root=collect.ROOT, port=8765, verbose=False):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.store, srv.verbose = Store(root), verbose
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--root", type=Path, default=collect.ROOT)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    try:
        srv = make_server(a.root, a.port, a.verbose)
    except OSError as exc:
        raise SystemExit(f"Khong mo duoc cong {a.port} ({exc}). Dashboard co the dang chay o cua so khac; "
                         f"dong cua so do hoac chay voi --port <cong khac>.")
    data, _ = srv.store.get()
    url = f"http://127.0.0.1:{a.port}/"
    print(f"AI-WhiteSec-CI dashboard: {url}")
    print(f"  {len(data['runs'])} lan quet, {len(data['configs'])} cau hinh; hien tai: {data['project']['current_label']}")
    print("  Nhan Ctrl+C de dung.")
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    mimetypes.add_type("font/woff2", ".woff2")
    main()
