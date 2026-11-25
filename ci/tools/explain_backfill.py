"""Chay BU giai thich CodeBERT (occlusion) cho 1 version da quet qua worker (tai ZIP len dashboard).

Worker cua luot tai len khong tinh 'codebert_explain' nhu P3 cua pipeline CI -> dashboard khong to tim duoc khoi ma
CodeBERT dua vao. Script nay lay DUNG ma da quet (ZIP trong public.source_uploads), ranh gioi ham va lop CodeBERT da
gan (report.gate.units cua luot do), chay lai DUNG checkpoint (kiem SHA-256 voi report.model), roi ghi vao
public.codebert_explanations. Khong sua bao cao cua worker, khong doi ket qua Gate.

Chay trong anh aiws-codebert (Server 3):
  bash ci/tools/giai_thich_version.sh <version id>        mot version (chay tay)
  python explain_backfill.py --pending [--limit 5]       TU DONG: moi luot tai len chua giai thich (systemd timer,
                                                           cai bang ci/tools/cai_tu_dong_giai_thich.sh); ghi ket qua
                                                           vao public.codebert_explain_runs de khong lam lai.
Bien: AIWS_DB_DSN (+ PGPASSWORD), AIWS_MODEL_STORE (mac dinh /models).

Ha tang buoc 3-4 ("khong luu ma nguon"): worker v2.10.2 luu code cua moi ham CodeBERT gan co vao
public.finding_snippets (cung lan quet, cung file, cung dong bat dau-ket thuc voi report.gate.units). Script uu tien
lay code o do; luot quet cu chua co doan code -> doc ZIP trong source_uploads nhu truoc (neu ZIP con noi dung).

GPU (AIWS_GPU_URL + AIWS_GPU_TOKEN, vd http://192.168.12.1:8091): phan CHAM DIEM gui sang dich vu aiws-explain GPU tren
laptop (aiws_explain_serve.py - chay DUNG aiws_ci.scoring.Scorer + infer_window.py cua goi model, tren cuda). Chi dung
khi dich vu tra loi dung ten model + SHA-256 model.safetensors cua kho CI va cung cach suy luan. Occlusion, ghi DB:
giu nguyen o day. Worker WhiteSec dang chay job (/worker.lock bi khoa) -> cho, de luot quet duoc dung GPU truoc.
Dich vu GPU tat / loi giua chung -> tu chuyen ve CPU (Scorer tai cho) nhu truoc.
"""
import argparse
import fcntl
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, os.environ.get("AIWS_CI_HOME", "/opt/aiws/ci"))
from aiws_ci import common as C  # noqa: E402
from aiws_ci.p3_codebert import explain_units  # noqa: E402
from aiws_ci.scoring import Scorer  # noqa: E402

STEP = "explain-backfill"


def find_member(z: zipfile.ZipFile, path: str):
    want = path.replace("\\", "/").lstrip("./")
    names = {i.filename.replace("\\", "/"): i for i in z.infolist() if not i.is_dir()}
    if want in names:
        return names[want]
    tail = [n for n in names if n.endswith("/" + want)]
    if len(tail) == 1:
        return names[tail[0]]
    short = want.split("/", 1)[1] if "/" in want else None
    return names.get(short) if short else None


def same_checkpoint(ck: Path, name: str, want: str, worker_store: Path):
    """Worker ghi checkpoint_sha256 = SHA-256 cua file SHA256SUMS trong kho model cua worker (whitesec-model.py),
    pipeline CI ghi SHA-256 cua model.safetensors. Chap nhan ca hai, mien la CUNG file model.safetensors."""
    got = C.sha256_file(ck)
    if got == want:
        return True, "SHA-256 model.safetensors trung"
    sums = worker_store / name / "SHA256SUMS"
    if not sums.is_file():
        return False, f"khong co {sums} de doi chieu cach tinh cua worker"
    if C.sha256_file(sums) != want:
        return False, "SHA256SUMS cua worker cung khong khop"
    for line in sums.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*").replace("\\", "/").endswith("model.safetensors"):
            return (parts[0].lower() == got,
                    "SHA256SUMS cua worker khop luot quet va liet ke dung model.safetensors nay" if parts[0].lower() == got
                    else "model.safetensors cua worker KHAC file trong kho CI")
    return False, "SHA256SUMS cua worker khong co dong model.safetensors"


def snippet_codes(conn, run_id):
    """{(file, start, end): code} tu public.finding_snippets cua luot quet (bang chua co / khong co quyen -> {})."""
    try:
        with conn.transaction():
            rows = conn.execute("SELECT file_path, line_start, line_end, code FROM public.finding_snippets "
                                "WHERE run_id = %s AND kind = 'function'", (run_id,)).fetchall()
    except Exception as e:  # noqa: BLE001 - chua co migration 010 / chua cap quyen -> dung ZIP nhu truoc
        C.log(STEP, f"khong doc duoc finding_snippets ({type(e).__name__}) - dung ZIP")
        return {}
    return {(r["file_path"], r["line_start"], r["line_end"]): r["code"] for r in rows}


class Skip(Exception):
    """Luot nay khong giai thich duoc (khong co ZIP / model khac) -> ghi lai, khong thu lai."""


_models = {}


def wait_worker(path=Path(os.environ.get("AIWS_WORKER_LOCK", "/worker.lock"))):
    """Worker WhiteSec giu khoa LOCK_EX tren ~/whitesec-work/.worker.lock suot job -> cho den khi nha (uu tien quet)."""
    if not path.is_file():
        return
    t0 = None
    with path.open("rb") as fh:
        while True:
            try:
                fcntl.flock(fh, fcntl.LOCK_SH | fcntl.LOCK_NB)
                fcntl.flock(fh, fcntl.LOCK_UN)
                break
            except BlockingIOError:
                if t0 is None:
                    t0 = time.time()
                    C.log(STEP, "worker WhiteSec dang quet - tam dung de luot quet dung GPU truoc")
                time.sleep(5)
    if t0 is not None:
        C.log(STEP, f"worker xong - chay tiep (da cho {round(time.time() - t0)} s)")


class RemoteScorer:
    """Cung giao dien Scorer (mode, score, probs, seen_until) nhung cham diem tren dich vu aiws-explain GPU.
    Loi mang / dich vu tat giua chung -> chuyen han ve Scorer CPU tai cho cho phan con lai."""

    def __init__(self, url, token, mdir: Path):
        self.url, self.token, self.mdir = url.rstrip("/"), token, mdir
        lock = C.read_json(mdir / "model-lock.json", {})
        h = self._call("GET", "/health", None, 10)
        want = (lock.get("files") or {}).get("checkpoint/model.safetensors")
        mode = ((lock.get("inference") or {}).get("mode")) or "head512"
        if h.get("model") != lock.get("name") or not want or h.get("checkpoint") != want:
            raise RuntimeError(f"dich vu GPU nap {h.get('model')} ({str(h.get('checkpoint'))[:12]}), "
                               f"kho CI la {lock.get('name')} ({str(want)[:12]})")
        if h.get("mode") != mode or mode != "window":
            raise RuntimeError(f"cach suy luan khac (GPU {h.get('mode')}, kho CI {mode}) - chi ho tro window")
        if not str(h.get("device", "")).startswith("cuda"):
            raise RuntimeError(f"dich vu khong chay GPU (device {h.get('device')})")
        self.mode, self.model, self.local = mode, lock.get("name"), None
        self.device = f"GPU {h.get('gpu_name')} ({self.url})"

    def _call(self, method, path, body, timeout):
        req = urllib.request.Request(self.url + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {self.token}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - URL http(s) tu bien moi truong
            return json.load(r)

    def score(self, codes, batch=8, start_lines=None):
        codes = [c or "" for c in codes]
        if not codes:
            return []
        if self.local is None:
            wait_worker()
            for attempt in range(3):
                try:
                    return self._call("POST", "/v1/score", {"model": self.model, "codes": codes, "batch": batch,
                                                            "start_lines": start_lines}, 300)["results"]
                except urllib.error.HTTPError as e:
                    if e.code != 503 or attempt == 2:          # 503 = het bo nho GPU tam thoi -> thu lai
                        err = f"HTTP {e.code}"
                        break
                    time.sleep(10)
                except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
                    err = f"{type(e).__name__}: {e}"
                    break
            C.log(STEP, f"dich vu GPU loi ({str(err)[:150]}) - chuyen ve CPU cho phan con lai")
            self.local, self.device = Scorer(self.mdir), "CPU (dich vu GPU loi giua chung)"
        return self.local.score(codes, batch, start_lines)

    def probs(self, codes, batch=8):
        return [r["probs"] for r in self.score(codes, batch)]

    def seen_until(self, code, start):
        return None                                           # window: moi doan deu duoc doc (xem 'windows')


def load_model(mdir: Path):
    """Nap model 1 lan / tien trinh, DUNG cach suy luan ghi trong model-lock.json cua kho (head512 hoac window).
    Co AIWS_GPU_URL -> uu tien dich vu aiws-explain GPU; khong dung duoc -> Scorer CPU nhu truoc."""
    if mdir not in _models:
        url, tok = os.environ.get("AIWS_GPU_URL", "").strip(), os.environ.get("AIWS_GPU_TOKEN", "").strip()
        sc = None
        if url and tok:
            try:
                sc = RemoteScorer(url, tok, mdir)
            except Exception as e:  # noqa: BLE001
                C.log(STEP, f"khong dung duoc dich vu GPU {url}: {str(e)[:200]} -> CPU")
        if sc is None:
            sc = Scorer(mdir)
            sc.device = "CPU"
        C.log(STEP, f"cham diem tren {sc.device}")
        _models[mdir] = sc
    return _models[mdir]


def process_version(conn, version_id: int, a, Jsonb):
    """-> (run_id, so ham da giai thich). Loi co ly do -> Skip."""
    row = conn.execute(
        "SELECT r.id AS run_id, r.report, su.content FROM public.project_versions pv "
        "JOIN public.worker_jobs j ON j.id = pv.job_id JOIN public.pipeline_runs r ON r.id = j.pipeline_run_id "
        "JOIN public.source_uploads su ON su.id = j.upload_id WHERE pv.id = %s", (version_id,)).fetchone()
    if row is None:
        raise Skip(f"version {version_id}: khong co luot quet tai len hoan tat (thieu bao cao hoac ZIP)")
    rep, run_id = row["report"] or {}, row["run_id"]
    m = rep.get("model") or {}
    mdir = a.model_store / str(m.get("name"))
    ck = mdir / "checkpoint" / "model.safetensors"
    if not ck.is_file():
        raise Skip(f"khong co model {m.get('name')} trong {a.model_store} (luot nay quet bang model khac)")
    if m.get("checkpoint_sha256"):
        ok, how = same_checkpoint(ck, m["name"], m["checkpoint_sha256"], a.worker_store)
        if not ok:
            raise Skip(f"checkpoint trong kho khac SHA-256 cua luot quet ({m['checkpoint_sha256'][:12]}): {how}")
        C.log(STEP, f"checkpoint khop luot quet: {how}")
    snips = snippet_codes(conn, run_id)          # code worker da cat luc quet (khong can ZIP)
    z = None                                     # ZIP chi mo khi can (luot cu chua co doan code)
    files, units, skipped, from_snip, from_zip = {}, [], 0, 0, 0
    for u in (rep.get("gate") or {}).get("units") or []:
        flagged = [C.canon_class(g) for g in (u.get("codebert_classes") or [])]
        if not flagged:
            continue
        code = snips.get((u["file"], u["start"], u["end"]))
        if code is not None:
            from_snip += 1
        else:
            if z is None and row["content"] is not None:
                z = zipfile.ZipFile(io.BytesIO(bytes(row["content"])))
            if z is None:                        # khong doan code, ZIP khong luu -> khong giai thich duoc ham nay
                skipped += 1
                continue
            if u["file"] not in files:
                info = find_member(z, u["file"])
                files[u["file"]] = z.read(info).decode("utf-8", errors="replace").splitlines() if info else None
            lines = files[u["file"]]
            if not lines or u["start"] > len(lines):
                skipped += 1
                continue
            code = "\n".join(lines[u["start"] - 1:u["end"]])
            from_zip += 1
        units.append({"id": u["id"], "file": u["file"], "start": u["start"], "end": u["end"], "flagged": flagged,
                      "code": code})
    C.log(STEP, f"version {version_id} (pipeline_runs #{run_id}), model {m.get('name')}: {len(units)} ham CodeBERT gan co"
                f" (doan code: {from_snip}, ZIP: {from_zip})"
                f"{f', bo qua {skipped} (khong co doan code / khong thay file)' if skipped else ''}")
    if not units and skipped:
        raise Skip(f"khong co ma cua {skipped} ham CodeBERT gan co (khong co doan code va ZIP khong luu)")
    if not units:
        return run_id, 0
    scorer = load_model(mdir)
    t0, done = time.time(), 0
    for u in units:
        meta = scorer.score([u["code"]], a.batch, [u["start"]])
        p = meta[0]["probs"]
        th = {g: (0.0 if g in u["flagged"] else 2.0) for g in C.GROUPS}      # giai thich dung cac lop worker da gan
        ex = explain_units(scorer, [u], [p], th, 1, a.max_blocks, a.batch, meta).get(u["id"])
        if ex is None:
            continue
        ex["p_full"] = {g: round(p[C.GROUPS.index(g)], 4) for g in u["flagged"] if g in C.GROUPS}
        if not a.dry_run:
            conn.execute(
                "INSERT INTO public.codebert_explanations (pipeline_run_id, unit_id, file_path, line_start, line_end, "
                "model_name, checkpoint_sha256, explain) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (pipeline_run_id, unit_id) DO UPDATE SET explain = EXCLUDED.explain, created_at = now()",
                (run_id, u["id"], u["file"], u["start"], u["end"], m.get("name"), m.get("checkpoint_sha256"), Jsonb(ex)))
            conn.commit()
        done += 1
        if done % 20 == 0:
            C.log(STEP, f"  {done}/{len(units)} ham ({round(time.time() - t0)} s)")
    C.log(STEP, f"xong: {done} ham co giai thich trong {round(time.time() - t0)} s"
                f"{' (dry-run, chua ghi DB)' if a.dry_run else ' -> public.codebert_explanations'}")
    return run_id, done


PENDING_SQL = """
SELECT pv.id AS version_id, r.id AS run_id FROM public.project_versions pv
JOIN public.worker_jobs j ON j.id = pv.job_id
JOIN public.pipeline_runs r ON r.id = j.pipeline_run_id
WHERE j.upload_id IS NOT NULL AND r.status = 'completed' AND r.created_at > now() - interval '60 days'
  AND NOT EXISTS (SELECT 1 FROM public.codebert_explain_runs e WHERE e.pipeline_run_id = r.id)
ORDER BY r.id LIMIT %s
"""


def mark(conn, run_id, version_id, status, units, note):
    conn.execute("INSERT INTO public.codebert_explain_runs (pipeline_run_id, version_id, status, units, note) "
                 "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (pipeline_run_id) DO NOTHING",
                 (run_id, version_id, status, units, (note or "")[:500]))
    conn.commit()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--version", type=int, help="id version (project_versions.id, = so trong /api/versions/<id>)")
    g.add_argument("--pending", action="store_true", help="moi luot tai len hoan tat chua giai thich")
    ap.add_argument("--limit", type=int, default=5, help="--pending: toi da so luot moi lan chay")
    ap.add_argument("--model-store", type=Path, default=Path(os.environ.get("AIWS_MODEL_STORE", "/models")))
    ap.add_argument("--worker-store", type=Path, default=Path(os.environ.get("AIWS_WORKER_MODEL_STORE", "/worker_models")),
                    help="kho model cua worker (de doi chieu SHA256SUMS)")
    ap.add_argument("--max-blocks", type=int, default=6)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--dry-run", action="store_true", help="tinh nhung khong ghi DB")
    a = ap.parse_args()
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
    dsn = os.environ.get("AIWS_DB_DSN", "").strip()
    if not dsn:
        C.die(STEP, "thieu AIWS_DB_DSN", C.EXIT_CONFIG)
    with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=10, application_name="aiws-explain-backfill") as conn:
        if a.version:
            try:
                run_id, n = process_version(conn, a.version, a, Jsonb)
            except Skip as e:
                C.die(STEP, f"{e} -> khong giai thich", C.EXIT_CONFIG)
            if not a.dry_run:
                mark(conn, run_id, a.version, "done", n, "chay tay")
            return
        todo = conn.execute(PENDING_SQL, (a.limit,)).fetchall()
        if not todo:
            C.log(STEP, "khong co luot tai len moi can giai thich")
            return
        for t in todo:
            try:
                _, n = process_version(conn, t["version_id"], a, Jsonb)
                status, note = "done", ""
            except Skip as e:
                C.log(STEP, f"bo qua version {t['version_id']}: {e}")
                status, n, note = "skipped", 0, str(e)
            except Exception as e:  # noqa: BLE001 - loi tam thoi (DB, RAM...) -> khong danh dau, lan sau thu lai
                conn.rollback()
                C.log(STEP, f"LOI version {t['version_id']} (se thu lai lan sau): {type(e).__name__}: {e}")
                continue
            if not a.dry_run:
                mark(conn, t["run_id"], t["version_id"], status, n, note)


if __name__ == "__main__":
    main()
