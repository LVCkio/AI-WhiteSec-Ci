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
"""
import argparse
import io
import os
import sys
import time
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


class Skip(Exception):
    """Luot nay khong giai thich duoc (khong co ZIP / model khac) -> ghi lai, khong thu lai."""


_models = {}


def load_model(mdir: Path):
    """Nap model 1 lan / tien trinh, DUNG cach suy luan ghi trong model-lock.json cua kho (head512 hoac window)."""
    if mdir not in _models:
        _models[mdir] = Scorer(mdir)
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
    z = zipfile.ZipFile(io.BytesIO(bytes(row["content"])))
    files, units, skipped = {}, [], 0
    for u in (rep.get("gate") or {}).get("units") or []:
        flagged = [C.canon_class(g) for g in (u.get("codebert_classes") or [])]
        if not flagged:
            continue
        if u["file"] not in files:
            info = find_member(z, u["file"])
            files[u["file"]] = z.read(info).decode("utf-8", errors="replace").splitlines() if info else None
        lines = files[u["file"]]
        if not lines or u["start"] > len(lines):
            skipped += 1
            continue
        units.append({"id": u["id"], "file": u["file"], "start": u["start"], "end": u["end"], "flagged": flagged,
                      "code": "\n".join(lines[u["start"] - 1:u["end"]])})
    C.log(STEP, f"version {version_id} (pipeline_runs #{run_id}), model {m.get('name')}: {len(units)} ham CodeBERT gan co"
                f"{f', bo qua {skipped} (khong thay file)' if skipped else ''}")
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
