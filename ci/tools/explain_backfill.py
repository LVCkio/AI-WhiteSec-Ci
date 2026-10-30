"""Chay BU giai thich CodeBERT (occlusion) cho 1 version da quet qua worker (tai ZIP len dashboard).

Worker cua luot tai len khong tinh 'codebert_explain' nhu P3 cua pipeline CI -> dashboard khong to tim duoc khoi ma
CodeBERT dua vao. Script nay lay DUNG ma da quet (ZIP trong public.source_uploads), ranh gioi ham va lop CodeBERT da
gan (report.gate.units cua luot do), chay lai DUNG checkpoint (kiem SHA-256 voi report.model), roi ghi vao
public.codebert_explanations. Khong sua bao cao cua worker, khong doi ket qua Gate.

Chay trong anh aiws-codebert (Server 3):  bash ci/tools/giai_thich_version.sh <version id>
  python explain_backfill.py --version 5 [--max-blocks 6] [--dry-run]
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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", type=int, required=True, help="id version (project_versions.id, = so trong /api/versions/<id>)")
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
        row = conn.execute(
            "SELECT r.id AS run_id, r.report, su.content FROM public.project_versions pv "
            "JOIN public.worker_jobs j ON j.id = pv.job_id JOIN public.pipeline_runs r ON r.id = j.pipeline_run_id "
            "JOIN public.source_uploads su ON su.id = j.upload_id WHERE pv.id = %s", (a.version,)).fetchone()
        if row is None:
            C.die(STEP, f"version {a.version}: khong co luot quet tai len hoan tat (thieu bao cao hoac ZIP)", C.EXIT_CONFIG)
        rep, run_id = row["report"] or {}, row["run_id"]
        m = rep.get("model") or {}
        mdir = a.model_store / str(m.get("name"))
        ck = mdir / "checkpoint" / "model.safetensors"
        if not ck.is_file():
            C.die(STEP, f"khong co model {m.get('name')} trong {a.model_store} (luot nay quet bang model khac)", C.EXIT_CONFIG)
        if m.get("checkpoint_sha256"):
            ok, how = same_checkpoint(ck, m["name"], m["checkpoint_sha256"], a.worker_store)
            if not ok:
                C.die(STEP, f"checkpoint trong kho khac SHA-256 cua luot quet ({m['checkpoint_sha256'][:12]}): {how} -> khong giai thich",
                      C.EXIT_CONFIG)
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
        C.log(STEP, f"version {a.version} (pipeline_runs #{run_id}), model {m.get('name')}: {len(units)} ham CodeBERT gan co"
                    f"{f', bo qua {skipped} (khong thay file)' if skipped else ''}")
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        torch.set_num_threads(max(1, int(os.environ.get("AIWS_TORCH_THREADS", os.cpu_count() or 1))))
        tok = AutoTokenizer.from_pretrained(mdir / "checkpoint")
        net = AutoModelForSequenceClassification.from_pretrained(mdir / "checkpoint").eval()
        t0, done = time.time(), 0
        for u in units:
            with torch.inference_mode():
                enc = tok(u["code"], truncation=True, max_length=512, return_tensors="pt")
                p = torch.sigmoid(net(**enc).logits.float())[0].tolist()
            th = {g: (0.0 if g in u["flagged"] else 2.0) for g in C.GROUPS}      # giai thich dung cac lop worker da gan
            ex = explain_units(tok, net, torch, [u], [p], th, 1, a.max_blocks, a.batch).get(u["id"])
            if ex is None:
                continue
            ex["p_full"] = {g: round(p[C.GROUPS.index(g)], 4) for g in u["flagged"] if g in C.GROUPS}
            if not a.dry_run:
                conn.execute(
                    "INSERT INTO public.codebert_explanations (pipeline_run_id, unit_id, file_path, line_start, line_end, "
                    "model_name, checkpoint_sha256, explain) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT (pipeline_run_id, unit_id) DO UPDATE SET explain = EXCLUDED.explain, created_at = now()",
                    (run_id, u["id"], u["file"], u["start"], u["end"], m.get("name"), m.get("checkpoint_sha256"), Jsonb(ex)))
            done += 1
            if done % 20 == 0:
                C.log(STEP, f"  {done}/{len(units)} ham ({round(time.time() - t0)} s)")
        C.log(STEP, f"xong: {done} ham co giai thich trong {round(time.time() - t0)} s"
                    f"{' (dry-run, chua ghi DB)' if a.dry_run else ' -> public.codebert_explanations'}")


if __name__ == "__main__":
    main()
