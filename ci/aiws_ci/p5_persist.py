"""P5 - Persist Results: ghi report.json vao PostgreSQL Server 2 (bang public.pipeline_runs) de Dashboard hien thi.

  python -m aiws_ci.p5_persist --out-dir aiws-out

Ket noi: bien CI/CD AIWS_DB_DSN (Masked + Protected), vd
  host=192.168.12.202 port=5432 dbname=whitesec user=whitesec_ci sslmode=verify-full sslrootcert=$AIWS_DB_CA
AIWS_DB_CA la bien kieu File (chung chi CA cua PostgreSQL). Tai khoan chi can SELECT/INSERT projects, INSERT pipeline_runs.
Khong co AIWS_DB_DSN -> bo qua (bao cao van nam trong artifact), ma 0.
Chay lai cung pipeline -> khong ghi trung (run_key = gitlab-<project>-<pipeline id>, UNIQUE).
Bang co CHECK executor: them 'gitlab_ci' vao rang buoc, hoac dat AIWS_DB_EXECUTOR (ci/README.md).
"""
import argparse
import os
import re
from pathlib import Path

from . import common as C

STEP = "P5-persist"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", type=Path, default=Path("aiws-out"))
    a = ap.parse_args()
    rep = C.read_json(a.out_dir / "report.json")
    if rep is None:
        C.die(STEP, "thieu report.json (P4 khong chay?)", C.EXIT_CONFIG)
    dsn = os.environ.get("AIWS_DB_DSN", "").strip()
    if not dsn:
        C.log(STEP, "chua dat AIWS_DB_DSN -> bo qua ghi PostgreSQL (bao cao co trong artifact report.json)")
        return
    if os.environ.get("AIWS_DB_CA") and "sslrootcert" not in dsn:
        dsn += f" sslrootcert={os.environ['AIWS_DB_CA']}"
    import psycopg
    from psycopg.types.json import Jsonb
    ci = rep["ci"]
    name = os.environ.get("AIWS_DB_PROJECT_NAME") or re.sub(r"[^A-Za-z0-9._-]", "-", ci.get("project_path") or "gitlab-project")[:200]
    url = ci.get("project_url") or f"gitlab://{name}"
    status = "failed" if rep["analysis_status"] == "failed" else "completed"
    try:
        with psycopg.connect(dsn, connect_timeout=10, application_name="aiws-gitlab-ci") as c:
            row = c.execute("SELECT id FROM public.projects WHERE repository_url=%s ORDER BY id LIMIT 1", (url,)).fetchone()
            if row is None:
                row = c.execute("INSERT INTO public.projects (name, repository_url) VALUES (%s,%s) "
                                "ON CONFLICT DO NOTHING RETURNING id", (name, url)).fetchone()
                if row is None:
                    C.die(STEP, f"ten project {name} da dung cho repo khac - doi AIWS_DB_PROJECT_NAME", C.EXIT_CONFIG)
            pid = row[0]
            # run_key: NOT NULL + UNIQUE trong bang -> chay lai cung pipeline khong ghi trung
            run_key = f"gitlab-{name}-{ci.get('pipeline_id')}"[:200]
            sha = rep.get("target_commit")
            run = c.execute(
                "INSERT INTO public.pipeline_runs (project_id, run_key, run_type, executor, worker_id, branch, "
                "commit_sha, status, report, started_at, finished_at) "
                "VALUES (%s,%s,'security_scan',%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (run_key) DO NOTHING RETURNING id",
                (pid, run_key, os.environ.get("AIWS_DB_EXECUTOR", "gitlab_ci"),
                 (ci.get("runner") or "gitlab-runner")[:100], rep.get("branch"),
                 sha if sha and re.fullmatch(r"[0-9a-f]{40}", sha) else None, status, Jsonb(rep),
                 rep.get("started_at"), rep.get("finished_at"))).fetchone()
            if run is None:
                C.log(STEP, f"{run_key} da ghi truoc do - bo qua")
                return
            C.log(STEP, f"da ghi pipeline_runs #{run[0]} ({run_key}, project #{pid}, {status}, "
                        f"Gate {rep['security_gate']})")
            C.write_json(a.out_dir / "p5-persist.json", {"pipeline_run_id": run[0], "project_id": pid})
    except psycopg.Error as e:
        C.die(STEP, f"ghi PostgreSQL loi: {str(e)[:500]}", C.EXIT_TOOL)


if __name__ == "__main__":
    main()
