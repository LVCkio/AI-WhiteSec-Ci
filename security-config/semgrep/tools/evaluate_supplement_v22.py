"""Evaluate local rules on dataset v2.3 train/val; never accepts the held-out test split.

Dataset: v2.3 (ban moi nhat; v2.2 khong con dung de do), read from --data-root
(default: <thu muc do an>/dataset_model/dataset; fallback main/<version> if present).

Uses the same fragment normalisation and Semgrep mapping as 34_baseline_v22.py.
Output contains sample IDs and metrics, never source code or replacement labels.
"""
import argparse
import collections
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import yaml

MAIN = Path(__file__).resolve().parents[3]
DATA_ROOT = MAIN.parent / 'dataset_model' / 'dataset'


def dataset_dir(version, root=None):
    root = Path(root) if root else DATA_ROOT
    for d in (root / version, MAIN / version):
        if (d / 'train.jsonl').is_file():
            return d
    raise SystemExit(f'Khong tim thay dataset {version} trong {root} hoac {MAIN}')
BASE = MAIN / 'security-config' / 'semgrep'
sys.stdout.reconfigure(encoding='utf-8')
spec = importlib.util.spec_from_file_location('v22_baseline', MAIN / '34_baseline_v22.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)
sast = baseline.sast


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate(split, config, output, baseline_csv=None, dataset='v2.3', data_root=None):
    exe = sast.find_executable('semgrep')
    version = sast.run_command([exe, '--version']).stdout.strip().splitlines()[-1].strip()
    if version != '1.181.0':
        raise SystemExit(f'Semgrep {version} != 1.181.0')
    ddir = dataset_dir(dataset, data_root)
    source = ddir / f'{split}.jsonl'
    rows = baseline.load_rows(source)
    config_hash = digest(config)
    config_rules = yaml.safe_load(config.read_text(encoding='utf-8'))['rules']
    languages = {lang for r in config_rules for lang in r['languages']}
    applicable = {r['id'] for r in rows if r['programming_language'].lower() in languages
                  or ('regex' in languages and r['programming_language']=='PHP')}
    originals = [json.loads(line) for line in source.read_text(encoding='utf-8').splitlines() if line.strip()]
    output.mkdir(parents=True, exist_ok=True)
    print(f'{split}: {len(rows)} samples; config {config.name}', flush=True)
    with tempfile.TemporaryDirectory(prefix='aiws_r4_') as folder:
        folder = Path(folder)
        samples = folder / 'samples'
        samples.mkdir()
        names = {}
        offsets = {}
        for i, r in enumerate(rows):
            name = sast.sample_name(i, r)
            code, offset = sast.wrap_fragment(sast.normalize_code(r['code']), r['programming_language'])
            (samples / name).write_text(code, encoding='utf-8')
            names[name] = r
            offsets[name] = offset
        raw = folder / 'semgrep.json'
        command = [exe, 'scan', '--metrics=off', '--disable-version-check', '--no-git-ignore',
                   '--json', '--quiet', '--config', str(config), '--output', str(raw), str(samples)]
        proc = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                              errors='replace', env={**os.environ, 'PYTHONUTF8':'1'})
        if proc.returncode != 0 or not raw.exists():
            raise RuntimeError(f'Semgrep exit {proc.returncode}: {proc.stderr[-3000:]}')
        data = json.loads(raw.read_text(encoding='utf-8'))
        fatal = [e for e in data.get('errors',[]) if e.get('level') != 'warn']
        if fatal:
            raise RuntimeError(str(fatal)[:3000])
        status = sast.parse_status([raw])
        scanned = {Path(p).name for p in data.get('paths',{}).get('scanned',[])}
        if not scanned:
            raise RuntimeError('Semgrep reported no scanned files')
        hits = collections.defaultdict(dict)
        for f in data.get('results',[]):
            name = Path(f['path']).name
            if name not in names:
                continue
            md = f['extra'].get('metadata',{})
            classes = sast.finding_classes(sast.get_cwe_numbers(md.get('cwe')), md)
            rid = baseline.short_id(f['check_id'])
            hits[names[name]['id']][rid] = {'classes':classes, 'confidence':md.get('confidence','audit'),
                                        'line':f['start']['line']-offsets[name]}
        skipped = sorted(set(names)-scanned)
        # A parse failure may legitimately be absent from paths.scanned; other omissions invalidate a run.
        unexplained = [n for n in skipped if n not in status and names[n]['id'] in applicable]
        if unexplained:
            raise RuntimeError(f'Unexplained skipped samples: {unexplained[:5]}')
    old = {}
    if baseline_csv:
        with baseline_csv.open(encoding='utf-8-sig',newline='') as f:
            old = {r['id']:r for r in csv.DictReader(f)}
        if set(old) != {r['id'] for r in rows}:
            raise RuntimeError('Baseline sample IDs do not match current split')
    rule_stats = collections.defaultdict(collections.Counter)
    records = []
    for name,r in names.items():
        fs = hits.get(r['id'],{})
        positive = r['cls_gt'] != baseline.NEG
        correct = [rid for rid,f in fs.items() if r['cls_gt'] in f['classes']]
        high = [rid for rid in correct if fs[rid]['confidence']=='high']
        old_hit = bool(int(old[r['id']]['correct_any'])) if old else False
        for rid,f in fs.items():
            st=rule_stats[rid]
            st['positive_hits' if positive else 'negative_hits']+=1
            st['correct_positive']+=positive and rid in correct
            st['new_positive_vs_baseline']+=positive and rid in correct and not old_hit
        records.append({'id':r['id'],'language':r['programming_language'],
                        'class':baseline.disp(r['cls_gt']), 'parse':status.get(name,'ok' if r['id'] in applicable else 'not_applicable'),
                        'correct_any':int(bool(correct)), 'correct_high':int(bool(high)),
                        'any_finding':int(bool(fs)), 'any_high':int(any(f['confidence']=='high' for f in fs.values())),
                        'baseline_correct':int(old_hit),
                        'new_correct':int(bool(correct) and not old_hit),
                        'rules':';'.join(sorted(fs))})
    with (output/f'{split}_samples.csv').open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    idx={r['id']:r for r in originals}
    after={r['pair_id']:r['id'] for r in originals if r.get('version')=='after_fix'}
    pair_stats={}
    for rid in rule_stats:
        before=[r for r in originals if r.get('version')=='before_fix' and r.get('labels')
                and rid in hits.get(r['id'],{}) and sast.canonical_class(r['labels'][0]) in hits[r['id']][rid]['classes']]
        paired=[r for r in before if r.get('pair_id') in after]
        pair_stats[rid]={'correct_before_with_after':len(paired),
                         'after_still_flagged':sum(rid in hits.get(after[r['pair_id']],{}) for r in paired)}
    pos=[r for r in records if r['class']!=baseline.NEG_NAME]
    neg=[r for r in records if r['class']==baseline.NEG_NAME]
    if digest(config) != config_hash:
        raise RuntimeError('Rule configuration changed during evaluation; discard this run')
    summary={'dataset_version':dataset,'dataset_dir':str(ddir),'split':split,'n':len(rows),'semgrep_version':version,'rules_sha256':config_hash,
             'data_sha256':digest(source),'data_card_sha256':digest(ddir/'DATA_CARD.md'),
             'config':str(config.resolve()),'baseline_csv':str(baseline_csv) if baseline_csv else None,
             'n_positive':len(pos),'n_negative':len(neg),'correct_positive':sum(r['correct_any'] for r in pos),
             'correct_high':sum(r['correct_high'] for r in pos),
             'negative_flagged':sum(r['any_finding'] for r in neg),'negative_high':sum(r['any_high'] for r in neg),
             'new_correct_vs_baseline':sum(r['new_correct'] for r in pos),
             'parse':dict(collections.Counter(r['parse'] for r in records)),
             'n_scanned':len(scanned),'rules':{rid:dict(st) for rid,st in sorted(rule_stats.items())},
             'pairs':pair_stats,
             'cells':{lang+'|'+cls:{'n':len(rr),'correct':sum(r['correct_any'] for r in rr)}
                      for lang in baseline.LANGS for cls in sorted({r['class'] for r in pos})
                      if (rr:=[r for r in pos if r['language']==lang and r['class']==cls])},
             'policy':'train for development, val for aggregate evaluation; no test or target applications read; no labels changed'}
    (output/f'{split}_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:summary[k] for k in ['split','correct_positive','negative_flagged','new_correct_vs_baseline','rules']},ensure_ascii=False),flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--split',required=True,choices=['train','val'])
    ap.add_argument('--config',required=True,type=Path)
    ap.add_argument('--out',required=True,type=Path)
    ap.add_argument('--baseline',type=Path)
    ap.add_argument('--dataset',default='v2.3',choices=['v2.3'])
    ap.add_argument('--data-root',type=Path)
    args=ap.parse_args()
    evaluate(args.split,args.config.resolve(),args.out.resolve(),args.baseline.resolve() if args.baseline else None,args.dataset,args.data_root)
