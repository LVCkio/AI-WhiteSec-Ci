#!/usr/bin/env python3
# Dung: python measure_ts_vs_dataset.py <val.jsonl> <thu muc ci/ cua repo AI-WhiteSec-Ci>
"""Do do khop ranh gioi ham: don vi trong dataset (CVEfixes method_change / lizard) vs tree-sitter (ci/aiws_ci/units.py)."""
import json, sys, textwrap, collections
sys.path.insert(0, sys.argv[2])
from aiws_ci.units import file_units
LANG = {"Python": "python", "Java": "java", "JavaScript": "javascript", "PHP": "php"}

def wrap(code, lang):
    """Dua doan ham ve dang parse duoc; tra ve (text, so dong lech)."""
    if lang == "python":
        return textwrap.dedent(code), 0
    if lang == "php":
        return "<?php\n" + code, 1
    if lang == "java":
        return "class __W__ {\n" + code + "\n}", 1
    return code, 0

def classify(r):
    lang = LANG[r["language"]]
    code = r["code"] or ""
    lines = code.splitlines()
    nz = [i for i, l in enumerate(lines, 1) if l.strip()]
    if not nz:
        return "empty"
    first, last = nz[0], nz[-1]
    tries = [wrap(code, lang)]
    if lang == "javascript":
        tries.append(("class __W__ {\n" + code + "\n}", 1))    # method trong class / object
    if lang == "php":
        tries.append(("<?php class __W__ {\n" + code + "\n}", 1))   # method co public/static phai nam trong class
    best = None
    for text, off in tries:
        us, err = file_units("x", text, lang)
        fs = [(u["start"] - off, u["end"] - off) for u in us if u["unit"] == "function"]
        top = [f for f in fs if f[0] <= first + 0 and f[1] >= last]
        if any(s == first and e == last for s, e in fs):
            return "exact"
        if top:
            best = best or "ts_rong_hon"
        elif fs:
            m = max(fs, key=lambda f: f[1] - f[0])
            cov = (min(m[1], last) - max(m[0], first) + 1) / (last - first + 1)
            best = best or ("ts_hep_hon (phu >=90%)" if cov >= 0.9 else "ts_hep_hon (phu <90%)")
    return best or "ts_khong_thay_ham"

R = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
tab = collections.defaultdict(collections.Counter)
for r in R:
    if r["unit"] != "function":
        continue
    tab[(r["merge_source"], r["language"])][classify(r)] += 1
tot = collections.Counter()
for k in sorted(tab):
    tot.update(tab[k])
    n = sum(tab[k].values())
    print(f"{k[0]:10s} {k[1]:10s} n={n:4d}  " + "  ".join(f"{c}={v}" for c, v in tab[k].most_common()))
n = sum(tot.values())
print(f"\nTONG n={n}: " + "  ".join(f"{c}={v} ({v/n:.1%})" for c, v in tot.most_common()))
bylang = collections.defaultdict(collections.Counter)
for (src, lang), c in tab.items():
    bylang[lang].update(c)
for lang, c in sorted(bylang.items()):
    m = sum(c.values()); print(f"{lang:10s} exact {c['exact']}/{m} = {c['exact']/m:.1%}")
