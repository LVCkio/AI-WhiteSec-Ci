from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def safe_div(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def aggregate_chunks(rows: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("parent_sample_id") or row["sample_id"])].append(row)
    aggregated = []
    for parent_id, items in grouped.items():
        expected = Counter(item["expected"] for item in items).most_common(1)[0][0]
        predicted = max(items, key=lambda item: float(item.get("confidence", 0)))
        aggregated.append(
            {
                "sample_id": parent_id,
                "expected": expected,
                "predicted": predicted["predicted"],
                "confidence": predicted.get("confidence"),
            }
        )
    return aggregated


def evaluate(rows: list[dict]) -> dict:
    labels = sorted({row["expected"] for row in rows} | {row["predicted"] for row in rows})
    per_label = {}
    confusion = {expected: {predicted: 0 for predicted in labels} for expected in labels}
    for row in rows:
        confusion[row["expected"]][row["predicted"]] += 1
    for label in labels:
        tp = sum(row["expected"] == label and row["predicted"] == label for row in rows)
        fp = sum(row["expected"] != label and row["predicted"] == label for row in rows)
        fn = sum(row["expected"] == label and row["predicted"] != label for row in rows)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1 = safe_div(2 * precision * recall, precision + recall)
        per_label[label] = {
            "support": sum(row["expected"] == label for row in rows),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        }
    return {
        "samples": len(rows),
        "accuracy": round(safe_div(sum(row["expected"] == row["predicted"] for row in rows), len(rows)), 6),
        "macro_f1": round(safe_div(sum(value["f1"] for value in per_label.values()), len(per_label)), 6),
        "per_label": per_label,
        "confusion_matrix": confusion,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate classifier predictions from JSONL")
    parser.add_argument("input", type=Path, help="JSONL with sample_id, expected, predicted, and confidence")
    parser.add_argument("--aggregate-parent", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rows = read_jsonl(args.input)
    if args.aggregate_parent:
        rows = aggregate_chunks(rows)
    report = evaluate(rows)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()

