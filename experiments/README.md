# Experiment workspace

Store an immutable manifest for every experiment:

- dataset checksum and split name;
- model version, checkpoint checksum, tokenizer, and label map;
- class thresholds and random seed;
- Checkmarx project, preset, and scanner version;
- correlation policy version;
- commit SHA and wall-clock runtime for each stage.

`evaluate.py` accepts JSONL rows with this minimum contract:

```json
{"sample_id":"sample-1","parent_sample_id":"case-1","expected":"CWE-89","predicted":"CWE-89","confidence":0.94}
```

Use `--aggregate-parent` when functions were split into multiple CodeBERT chunks.
Do not choose thresholds, Checkmarx presets, or policies using the held-out test set.

