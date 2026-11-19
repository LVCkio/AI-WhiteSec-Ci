# Semgrep v4.6.1 trên dataset v2.3 (train/val)

Ngày 26/10/2026 · Semgrep 1.181.0 · bundle sha256 `bff761dd3726fa3a094109e30dc3d6f62612254d4cf135e3a1e627ac2b863986` · `verify` đạt.
Dataset v2.3 (`dataset_model/dataset/v2.3`): train sha256 `dfc6b766…b527` (8.261), val sha256 `06033fd8…d28c` (1.225), khớp DATA_CARD. Không đọc, không quét test.
Lệnh: `run_v23_v461.bat` → `evaluate_supplement_v22.py --dataset v2.3 --split train|val`.

## Kết quả

| Chỉ số | Train v2.3 | Val v2.3 |
|---|---:|---:|
| Mẫu dương bắt đúng lớp (high+audit) | 777/2.773 = 28,0% | 132/381 = 34,6% |
| Mẫu dương bắt đúng lớp tầng high | 157/2.773 = 5,7% | 17/381 = 4,5% |
| Mẫu âm có finding (bất kỳ) | 978/5.488 = 17,8% | 159/844 = 18,8% |
| Mẫu âm có finding high | 67/5.488 = 1,2% | 13/844 = 1,5% |

Theo lớp (bắt đúng / mẫu dương):

| Lớp | Train | Val |
|---|---:|---:|
| SQL_INJECTION | 271/679 | 45/68 |
| XSS | 260/1.204 | 49/164 |
| OS_COMMAND_INJECTION | 75/194 | 11/56 |
| PATH_TRAVERSAL | 75/214 | 18/41 |
| INSECURE_AUTHENTICATION | 3/181 | 0/29 |
| HARDCODED_CREDENTIALS | 93/301 | 9/23 |

## So với v2.2 (cùng bundle v4.6.1)

- Mẫu chung giữa v2.2 và v2.3: kết quả **giống hệt** (0 mẫu khác), nên chênh lệch chỉ do mẫu bị bỏ.
- Quy tắc T bỏ 269 mẫu dương train; Semgrep chỉ bắt đúng 14 trong số đó (5%). Phù hợp với nhận định của leader rằng các mẫu này phần lớn mang nhãn sai.
- Recall train tăng 26,0% → 28,0% chỉ vì mẫu số nhỏ lại; số mẫu bắt đúng tầng high không đổi (157).

## So với CodeBERT (tham khảo)

`RESULTS.md` (val **v2.2**, ngưỡng dò trên chính val): model `v22_sel_e8` báo nhầm 44,7% mẫu âm. Semgrep trên val v2.3: 18,8% (bất kỳ tầng), 1,5% (high). Hai số chưa cùng tập val; cần số CodeBERT trên val v2.3 để so ngang.

## Điều chưa chắc chắn

- Nhãn v2.3 vẫn phần lớn UNREVIEWED; quy tắc T chỉ bỏ mẫu, không sửa nhãn.
- Không có baseline v2.3 trước đó nên cột `new_correct_vs_baseline` trong summary không có ý nghĩa (bằng toàn bộ).
