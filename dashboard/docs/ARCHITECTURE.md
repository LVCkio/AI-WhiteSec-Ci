# Kiến trúc phân tích song song và Security Gate

```text
                 Git SHA + source scope + build digest
                                  |
                          POST /v1/runs
                                  |
                 +----------------+----------------+
                 |                                 |
         Checkmarx do CI chạy              CodeBERT inference nền
         SARIF + scan metadata             scores + status + version
                 |                                 |
                 +-------------- Gateway ----------+
                         khớp identity / scope
                                  |
                        Security Gate + policy
                       authority: gateway-security-gate
                       PASS / BLOCK / REVIEW / ERROR
                                  |
                       CI kiểm tra allow_deploy
```

CI phải đăng ký run trước khi chờ Checkmarx để hai detector thực sự chạy độc lập. CodeBERT không nhận SARIF làm điều kiện bắt đầu và không phát quyết định deploy. Gateway tiếp nhận/chuẩn hóa từng kết quả rồi Security Gate trong Gateway áp dụng policy có phiên bản.

| Thành phần | Trách nhiệm |
| --- | --- |
| Checkmarx | Quét cùng SHA/scope, giao SARIF và trạng thái scanner độc lập |
| CodeBERT | Nạp checkpoint cố định; trả scores, coverage, model version và thresholds |
| Gateway / Security Gate | Điều phối hai nhánh, kiểm tra identity, hợp nhất evidence và phát quyết định cuối |
| CI | Bắt đầu run/scan, giao report, chờ gate và thực thi quyết định đúng artifact |
| Audit store | Lưu unit references/hashes, branch results, normalized scan và quyết định; không lưu raw source |

## Hợp đồng schema 2.0

`POST /v1/runs` nhận `RunStart(identity, sources)` và kích hoạt CodeBERT nền ngay. `POST /v1/runs/{id}/checkmarx` nhận `CheckmarxScan` cho run đã tồn tại. `GET /v1/runs/{id}` trả `RunView` với trạng thái pending/decided, trạng thái từng nhánh và decision nullable. CodeBERT dùng `POST /v1/inferences` nội bộ, không có policy hoặc endpoint quyết định bảo mật.

Gateway giữ run pending đến khi **cả hai kết quả đã đến và khớp**. Một nhánh lỗi đến trước không biến nhánh chưa đến thành kết quả hoàn tất; sau khi cả hai đã nhận, gate trả `ERROR`. Scanner `error`/`incomplete` được giao SARIF `{}`. Retry cùng payload là idempotent; cùng ID khác snapshot/evidence bị từ chối 409. Receipt khởi tạo hoặc HTTP 200 pending không cho phép deploy. Endpoint tuần tự cũ `POST /v1/scans` trả 410.

Policy được khóa vào từng run. Lease suy luận hết hạn sau 150 giây cho phép retry cùng `RunStart` kèm source và giữ nguyên identity/scope; worker từ lease cũ không được ghi đè kết quả mới.

| Gate decision | Điều kiện | allow_deploy |
| --- | --- | --- |
| `PASS` | Hai nhánh hoàn tất; evidence/coverage hợp lệ; không có điều kiện chặn/review; policy đã duyệt | true chỉ khi cả hai là mode thật |
| `BLOCK` | Chính sách yêu cầu chặn vì findings nghiêm trọng hoặc AI score vượt ngưỡng | false |
| `REVIEW` | Finding chưa giải quyết, thiếu coverage/provenance, context quá dài, nhãn ngoài scope hoặc policy chưa duyệt | false |
| `ERROR` | Đã nhận cả hai nhánh, nhưng scanner/model/transport của nhánh không thể hoàn tất hợp lệ | false |

Demo luôn `allow_deploy=false`, kể cả gate `PASS`. Thiếu một nhánh thì decision còn null; CI timeout phải dừng. Gate không dùng detector agreement làm ground truth và không cho điểm AI thấp tự xóa cảnh báo nghiêm trọng của Checkmarx.

HTTP 422 là lỗi input/giao thức: schema, SARIF hoặc identity bất nhất bị từ chối trước khi ghi nhận nhánh hợp lệ. Đây không phải gate `ERROR`; nhánh chưa được chấp nhận không hoàn tất run. CI vẫn dừng. CI build/test, staging readiness, artifact identity và health/rollback tiếp tục là operational checks riêng.

## Identity và coverage

Run giữ repository, full commit SHA, artifact digest và manifest source có SHA-256. `start_run.py` đọc nội dung từ Git SHA bất biến. Scanner và CodeBERT phải phân tích cùng scope; không thay source sau khi khởi tạo run. SARIF revision trái SHA bị từ chối; thiếu provenance hoặc danh sách `analysisTarget` không đủ để xác nhận coverage phải review.

Manifest tự khai và API key chỉ bảo đảm tính nhất quán/xác thực client. Trước deploy thật cần report và snapshot provenance do scanner hoặc CI đáng tin cậy xác nhận. Không sửa report bằng revision tự điền để biến fixture thành scan thật.

Pilot phân loại module Python theo sáu label ID trong `config/label_mapping.json`. Input vượt giới hạn tokenizer không được âm thầm truncate rồi PASS. Model checkpoint/tokenizer/mapping/thresholds và gate policy đều có phiên bản. Feedback phải được kiểm duyệt và gửi pipeline train offline; inference không cập nhật weights.

## Vận hành

Gateway nạp `POLICY_PATH`; CodeBERT readiness chỉ kiểm tra khả năng suy luận bằng artifact model. Mặc định `MODEL_MODE=real`, thiếu artifact tạo branch error. Policy mẫu `release_approved=false` chặn release. `approved_for_inference` trong manifest và phê duyệt release ở Gateway là hai điều kiện riêng.

Compose publish Gateway tại localhost; CodeBERT/PostgreSQL ở mạng nội bộ. `GATEWAY_API_KEY` dành cho CI, `SERVICE_API_KEY` riêng cho inference, `POSTGRES_PASSWORD` dành cho audit. App chạy user không đặc quyền và filesystem chỉ đọc; model mount chỉ đọc, Hugging Face offline. Audit dùng PostgreSQL volume ở Compose hoặc SQLite local.

Compose dùng liveness cho dependency để Gateway vẫn ghi nhận run khi model chưa ready. Một process sống không đồng nghĩa hai nhánh đã hoàn tất hoặc gate cho phép deploy. Chưa chạy scanner thật, train checkpoint, build container/PostgreSQL hoặc triển khai server trong lần chuyển workflow này.

## Dashboard cùng origin

Gateway phục vụ UI tại `/dashboard` và các static assets local. Bốn màn hình tổng quan, theo dõi pipeline, cảnh báo và evaluation dùng cùng adapter dữ liệu. Mặc định adapter đọc fixture UI độc lập; không ghi run vào audit hoặc gọi scanner. Chọn nguồn API local mới đọc projections được xác thực tại `/v1/dashboard`, `/v1/dashboard/runs/{run_id}` và export.

`GATEWAY_API_KEY` được nhập vào UI và chỉ giữ trong memory để gửi header `X-API-Key` tới cùng origin; không persist khóa vào browser storage hoặc URL. Live UI chỉ đọc, giữ nguyên Security Gate authority và không phát quyết định thay backend. Raw source không được trả qua projections; chức năng review fixture chỉ đổi UI mẫu.

Evaluation hiển thị metadata model đã quan sát riêng với benchmark. Không tạo precision/recall/F1 hoặc kết luận FP/FN từ score, scanner agreement hay dữ liệu demo. Phiên Gateway đang chạy code cũ phải được khởi động lại mới có routes dashboard; xem lệnh trong README.
