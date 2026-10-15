# AI WhiteSec CI — Checkmarx và CodeBERT song song

Luồng hiện tại: **cùng Git snapshot → Checkmarx và CodeBERT chạy song song → Gateway hợp nhất → Security Gate quyết định → CI thực thi**. Security Gate nằm trong Gateway, có authority `gateway-security-gate`. CodeBERT chỉ trả điểm, trạng thái suy luận, model version và thresholds; không quyết định deploy.

Chưa có tài khoản Checkmarx hoặc checkpoint classifier sáu nhóm đã được duyệt. Demo dùng SARIF và điểm fixture để thử giao tiếp; luôn `allow_deploy=false`. Chế độ thật mặc định: thiếu model tạo kết quả nhánh lỗi; Gateway giữ run pending đến khi nhận cả hai nhánh rồi gate trả `ERROR`. Policy mẫu chưa được duyệt release. Xem [kiến trúc](docs/ARCHITECTURE.md) và [trạng thái kiểm chứng](docs/BUILD_STATUS.md).

## Chạy local trên Windows

Cần Python 3.11. Chạy trong thư mục `ai-whitesec-ci`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\scripts\run-local.ps1 -Demo -Python .\.venv\Scripts\python.exe
```

Chạy smoke trong cùng cửa sổ PowerShell để dùng API keys do `run-local.ps1` tạo. Gateway dùng port 8080, CodeBERT 8001; audit SQLite và logs nằm trong `data/`. Smoke kiểm tra CodeBERT bắt đầu trước khi báo cáo Checkmarx đến, run ban đầu pending và chỉ có quyết định sau callback scanner.

Nếu hai dịch vụ đang chạy từ phiên bản cũ, khởi động lại để nạp code song song và route dashboard: chạy `stop-local.ps1`, rồi `run-local.ps1 -Demo -Python .\.venv\Scripts\python.exe` trong cùng phiên PowerShell. Có thể thay đường dẫn `.venv` bằng Python đã cài đủ dependencies.

## Dashboard local

Mở [Dashboard](http://127.0.0.1:8080/dashboard) sau khi Gateway chạy. UI được phục vụ cùng origin với Gateway, không cần frontend dev server hoặc bước build riêng. Nếu đổi `-GatewayPort`, dùng URL dashboard mà script in ra.

Năm màn hình: **Tổng quan**, **Giám sát CI/CD**, **Cảnh báo bảo mật**, **Đánh giá mô hình**, **So sánh lượt quét**. Mặc định UI đọc fixture minh họa riêng trong frontend; fixture không tạo scan/audit run và không phải kết quả Checkmarx thật. `-Demo` điều khiển model service, còn nguồn minh họa của UI là lựa chọn riêng.

Tổng quan ưu tiên cảnh báo rủi ro cao, các lượt bị chặn, cần thẩm định và đang chờ bằng chứng. Bấm từng ô để xem danh sách tương ứng theo dự án và khoảng thời gian đã chọn. Phần Security Gate hiển thị lý do đã lưu cùng số liệu đối chiếu từ bằng chứng của đúng lượt chạy.

**So sánh lượt quét** cho phép chọn hai lượt trong cùng repository, xem thay đổi quyết định và đối chiếu các phát hiện theo đường dẫn, vị trí và định danh quy tắc/nhóm. Nhãn **không còn ghi nhận** không chứng minh lỗi đã được sửa. Khi thiếu bằng chứng, lượt chưa hoàn tất hoặc cấu hình/phạm vi khác nhau, dashboard hiển thị giới hạn đối chiếu thay vì khẳng định đã hết lỗ hổng. Dữ liệu demo có ví dụ trước/sau riêng để thử giao diện.

Để đọc audit local, chọn nguồn **API local** trong dashboard và nhập `GATEWAY_API_KEY` của phiên chạy Gateway. Requests chỉ đi tới API cùng origin. Khóa giữ trong memory của trang, không lưu trong URL, localStorage hoặc sessionStorage; tải lại trang cần nhập lại. UI live chỉ đọc audit và cho xuất dữ liệu: chưa có API xác nhận finding/False Positive hoặc chạy scanner từ dashboard. Source code chỉ hiển thị ở fixture demo; live audit không trả raw source.

Danh sách cảnh báo và bộ đếm UI gồm finding Checkmarx cùng tín hiệu CodeBERT vượt ngưỡng chưa có finding tương ứng; hai nguồn trùng unit/nhóm được ghép để tránh đếm đôi. `summary.findings_count` trong JSON audit vẫn là số finding Checkmarx; `ai_threshold_hits` thống kê tín hiệu model riêng. Điểm thấp hơn ngưỡng được giữ khi có unit/nhóm liên quan, không tự chuyển thành cảnh báo AI.

Chưa có tài khoản Checkmarx, model classifier đã duyệt hoặc policy cho release thật. Dashboard phân biệt pending, quyết định gate và `allow_deploy`; demo luôn không deploy. Trang evaluation giữ benchmark chưa có dữ liệu cho tới khi có held-out/ground truth; AI score và số findings không phải precision/recall/F1.

Khi xem xong, dừng phiên local bằng `scripts/stop-local.ps1`. Smoke có thể chạy trong cùng cửa sổ PowerShell khi hai dịch vụ vẫn đang chạy:

```powershell
.\.venv\Scripts\python.exe scripts/smoke_demo.py --url http://127.0.0.1:8080
```

## Kiểm tra hạ tầng

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts/smoke_demo.py --offline
.\scripts\verify-local.ps1 -Python .\.venv\Scripts\python.exe
```

Đã đạt **70 tests**; smoke offline và smoke HTTP giữa hai process local đã được kiểm chứng. Smoke chứng minh CodeBERT đã hoàn tất trong lúc Checkmarx còn pending thì chưa có quyết định; callback scanner mới tạo gate `BLOCK`/`PASS`, cả hai là demo và `allow_deploy=false`.

Kiểm tra logic so sánh mới (Node chỉ cần khi phát triển, không cần để mở dashboard):

```powershell
node --experimental-vm-modules scripts/verify-dashboard-comparison.mjs
```

Kiểm tra này bao gồm thay đổi định danh finding giữa các run, dịch chuyển dòng, phạm vi source khác nhau, thiếu prediction, pending/error, hai repository khác nhau và dữ liệu không đủ để kết luận.

`verify-local.ps1` thử riêng trên 18080/18081 với `-DataDirectory data\verification`, rồi dừng hai process do nó tạo; không dừng phiên người dùng ở 8080/8001. `.github/workflows/infra-checks.yml` kiểm tra scaffold bằng tests, demo và Compose config; chưa nối scanner hoặc deploy thật.

## Docker Compose

Copy `.env.example` thành `.env` và điền ba secret riêng: `GATEWAY_API_KEY`, `SERVICE_API_KEY`, `POSTGRES_PASSWORD`. `.env` local được ignore. Password dạng hexadecimal tránh ký tự cần encode trong URI database.

```powershell
docker compose -f compose.yaml -f compose.demo.yaml config --quiet
docker compose -f compose.yaml -f compose.demo.yaml up --build -d
```

Bản demo không cài PyTorch. Bản thật cần artifact ở `models/current`:

```powershell
docker compose config --quiet
docker compose up --build -d
```

Gateway publish `127.0.0.1:8080`; CodeBERT và PostgreSQL ở mạng nội bộ. Gateway nạp `POLICY_PATH=/app/config/final-policy.json`; CodeBERT chỉ nạp model local từ mount chỉ đọc. Image model cài CPU PyTorch/Transformers; không tự tải checkpoint. PostgreSQL giữ audit trong volume `audit-data`; `docker compose down` giữ volume.

Compose dùng liveness để Gateway vẫn hoạt động khi model thiếu. Readiness CodeBERT lúc đó trả 503. Docker engine trên máy hiện đang tắt; các lệnh `up` trên đây là hướng dẫn, chưa phải xác nhận container đã chạy.

## CI: bắt đầu cả hai nhánh trước khi chờ scanner

Tạo run **trước** khi bắt đầu/chờ Checkmarx. `start_run.py` đọc Python source từ commit SHA bằng Git, đăng ký identity/snapshot và kích hoạt suy luận nền ngay; receipt không cấp quyền deploy.

```powershell
$env:GATEWAY_API_KEY = '<gateway key từ secret CI>'
.\.venv\Scripts\python.exe scripts/start_run.py `
    --source '<repo-local>' --commit '<full-commit-sha>' `
    --artifact-digest 'sha256:<build-digest>' `
    --repository '<repository-url>' --run-id '<ci-run-id>' `
    --url http://127.0.0.1:8080 --output run-receipt.json
```

Tiếp đó CI chạy Checkmarx trên **cùng SHA và scope** trong lúc CodeBERT đang chạy. Khi scanner hoàn tất, gửi SARIF và metadata thật:

```powershell
.\.venv\Scripts\python.exe scripts/submit_scan.py `
    --source '<repo-local>' --commit '<full-commit-sha>' `
    --sarif '<reports/checkmarx.sarif>' --scan-id '<checkmarx-scan-id>' `
    --scan-preset '<preset đã dùng>' --scan-status completed `
    --artifact-digest 'sha256:<build-digest>' `
    --repository '<repository-url>' --run-id '<ci-run-id>' `
    --url http://127.0.0.1:8080 --output decision.json
```

`submit_scan.py` chỉ giao kết quả Checkmarx cho run đã tồn tại rồi poll Security Gate; không khởi động CodeBERT muộn. Chỉ exit `0` khi gate trả `PASS`, mode thật và `allow_deploy=true`. Pending quá timeout, thiếu nhánh, lỗi HTTP, demo, `BLOCK`, `REVIEW` hoặc `ERROR` đều dừng CI. Giữ nguyên SHA, scope, build digest và run ID giữa hai lệnh.

## API schema 2.0

| API | Kết quả |
| --- | --- |
| `POST /v1/runs` với `RunStart(identity, sources)` | Đăng ký snapshot, bắt đầu CodeBERT nền, trả `RunView` |
| `POST /v1/runs/{run_id}/checkmarx` với `CheckmarxScan` | Nhận metadata/SARIF của nhánh scanner độc lập |
| `GET /v1/runs/{run_id}` | `RunView`: pending/decided, trạng thái hai nhánh, decision có thể null |
| CodeBERT nội bộ `POST /v1/inferences` | Scores/status/model version/thresholds, không có quyết định release |

Client dùng `X-API-Key`; Gateway gọi CodeBERT bằng `X-Service-Key`. Gate chỉ hợp nhất hai kết quả đã khớp identity và scope; policy được khóa cho từng run. Gửi lại cùng nội dung/run là idempotent; tái dùng ID với nội dung khác trả 409. Request/report sai schema hoặc revision bất nhất trả 422; không phải quyết định gate `ERROR`. Scanner có status `error`/`incomplete` được gửi SARIF `{}` và tạo gate `ERROR` sau khi cả hai nhánh đã được ghi nhận. Thiếu một nhánh vẫn pending và không được deploy. Endpoint cũ `POST /v1/scans` trả 410.

Nếu worker suy luận gián đoạn, sau lease 150 giây có thể gửi lại cùng `RunStart` kèm source để tiếp tục; giữ nguyên run ID, identity và scope. Worker cũ không được ghi đè kết quả của lease mới.

SARIF thật cần revision khớp commit và artifacts `analysisTarget` khớp source manifest. Thiếu provenance/coverage đi review; findings rỗng không chứng minh scan đầy đủ. API key xác thực bên gửi, không chứng minh report là bản gốc scanner. Cần metadata do scanner/CI đáng tin cậy xác nhận; không tự thêm revision vào fixture để dùng làm scan thật. Tích hợp Checkmarx One/CxSAST cần tài khoản và kiểm thử adapter bằng report thực tế.

## Model và policy

Artifact phải là CodeBERT classifier đa nhãn đã fine-tune, có tokenizer, config, Safetensors và `manifest.json` theo `models/manifest.example.json`. CodeBERT nền chưa fine-tune không thay thế artifact này. Chỉ bật `approved_for_inference` sau đánh giá; policy tại Gateway vẫn `release_approved=false` đến khi được duyệt.

Pilot hỗ trợ Python với sáu nhãn theo thứ tự: `PATH_TRAVERSAL`, `XSS`, `OS_COMMAND_INJECTION`, `SQL_INJECTION`, `INSECURE_AUTHENTICATION`, `HARDCODED_CREDENTIALS`. Context vượt giới hạn token, nhãn/CWE ngoài scope hoặc evidence chưa giải quyết phải review. Threshold mẫu chưa được chứng minh bằng validation.

Để chạy model thật local, cài CPU PyTorch cùng `requirements-model.txt`, đặt artifact ở `models/current`, rồi chạy `run-local.ps1` không có `-Demo`. Hiện chưa train model, chưa quét Checkmarx thật hoặc deploy server.
