# Trạng thái hạ tầng — 13/10/2026

Workflow hiện tại theo yêu cầu mới: **Checkmarx và CodeBERT chạy song song → Gateway hợp nhất → Security Gate quyết định**. Authority cuối là `gateway-security-gate`; CodeBERT chỉ trả kết quả suy luận. API hiện dùng schema 2.0 và quy trình đăng ký run trước khi giao kết quả scanner.

Runtime, scripts, tests, docs và cấu hình đã đồng bộ cho bản song song. Gateway giữ pending khi chưa nhận đủ hai nhánh, khóa policy theo run và chỉ Security Gate tại Gateway phát quyết định cuối.

Dashboard local được gắn tại `/dashboard` với bốn màn hình tổng quan, pipeline, alerts và evaluation. UI mặc định dùng fixture minh họa riêng; nguồn API local cần Gateway API key chỉ lưu memory và đọc audit cùng origin. Live UI không có thao tác ghi review hoặc chạy scanner.

Đã kiểm chứng lại bản hiện tại:

- **70 backend tests đạt**, gồm 15 kiểm thử dashboard/auth/asset headers/path isolation.
- Kiểm tra trình duyệt đạt: bốn màn hình, filter và run/finding đồng bộ, API key đúng/sai, source demo/live, export JSON và responsive 390px/1440px. Không có lỗi JavaScript trong lượt kiểm tra cuối.
- Adapter qua 122 checks trên audit HTTP và fixture demo; timing detector thiếu được giữ `null`, benchmark/readiness không bị suy diễn từ lịch sử inference.
- Smoke offline đạt; CodeBERT hoàn tất trong lúc Checkmarx còn pending vẫn chưa có quyết định.
- Smoke giữa hai process HTTP thật trên 18080/18081 đạt: callback Checkmarx tạo gate `BLOCK` hoặc `PASS`; cả hai là demo và `allow_deploy=false`.
- `verify-local.ps1` dùng riêng `data\verification`; hai process kiểm thử đã được dừng, phiên người dùng 8080/8001 không bị dừng.
- Compose thật/demo được validate; chưa chạy container.

Ảnh giao diện minh họa đã kiểm tra: [Dashboard tổng quan](screenshots/dashboard-overview.jpg). Dashboard dùng font/icon vendored trong `app/static/dashboard/vendor`, không gọi CDN hoặc cần Node tại runtime; `scripts/vendor-dashboard.mjs` chuẩn bị lại asset khi phát triển.

Giới hạn hiện tại:

- Chưa có tài khoản Checkmarx, chưa xác nhận adapter bằng scan thật.
- Chưa có checkpoint classifier sáu nhóm được duyệt. Mode thật thiếu artifact tạo nhánh lỗi; sau khi cả hai nhánh đến, gate trả `ERROR` và không deploy.
- Policy release mặc định chưa duyệt; demo luôn `allow_deploy=false`.
- Docker engine hiện đang tắt; chưa build/chạy container hoặc PostgreSQL cho bản song song.
- Chưa deploy server hoặc kích hoạt pipeline quét/release thật.

Phiên local đang chạy từ code cũ cần được khởi động lại bằng `stop-local.ps1`, rồi `run-local.ps1 -Demo -Python <python-đã-cài-dependencies>` để nạp workflow và routes dashboard mới. Các lệnh, URL dashboard và đường dẫn `.venv` mẫu nằm trong [README](../README.md).

## Nâng cấp dashboard — 15/10/2026

- Thêm màn hình so sánh hai lượt quét cùng repository: mới ghi nhận, còn ghi nhận, không còn ghi nhận và chưa thể kết luận; có bộ lọc, đổi chiều và xuất JSON.
- Đối chiếu kiểm tra chế độ, preset, phiên bản model, ngưỡng, phạm vi file/khoảng dòng, coverage, manifest và tính đầy đủ của prediction. Không coi thiếu bằng chứng hoặc pending là đã sửa lỗi.
- Tổng quan có bốn chỉ số ưu tiên bấm được, giới hạn theo dự án và thời gian; bộ đếm phụ được thu gọn.
- Security Gate trình bày lý do đã lưu, liên kết finding khi có mapping, policy/coverage và điểm so với ngưỡng đúng run. Số liệu hỗ trợ không tự chứng minh nguyên nhân quyết định.
- Kiểm tra đạt: 70 backend tests, 121 kiểm tra so sánh và 195 kiểm tra adapter. Đã kiểm tra trình duyệt ở 390px và 1440px, bộ lọc từ KPI, dữ liệu demo trước/sau, pending và xuất JSON.

Ảnh bản nâng cấp: [Tổng quan](screenshots/dashboard-upgrade-overview.jpg), [So sánh lượt quét](screenshots/dashboard-upgrade-comparison.jpg). Benchmark, nguồn Checkmarx và checkpoint thật vẫn cần bằng chứng thực nghiệm như các giới hạn đã nêu ở trên.
