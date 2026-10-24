# reports/scans

Đặt ở đây file JSON của `scan.py` khi quét một commit / pull request (ví dụ tải artifact từ CI về).
Dashboard (`run_dashboard.bat`) tự đọc mọi `*.json` trong thư mục này, hiển thị ở màn Giám sát lượt quét, Cảnh báo và So sánh.

    .venv\Scripts\python.exe scan.py --repo <repo> --commit <sha> --json reports\scans\<ten>.json --sarif reports\scans\<ten>.sarif
