import { esc, icon, badge, sectionHeading } from './ui.js';

const NO_DATA = 'Chưa có dữ liệu';
const GROUPS = [
  'PATH_TRAVERSAL', 'XSS', 'OS_COMMAND_INJECTION', 'SQL_INJECTION',
  'INSECURE_AUTHENTICATION', 'HARDCODED_CREDENTIALS',
];

const BENCHMARK_ROWS = [
  ['True Positive (TP)', 'Phát hiện đúng lỗ hổng đã được gán nhãn.'],
  ['False Positive (FP)', 'Cảnh báo sai trên mẫu được xác nhận an toàn.'],
  ['False Negative (FN)', 'Bỏ sót lỗ hổng đã được xác nhận.'],
  ['True Negative (TN)', 'Nhận diện đúng mẫu an toàn.'],
  ['Precision', 'Tỷ lệ cảnh báo đúng trong các cảnh báo đưa ra.'],
  ['Recall', 'Tỷ lệ phát hiện trong các lỗ hổng thực tế.'],
  ['F1-score', 'Trung bình điều hòa của precision và recall.'],
  ['Coverage', 'Phạm vi mẫu và nhóm lỗ hổng được đánh giá.'],
  ['Runtime', 'Thời gian chạy trên môi trường đánh giá xác định.'],
  ['Dataset', 'Tên, phiên bản và tập dữ liệu dùng cho benchmark.'],
  ['Model config', 'Checkpoint, tokenizer và ngưỡng dùng cho benchmark.'],
];

function modelStatus(model) {
  const statuses = {
    demo: ['Demo / mô phỏng', 'warning'],
    'observed-real': ['Đã ghi nhận inference thật', 'info'],
    unavailable: ['Chưa có artifact khả dụng', 'muted'],
    error: ['Artifact lỗi', 'danger'],
    loading: ['Đang nạp artifact', 'warning'],
    ready: ['Runtime sẵn sàng', 'success'],
    completed: ['Inference hoàn tất', 'info'],
    not_checked: ['Chưa kiểm tra', 'muted'],
  };
  return statuses[model.status] || [model.status || 'Chưa ghi nhận', 'muted'];
}

function runtimeStatus(model) {
  if (model.readiness === 'ready' || model.readiness === true) {
    return { label: 'Sẵn sàng', tone: 'success', detail: 'Theo trạng thái readiness được cung cấp.' };
  }
  if (['not_ready', 'unavailable', 'error'].includes(model.readiness) || model.readiness === false) {
    return { label: 'Chưa sẵn sàng', tone: 'danger', detail: 'Runtime chưa xác nhận khả năng phục vụ inference.' };
  }
  if (model.readiness && model.readiness !== 'not_checked') {
    return { label: String(model.readiness), tone: 'muted', detail: 'Trạng thái readiness do nguồn dữ liệu cung cấp.' };
  }
  return { label: 'Chưa kiểm tra', tone: 'muted', detail: 'Audit inference không thay thế kiểm tra readiness hiện tại.' };
}

function readinessConditions(model, source) {
  const version = model.version || model.model_version;
  const thresholds = model.thresholds && typeof model.thresholds === 'object' ? model.thresholds : {};
  const configured = GROUPS.filter(group => (
    typeof thresholds[group] === 'number' && Number.isFinite(thresholds[group])
    && thresholds[group] > 0 && thresholds[group] < 1
  )).length;
  const runtime = runtimeStatus(model);
  const mode = model.mode || (model.status === 'demo' ? 'demo' : model.status === 'observed-real' ? 'real' : null);
  const missing = { label: NO_DATA, tone: 'muted' };
  return [
    {
      title: 'Phiên bản model trong audit',
      detail: version ? 'Có định danh artifact; chưa xác minh checkpoint classifier.' : 'Chưa có phiên bản artifact được ghi nhận.',
      label: version ? 'Đã ghi nhận' : NO_DATA,
      tone: version ? 'info' : 'muted',
    },
    { title: 'Readiness của runtime', ...runtime },
    {
      title: 'Chế độ inference',
      detail: mode === 'demo' ? 'Kết quả mô phỏng không dùng để đánh giá hiệu năng.'
        : mode === 'real' ? 'Audit ghi nhận inference thật; chưa có benchmark.' : 'Chưa có chế độ inference trong metadata.',
      label: mode === 'demo' ? 'Demo' : mode === 'real' ? 'Real' : NO_DATA,
      tone: mode === 'demo' ? 'warning' : mode === 'real' ? 'info' : 'muted',
    },
    {
      title: 'Ngưỡng cho sáu nhóm lỗ hổng',
      detail: configured ? 'Cấu hình ngưỡng được lấy từ metadata của model.' : 'Chưa có ngưỡng hợp lệ trong metadata.',
      label: configured ? `${configured}/6 nhóm có ngưỡng` : NO_DATA,
      tone: configured === GROUPS.length ? 'info' : configured ? 'warning' : 'muted',
    },
    {
      title: 'Run tham chiếu của artifact',
      detail: model.observed_run_id ? String(model.observed_run_id) : 'Chưa có run được liên kết với phiên bản model.',
      label: model.observed_run_id ? (source === 'demo' ? 'Run demo' : 'Đã ghi nhận') : NO_DATA,
      tone: model.observed_run_id ? (source === 'demo' ? 'warning' : 'info') : 'muted',
    },
    { title: 'Checkpoint classifier fine-tuned', detail: 'Cần artifact và cấu hình head phân loại đã được kiểm chứng.', ...missing },
    { title: 'Provenance của tập dữ liệu', detail: 'Cần nguồn, phiên bản, phạm vi và quy trình gán nhãn.', ...missing },
    { title: 'Tách train / validation / test', detail: 'Cần chứng cứ tập held-out độc lập và kiểm soát rò rỉ dữ liệu.', ...missing },
    { title: 'Ground truth đã kiểm duyệt', detail: 'Cần nhãn tham chiếu được xác nhận cho từng mẫu.', ...missing },
    { title: 'Báo cáo đánh giá held-out', detail: 'Cần TP, FP, FN, TN và phương pháp đo trên cùng tập đánh giá.', ...missing },
    { title: 'Khả năng tái lập benchmark', detail: 'Cần seed, môi trường, cấu hình và artifact đánh giá cố định.', ...missing },
  ];
}

function renderConditions(conditions) {
  return conditions.map((condition, index) => `
    <div class="eval-condition">
      <span class="eval-condition-number" aria-hidden="true">${String(index + 1).padStart(2, '0')}</span>
      <div class="eval-condition-copy">
        <h4>${esc(condition.title)}</h4>
        <p>${esc(condition.detail)}</p>
      </div>
      <span class="eval-condition-status">${badge(condition.label, condition.tone)}</span>
    </div>
  `).join('');
}

function renderChart(title, description, iconName, required) {
  return `
    <article class="card eval-card eval-chart-card">
      ${sectionHeading(title, description)}
      <div class="eval-chart-placeholder">
        <span class="eval-placeholder-icon" aria-hidden="true">${icon(iconName)}</span>
        <strong>${NO_DATA}</strong>
        <p>${esc(required)}</p>
        <span class="eval-placeholder-tag">Chờ báo cáo đánh giá</span>
      </div>
    </article>
  `;
}

/** Return a read-only screen; the dashboard shell owns actions and API access. */
export function renderEvaluation(data = {}, state = {}) {
  const model = data.model && typeof data.model === 'object' ? data.model : {};
  const source = data.source === 'demo' ? 'demo' : 'live';
  const version = model.version || model.model_version;
  const [statusLabel, statusTone] = modelStatus(model);
  const runtime = runtimeStatus(model);
  const conditions = readinessConditions(model, source);
  const warnings = Array.isArray(data.warnings)
    ? data.warnings.filter(value => typeof value === 'string' && value.trim()) : [];

  return `
    <div class="eval-page">
      <header class="eval-page-header">
        <div>
          <span class="eval-eyebrow">MODEL EVALUATION</span>
          <h2>Đánh giá mô hình</h2>
          <p>Theo dõi bằng chứng đánh giá, cấu hình artifact và mức độ sẵn sàng của mô hình.</p>
        </div>
        <button class="btn btn-secondary" type="button" data-action="export">
          ${icon('download')}<span>Xuất dữ liệu</span>
        </button>
      </header>

      <div class="eval-alert eval-alert-danger" role="alert">
        <span class="eval-alert-icon" aria-hidden="true">${icon('triangle-alert')}</span>
        <div>
          <strong>Chưa có đánh giá held-out với ground truth</strong>
          <p>Chưa có bằng chứng để công bố benchmark của mô hình. Số lần quét, điểm suy luận và dữ liệu demo đều không chứng minh precision, recall hay F1.</p>
        </div>
        ${badge('Chưa được đánh giá', 'danger')}
      </div>

      ${warnings.length ? `<div class="eval-data-warnings" role="note">${warnings.map(warning => `<p>${icon('info')}<span>${esc(warning)}</span></p>`).join('')}</div>` : ''}

      <section class="card eval-card eval-artifact-card" aria-label="Metadata artifact mô hình">
        <div class="eval-card-top">
          ${sectionHeading('Artifact đang được ghi nhận', 'Metadata vận hành được hiển thị riêng với kết quả benchmark.')}
          <button class="btn btn-secondary eval-model-button" type="button" data-action="model-info">
            ${icon('cpu')}<span>Thông tin model</span>
          </button>
        </div>
        <dl class="eval-artifact-grid">
          <div><dt>Phiên bản artifact</dt><dd class="eval-mono">${esc(version || NO_DATA)}</dd></div>
          <div><dt>Trạng thái model</dt><dd>${badge(statusLabel, statusTone)}</dd></div>
          <div><dt>Readiness hiện tại</dt><dd>${badge(runtime.label, runtime.tone)}</dd></div>
          <div><dt>Nguồn dashboard</dt><dd>${badge(source === 'demo' ? 'Dữ liệu demo' : 'Audit live', source === 'demo' ? 'warning' : 'info')}</dd></div>
        </dl>
        <p class="eval-artifact-note">${icon('info')}<span>Tên model hoặc tokenizer nền không chứng minh đã có checkpoint phân loại fine-tuned. Readiness và phiên bản artifact cũng không phải chỉ số chất lượng.</span></p>
      </section>

      <section class="card eval-card eval-readiness-card" aria-label="Điều kiện đánh giá mô hình">
        <div class="eval-card-top">
          ${sectionHeading('Điều kiện để đánh giá mô hình', '11 điều kiện về artifact, dữ liệu tham chiếu và khả năng tái lập.')}
          ${badge('Cần bổ sung bằng chứng', 'warning')}
        </div>
        <div class="eval-readiness-grid">${renderConditions(conditions)}</div>
      </section>

      <section class="card eval-card eval-benchmark-card" aria-label="Bảng benchmark">
        <div class="eval-card-top">
          ${sectionHeading('Benchmark trên tập held-out', 'Các ô chỉ số chỉ được điền khi có báo cáo đánh giá gắn với ground truth.')}
          ${badge('Chưa có benchmark', 'muted')}
        </div>
        <div class="eval-table-wrap">
          <table class="table eval-benchmark-table">
            <caption class="eval-sr-only">Bảng benchmark chưa có dữ liệu đánh giá được xác minh.</caption>
            <thead><tr><th scope="col">Chỉ số / cấu hình</th><th scope="col">CodeBERT</th><th scope="col">Checkmarx</th><th scope="col">Bằng chứng đánh giá</th></tr></thead>
            <tbody>${BENCHMARK_ROWS.map(([label, description]) => `
              <tr><th scope="row"><span>${esc(label)}</span><small>${esc(description)}</small></th>
                <td>${NO_DATA}</td><td>${NO_DATA}</td><td>${NO_DATA}</td></tr>
            `).join('')}</tbody>
          </table>
        </div>
        <div class="eval-info-note">${icon('info')}<p>Điểm CodeBERT là đầu ra inference. Findings của Checkmarx là kết quả scanner. Cả hai cần đối chiếu nhãn tham chiếu độc lập trước khi tính TP, FP, FN, TN.</p></div>
      </section>

      <div class="eval-charts-grid">
        ${renderChart('Confusion matrix', 'Ma trận TP / FP / FN / TN', 'grid-2x2', 'Cần dự đoán và ground truth trên cùng tập held-out.')}
        ${renderChart('Precision–Recall curve', 'Đánh giá theo các mức ngưỡng', 'chart-no-axes-combined', 'Cần điểm dự đoán và nhãn tham chiếu cho từng mẫu.')}
        ${renderChart('Runtime', 'Phân bố thời gian chạy inference', 'timer', 'Cần phép đo lặp lại trên môi trường và cấu hình đã xác định.')}
        ${renderChart('Phân bố lớp', 'Sáu nhóm lỗ hổng và mẫu an toàn', 'chart-column', 'Cần thống kê nhãn thực tế của tập dữ liệu đánh giá.')}
      </div>

      <div class="eval-analysis-grid">
        <section class="card eval-card eval-provenance-card">
          ${sectionHeading('Provenance tập dữ liệu', 'Nguồn và phiên bản của dữ liệu dùng để đánh giá.')}
          <div class="eval-provenance-placeholder">
            <span class="eval-placeholder-icon" aria-hidden="true">${icon('database')}</span>
            <strong>Chưa có dataset card</strong>
            <p>Chưa ghi nhận nguồn dataset, phiên bản, cách gán nhãn và chiến lược chia tập.</p>
          </div>
          <div class="eval-provenance-fields">
            <div><span>Nguồn / phiên bản</span><span>${NO_DATA}</span></div>
            <div><span>Ground truth / kiểm duyệt</span><span>${NO_DATA}</span></div>
            <div><span>Train / validation / test</span><span>${NO_DATA}</span></div>
            <div><span>Kiểm soát data leakage</span><span>${NO_DATA}</span></div>
          </div>
        </section>

        <section class="card eval-card eval-error-analysis-card">
          ${sectionHeading('Phân tích FP / FN', 'Các mẫu dự đoán sai sau khi đối chiếu ground truth.')}
          <div class="eval-error-placeholders">
            <div><span class="eval-analysis-label">FALSE POSITIVE</span>${icon('search-x')}<strong>${NO_DATA}</strong><p>Chờ mẫu cảnh báo sai đã được xác nhận.</p></div>
            <div><span class="eval-analysis-label">FALSE NEGATIVE</span>${icon('scan-search')}<strong>${NO_DATA}</strong><p>Chờ mẫu lỗ hổng bị bỏ sót đã được xác nhận.</p></div>
          </div>
          <div class="eval-info-note">${icon('info')}<p>Chênh lệch giữa scanner và model là tín hiệu cần kiểm duyệt; chưa thể kết luận đó là FP hay FN khi thiếu ground truth.</p></div>
        </section>
      </div>
    </div>
  `;
}
