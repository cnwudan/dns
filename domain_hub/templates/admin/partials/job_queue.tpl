<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$__ = static function (string $key, string $fallback = '') use ($lang): string {
    return htmlspecialchars($lang[$key] ?? $fallback, ENT_QUOTES, 'UTF-8');
};
$__raw = static function (string $key, string $fallback = '') use ($lang): string {
    return $lang[$key] ?? $fallback;
};
$jobsView = $cfAdminViewModel['jobs'] ?? [];
$jobSummary = $jobsView['summary'] ?? [];
$jobsPagination = $jobsView['jobs'] ?? [];
$recentJobs = $jobsPagination['items'] ?? [];
$jobsPage = $jobsPagination['page'] ?? 1;
$jobsTotalPages = $jobsPagination['totalPages'] ?? 1;
$jobsTotal = $jobsPagination['total'] ?? 0;
$jobError = $jobsView['error'] ?? null;
$diffView = $jobsView['diffs'] ?? [];
$recentDiffs = $diffView['items'] ?? [];
$diffPage = $diffView['page'] ?? 1;
$diffTotalPages = $diffView['totalPages'] ?? 1;
$diffTotal = $diffView['total'] ?? 0;
$backlogCount = $jobSummary['backlogCount'] ?? 0;
$jobErrorRate = $jobSummary['errorRate'] ?? '-';
$lastCalTime = $jobSummary['lastCalibrationTime'] ?? '-';
$lastCalStatus = $jobSummary['lastCalibrationStatus'] ?? '-';
$calibrationByKind = $jobSummary['calibrationSummary']['byKind'] ?? [];
$calibrationByAction = $jobSummary['calibrationSummary']['byAction'] ?? [];
$rootdomainOptions = $jobsView['rootdomainOptions'] ?? [];
$hasRootdomainOptions = !empty($rootdomainOptions);

$buildPageQuery = static function (string $key, int $page) {
    $params = $_GET ?? [];
    $params['module'] = 'domain_hub';
    unset($params[$key]);
    $params[$key] = $page;
    return '?' . http_build_query($params);
};
?>

<div class="card mb-4 border-danger">
  <div class="card-body">
    <h5 class="card-title mb-3 text-danger"><i class="fas fa-bomb"></i> <?php echo $__('queue_danger_title', '危险操作'); ?></h5>
    <div class="alert alert-warning">
      <?php echo $__('queue_danger_warning', '“一键重置”将会清空本插件的所有本地数据表，并删除在 tbladdonmodules 中的配置，不会触发云端操作。'); ?>
    </div>
    <form method="post" onsubmit="return confirm('<?php echo addslashes($__('queue_danger_confirm', '确定执行一键重置？此操作会清空本地数据且不可撤销！')); ?>');" class="row g-2 align-items-end">
      <input type="hidden" name="action" value="reset_module">
      <div class="col-md-6">
        <label class="form-label"><?php echo $__('queue_danger_label', '请输入 RESET 以确认'); ?></label>
        <input type="text" name="confirm" class="form-control" placeholder="RESET" required>
      </div>
      <div class="col-md-6">
        <button type="submit" class="btn btn-danger w-100"><?php echo $__('queue_danger_button', '一键重置（仅本地数据与配置）'); ?></button>
      </div>
    </form>
  </div>
</div>

<div class="row">
  <div class="col-md-6">
    <div class="card mb-4" id="queue-summary">
      <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-clipboard-list"></i> <?php echo $__('queue_card_title', '队列管理'); ?></h5>
        <div class="mb-2 text-muted"><?php echo sprintf($__('queue_backlog_summary', '积压：%s，近期错误率：%s'), intval($backlogCount), htmlspecialchars($jobErrorRate)); ?></div>
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead>
              <tr>
                <th><?php echo $__('queue_header_id', 'ID'); ?></th>
                <th><?php echo $__('queue_header_type', '类型'); ?></th>
                <th><?php echo $__('queue_header_status', '状态'); ?></th>
                <th><?php echo $__('queue_header_started', '开始'); ?></th>
                <th><?php echo $__('queue_header_finished', '结束'); ?></th>
                <th><?php echo $__('queue_header_duration', '耗时(秒)'); ?></th>
                <th><?php echo $__('queue_header_summary', '摘要'); ?></th>
                <th><?php echo $__('queue_header_created', '创建'); ?></th>
                <th><?php echo $__('queue_header_updated', '更新'); ?></th>
                <th><?php echo $__('common_actions', '操作'); ?></th>
              </tr>
            </thead>
            <tbody>
              <?php if (!empty($recentJobs)): ?>
                <?php foreach ($recentJobs as $job): ?>
                  <?php
                    $statsSummary = '';
                    $warningsList = [];
                    $statsJson = $job->stats_json ?? '';
                    if ($statsJson) {
                        $statsArr = json_decode($statsJson, true);
                        if (is_array($statsArr)) {
                            $parts = [];
                            if (isset($statsArr['processed_subdomains'])) { $parts[] = 'subs:' . intval($statsArr['processed_subdomains']); }
                            if (isset($statsArr['differences_total'])) { $parts[] = 'diff:' . intval($statsArr['differences_total']); }
                            if (isset($statsArr['records_updated_local'])) { $parts[] = 'upd:' . intval($statsArr['records_updated_local']); }
                            if (isset($statsArr['records_imported_local'])) { $parts[] = 'add:' . intval($statsArr['records_imported_local']); }
                            if (isset($statsArr['records_updated_on_cf'])) { $parts[] = 'cf_upd:' . intval($statsArr['records_updated_on_cf']); }
                            if (isset($statsArr['records_deleted_on_cf'])) { $parts[] = 'cf_del:' . intval($statsArr['records_deleted_on_cf']); }
                            if (!empty($statsArr['warnings'])) {
                                $warnings = is_array($statsArr['warnings']) ? $statsArr['warnings'] : [$statsArr['warnings']];
                                foreach ($warnings as $warningItem) {
                                    if (is_array($warningItem) || is_object($warningItem)) {
                                        $warningItem = json_encode($warningItem, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                                    }
                                    $warningItem = trim((string) $warningItem);
                                    if ($warningItem !== '') {
                                        $warningsList[] = $warningItem;
                                    }
                                }
                                if (!empty($warningsList)) {
                                    $parts[] = 'warn:' . count($warningsList);
                                }
                            }
                            if (!empty($statsArr['message'])) {
                                $parts[] = $statsArr['message'];
                            }
                            $statsSummary = implode(' | ', array_slice(array_filter($parts), 0, 5));
                        }
                    }
                    if (!empty($job->attempts) && intval($job->attempts) > 1) {
                        $statsSummary = ($statsSummary !== '' ? $statsSummary . ' | ' : '') . 'att:' . intval($job->attempts);
                    }
                    if ($statsSummary === '' && !empty($warningsList)) {
                        $statsSummary = 'warn:' . count($warningsList);
                    }
                  ?>
                  <tr>
                    <td><?php echo intval($job->id); ?></td>
                    <td><span class="badge bg-secondary"><?php echo htmlspecialchars($job->type ?? ''); ?></span></td>
                    <td><span class="badge bg-<?php echo ($job->status ?? '') === 'done' ? 'success' : (($job->status ?? '') === 'failed' ? 'danger' : (($job->status ?? '') === 'running' ? 'primary' : 'secondary')); ?>"><?php echo htmlspecialchars($job->status ?? ''); ?></span></td>
                    <td><small class="text-muted"><?php echo htmlspecialchars($job->started_at ?? '-'); ?></small></td>
                    <td><small class="text-muted"><?php echo htmlspecialchars($job->finished_at ?? '-'); ?></small></td>
                    <td><?php echo isset($job->duration_seconds) ? intval($job->duration_seconds) : '-'; ?></td>
                    <td>
                      <?php if ($statsSummary !== ''): ?>
                        <small class="text-muted"><?php echo htmlspecialchars($statsSummary); ?></small>
                      <?php elseif (!empty($job->last_error) && $job->last_error !== 'OK'): ?>
                        <small class="text-muted"><?php echo htmlspecialchars($job->last_error); ?></small>
                      <?php else: ?>
                        <span class="text-muted"><?php echo $__('common_none', '-'); ?></span>
                      <?php endif; ?>
                      <?php if (!empty($warningsList)): ?>
                        <details class="mt-1">
                          <summary class="text-danger small"><?php echo sprintf($__('queue_warning_label', '警告(%d)'), count($warningsList)); ?></summary>
                          <ul class="mb-0 small text-muted ps-3">
                            <?php foreach (array_slice($warningsList, 0, 10) as $warningText): ?>
                              <li><?php echo htmlspecialchars($warningText); ?></li>
                            <?php endforeach; ?>
                            <?php if (count($warningsList) > 10): ?><li>…</li><?php endif; ?>
                          </ul>
                        </details>
                      <?php endif; ?>
                      <?php if (!empty($job->last_error) && $job->last_error !== 'OK'): ?>
                        <div class="mt-1"><a class="btn btn-sm btn-outline-danger" href="?module=domain_hub&job_error_id=<?php echo intval($job->id); ?>"><?php echo $__('queue_view_error', '查看'); ?></a></div>
                      <?php endif; ?>
                    </td>
                    <td><small class="text-muted"><?php echo htmlspecialchars($job->created_at ?? ''); ?></small></td>
                    <td><small class="text-muted"><?php echo htmlspecialchars($job->updated_at ?? ''); ?></small></td>
                    <td>
                      <form method="post" class="d-inline">
                        <input type="hidden" name="action" value="job_retry">
                        <input type="hidden" name="job_id" value="<?php echo intval($job->id); ?>">
                        <button class="btn btn-sm btn-outline-primary" <?php echo ($job->status ?? '') === 'running' ? 'disabled' : ''; ?>><?php echo $__('queue_retry_button', '重试'); ?></button>
                      </form>
                      <form method="post" class="d-inline ms-1" onsubmit="return confirm('<?php echo addslashes($__('queue_cancel_confirm', '确定取消该作业？')); ?>');">
                        <input type="hidden" name="action" value="job_cancel">
                        <input type="hidden" name="job_id" value="<?php echo intval($job->id); ?>">
                        <button class="btn btn-sm btn-outline-secondary" <?php echo in_array($job->status ?? '', ['done','failed','cancelled'], true) ? 'disabled' : ''; ?>><?php echo $__('queue_cancel_button', '取消'); ?></button>
                      </form>
                    </td>
                  </tr>
                <?php endforeach; ?>
              <?php else: ?>
                <tr><td colspan="10" class="text-center text-muted"><?php echo $__('queue_empty', '暂无作业记录'); ?></td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
        <?php if ($jobsTotalPages > 1): ?>
          <nav aria-label="<?php echo $__('queue_pagination_aria', '作业队列分页'); ?>" class="mt-2">
            <ul class="pagination pagination-sm justify-content-center">
              <?php if ($jobsPage > 1): ?><li class="page-item"><a class="page-link" href="<?php echo $buildPageQuery('jobs_page', $jobsPage - 1); ?>#queue-summary"><?php echo $__('common_prev', '上一页'); ?></a></li><?php endif; ?>
              <?php for ($i = 1; $i <= $jobsTotalPages; $i++): ?>
                <?php if ($i === $jobsPage): ?>
                  <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                <?php elseif ($i === 1 || $i === $jobsTotalPages || abs($i - $jobsPage) <= 2): ?>
                  <li class="page-item"><a class="page-link" href="<?php echo $buildPageQuery('jobs_page', $i); ?>#queue-summary"><?php echo $i; ?></a></li>
                <?php elseif (abs($i - $jobsPage) === 3): ?>
                  <li class="page-item disabled"><span class="page-link">...</span></li>
                <?php endif; ?>
              <?php endfor; ?>
              <?php if ($jobsPage < $jobsTotalPages): ?><li class="page-item"><a class="page-link" href="<?php echo $buildPageQuery('jobs_page', $jobsPage + 1); ?>#queue-summary"><?php echo $__('common_next', '下一页'); ?></a></li><?php endif; ?>
            </ul>
            <div class="text-center text-muted small"><?php echo sprintf($__('pagination_summary', '第 %1$d / %2$d 页（共 %3$d 条）'), $jobsPage, $jobsTotalPages, $jobsTotal); ?></div>
          </nav>
        <?php endif; ?>
        <?php if ($jobError): ?>
          <div class="alert alert-danger mt-3"><i class="fas fa-exclamation-triangle"></i> <?php echo $__('queue_error_detail', '错误详情：'); ?><?php echo htmlspecialchars($jobError); ?></div>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <div class="col-md-6" id="reconcile-diff">
    <div class="card mb-4">
      <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-balance-scale"></i> <?php echo $__('queue_diff_title', '本地-云端对账'); ?></h5>
        <form method="post" class="mb-2">
          <input type="hidden" name="action" value="enqueue_reconcile">
          <input type="hidden" name="mode" value="dry">
          <button class="btn btn-outline-primary"><?php echo $__('queue_diff_dry', '对账预演（dry-run）'); ?></button>
        </form>
        <form method="post" class="mb-3">
          <input type="hidden" name="action" value="enqueue_reconcile">
          <input type="hidden" name="mode" value="fix">
          <button class="btn btn-primary"><?php echo $__('queue_diff_fix', '对账并修复（fix）'); ?></button>
        </form>
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead><tr><th><?php echo $__('queue_diff_header_job', '作业ID'); ?></th><th><?php echo $__('queue_diff_header_subdomain', '子域ID'); ?></th><th><?php echo $__('queue_diff_header_kind', '类别'); ?></th><th><?php echo $__('queue_diff_header_action', '动作'); ?></th><th><?php echo $__('queue_diff_header_time', '时间'); ?></th></tr></thead>
            <tbody>
              <?php if (!empty($recentDiffs)): ?>
                <?php foreach ($recentDiffs as $diff): ?>
                  <tr>
                    <td><?php echo intval($diff->job_id ?? $diff->id ?? 0); ?></td>
                    <td><?php echo intval($diff->subdomain_id ?? 0); ?></td>
                    <td><?php echo htmlspecialchars($diff->kind ?? '-'); ?></td>
                    <td><?php echo htmlspecialchars($diff->action ?? '-'); ?></td>
                    <td><small class="text-muted"><?php echo htmlspecialchars($diff->created_at ?? ''); ?></small></td>
                  </tr>
                <?php endforeach; ?>
              <?php else: ?>
                <tr><td colspan="5" class="text-center text-muted"><?php echo $__('queue_diff_empty', '暂无差异记录'); ?></td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
        <?php if ($diffTotalPages > 1): ?>
          <nav aria-label="<?php echo $__('queue_diff_pagination_aria', '对账差异分页'); ?>" class="mt-2">
            <ul class="pagination pagination-sm justify-content-center">
              <?php if ($diffPage > 1): ?><li class="page-item"><a class="page-link" href="<?php echo $buildPageQuery('diff_page', $diffPage - 1); ?>#reconcile-diff"><?php echo $__('common_prev', '上一页'); ?></a></li><?php endif; ?>
              <?php for ($i = 1; $i <= $diffTotalPages; $i++): ?>
                <?php if ($i === $diffPage): ?>
                  <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                <?php elseif ($i === 1 || $i === $diffTotalPages || abs($i - $diffPage) <= 2): ?>
                  <li class="page-item"><a class="page-link" href="<?php echo $buildPageQuery('diff_page', $i); ?>#reconcile-diff"><?php echo $i; ?></a></li>
                <?php elseif (abs($i - $diffPage) === 3): ?>
                  <li class="page-item disabled"><span class="page-link">...</span></li>
                <?php endif; ?>
              <?php endfor; ?>
              <?php if ($diffPage < $diffTotalPages): ?><li class="page-item"><a class="page-link" href="<?php echo $buildPageQuery('diff_page', $diffPage + 1); ?>#reconcile-diff"><?php echo $__('common_next', '下一页'); ?></a></li><?php endif; ?>
            </ul>
            <div class="text-center text-muted small"><?php echo sprintf($__('pagination_summary', '第 %1$d / %2$d 页（共 %3$d 条）'), $diffPage, $diffTotalPages, $diffTotal); ?></div>
          </nav>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>

<div class="card mb-4" id="calibration-tools">
  <div class="card-body">
    <div class="row mb-3 g-3">
      <div class="col-md-3">
        <div class="border rounded p-3 h-100">
          <div class="small text-muted"><?php echo $__('queue_cal_last', '最近一次校准'); ?></div>
          <div class="mt-1"><?php echo $__('queue_cal_time', '时间：'); ?><?php echo htmlspecialchars($lastCalTime); ?></div>
          <div class="small text-muted mt-1"><?php echo $__('queue_cal_status', '状态：'); ?><span class="badge bg-<?php echo ($lastCalStatus==='done'?'success':($lastCalStatus==='failed'?'danger':($lastCalStatus==='running'?'info':'secondary'))); ?> ms-1"><?php echo htmlspecialchars($lastCalStatus); ?></span></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="border rounded p-3 h-100">
          <div class="small text-muted"><?php echo $__('queue_cal_backlog', '队列积压'); ?></div>
          <div class="mt-1"><span class="badge bg-<?php echo ($backlogCount>0?'warning':'success'); ?>"><?php echo intval($backlogCount); ?></span></div>
          <div class="small text-muted mt-1"><?php echo $__('queue_cal_pending_label', 'pending + running'); ?></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="border rounded p-3 h-100">
          <div class="small text-muted"><?php echo $__('queue_cal_error_rate', '近期错误率（20作业）'); ?></div>
          <div class="mt-1"><?php echo htmlspecialchars($jobErrorRate); ?></div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="border rounded p-3 h-100">
          <div class="small text-muted"><?php echo $__('queue_cal_summary', '校准结果摘要'); ?></div>
          <div class="mt-1">
            <?php if (!empty($calibrationByKind)): ?>
              <?php foreach ($calibrationByKind as $kindRow): ?>
                <span class="badge bg-secondary me-1"><?php echo htmlspecialchars($kindRow['k'] ?? ''); ?>：<?php echo intval($kindRow['c'] ?? 0); ?></span>
              <?php endforeach; ?>
            <?php else: ?>
              <span class="text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></span>
            <?php endif; ?>
          </div>
          <div class="small text-muted mt-2"><?php echo $__('queue_cal_by_action', '按动作：'); ?></div>
          <div class="mt-1">
            <?php if (!empty($calibrationByAction)): ?>
              <?php foreach ($calibrationByAction as $actionRow): ?>
                <span class="badge bg-light text-dark me-1"><?php echo htmlspecialchars($actionRow['a'] ?? ''); ?>：<?php echo intval($actionRow['c'] ?? 0); ?></span>
              <?php endforeach; ?>
            <?php else: ?>
              <span class="text-muted">—</span>
            <?php endif; ?>
          </div>
        </div>
      </div>
    </div>
    <div class="row g-3 align-items-end">
      <div class="col-md-6">
        <form method="post" class="row g-2">
          <input type="hidden" name="action" value="enqueue_calibration">
          <div class="col-6">
            <label class="form-label"><?php echo $__('queue_cal_mode', '模式'); ?></label>
            <select name="mode" class="form-select">
              <option value="dry"><?php echo $__('queue_cal_mode_dry', '干跑（仅比对显示差异）'); ?></option>
              <option value="fix"><?php echo $__('queue_cal_mode_fix', '自动修复（按差异执行）'); ?></option>
            </select>
          </div>
          <div class="col-6 d-flex align-items-end">
            <button type="submit" class="btn btn-primary w-100"><?php echo $__('queue_cal_submit', '提交校准作业'); ?></button>
          </div>
        </form>
      </div>
      <div class="col-md-6">
        <form method="post" class="row g-2">
          <input type="hidden" name="action" value="enqueue_root_calibration">
          <div class="col-6">
            <label class="form-label"><?php echo $__('queue_cal_root_domain', '根域名'); ?></label>
            <select name="rootdomain" class="form-select" <?php echo $hasRootdomainOptions ? '' : 'disabled'; ?> <?php echo $hasRootdomainOptions ? 'required' : ''; ?>>
              <?php if ($hasRootdomainOptions): ?>
                <option value=""><?php echo $__('queue_cal_root_placeholder', '请选择根域名'); ?></option>
                <?php foreach ($rootdomainOptions as $option): ?>
                  <option value="<?php echo htmlspecialchars($option['value'] ?? ''); ?>"><?php echo htmlspecialchars($option['label'] ?? ''); ?></option>
                <?php endforeach; ?>
              <?php else: ?>
                <option value="" selected><?php echo $__('queue_cal_root_empty', '暂无根域名可选'); ?></option>
              <?php endif; ?>
            </select>
          </div>
          <div class="col-3">
            <label class="form-label"><?php echo $__('queue_cal_mode', '模式'); ?></label>
            <select name="mode" class="form-select" <?php echo $hasRootdomainOptions ? '' : 'disabled'; ?>>
              <option value="dry"><?php echo $__('queue_cal_mode_dry', '干跑（仅比对显示差异）'); ?></option>
              <option value="fix"><?php echo $__('queue_cal_mode_fix', '自动修复（按差异执行）'); ?></option>
            </select>
          </div>
          <div class="col-3 d-flex align-items-end">
            <button type="submit" class="btn btn-outline-primary w-100" <?php echo $hasRootdomainOptions ? '' : 'disabled'; ?>><?php echo $__('queue_cal_root_submit', '提交指定根域校准'); ?></button>
          </div>
          <div class="col-12">
            <small class="text-muted"><?php echo $hasRootdomainOptions ? $__('queue_cal_root_help', '仅校准所选根域名下的子域。') : $__('queue_cal_root_empty', '暂无根域名可选'); ?></small>
          </div>
        </form>
      </div>
      <div class="col-md-3">
        <form method="post">
          <input type="hidden" name="action" value="run_queue_once">
          <button type="submit" class="btn btn-outline-secondary w-100"><?php echo $__('queue_run_once', '立即执行队列一次'); ?></button>
        </form>
      </div>
      <div class="col-md-3">
        <form method="post">
          <input type="hidden" name="action" value="run_migrations">
          <button type="submit" class="btn btn-outline-secondary w-100"><?php echo $__('queue_run_migrations', '手动迁移/修复表'); ?></button>
        </form>
      </div>
    </div>
  </div>
</div>
