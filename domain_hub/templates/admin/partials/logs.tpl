<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$__ = static function (string $key, string $fallback = '') use ($lang): string {
    return htmlspecialchars($lang[$key] ?? $fallback, ENT_QUOTES, 'UTF-8');
};
$logsView = $cfAdminViewModel['logs'] ?? [];
$logs = $logsView['entries'] ?? [];
$logsUserFilter = $logsView['userFilter'] ?? '';
$logsPagination = $logsView['pagination'] ?? [];
$logsPage = $logsPagination['page'] ?? 1;
$logsPerPage = $logsPagination['perPage'] ?? 20;
$logsTotal = $logsPagination['total'] ?? 0;
$logsTotalPages = $logsPagination['totalPages'] ?? 1;
?>

<div class="row">
  <div class="col-12">
    <div class="card mb-4" id="logs">
      <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-clipboard-list"></i> <?php echo $__('logs_title', '操作日志'); ?></h5>
        <form method="get" class="row g-2 mb-2">
          <input type="hidden" name="module" value="domain_hub">
          <div class="col-auto">
            <input type="text" name="logs_user" value="<?php echo htmlspecialchars($logsUserFilter ?? ''); ?>" class="form-control" placeholder="<?php echo $__('logs_filter_placeholder', '按用户筛选：邮箱或ID'); ?>">
          </div>
          <div class="col-auto">
            <button type="submit" class="btn btn-outline-primary btn-sm"><?php echo $__('common_filter', '筛选'); ?></button>
            <a href="?module=domain_hub" class="btn btn-outline-secondary btn-sm"><?php echo $__('common_reset', '重置'); ?></a>
          </div>
        </form>
        <div class="table-responsive">
          <table class="table table-sm">
            <thead>
              <tr>
                <th><?php echo $__('logs_header_id', 'ID'); ?></th>
                <th><?php echo $__('logs_header_time', '时间'); ?></th>
                <th><?php echo $__('logs_header_user', '用户ID'); ?></th>
                <th><?php echo $__('logs_header_subdomain', '子域ID'); ?></th>
                <th><?php echo $__('logs_header_action', '动作'); ?></th>
                <th><?php echo $__('logs_header_details', '详情'); ?></th>
                <th><?php echo $__('logs_header_ip', 'IP'); ?></th>
                <th><?php echo $__('logs_header_agent', '用户代理'); ?></th>
              </tr>
            </thead>
            <tbody>
              <?php if (!empty($logs)): ?>
                <?php foreach($logs as $log): ?>
                  <tr>
                    <td><?php echo intval($log->id); ?></td>
                    <td><?php echo date('Y-m-d H:i', strtotime($log->created_at ?? $log->updated_at)); ?></td>
                    <td><?php echo htmlspecialchars($log->userid ?? ''); ?></td>
                    <td><?php echo htmlspecialchars($log->subdomain_id ?? ''); ?></td>
                    <td><code><?php echo htmlspecialchars($log->action); ?></code></td>
                    <td><small class="text-muted">&lt;<?php echo htmlspecialchars($log->details ?? ''); ?>&gt;</small></td>
                    <td><?php echo htmlspecialchars($log->ip ?? ''); ?></td>
                    <td><small class="text-muted"><?php echo htmlspecialchars(substr($log->user_agent ?? '', 0, 50)); ?></small></td>
                  </tr>
                <?php endforeach; ?>
              <?php else: ?>
                <tr><td colspan="8" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
        <?php if ($logsTotalPages > 1): ?>
          <nav aria-label="<?php echo $__('logs_pagination_aria', '操作日志分页'); ?>" class="mt-2">
            <ul class="pagination pagination-sm justify-content-center">
              <?php if ($logsPage > 1): ?>
                <li class="page-item"><a class="page-link" href="?module=domain_hub&logs_page=<?php echo $logsPage-1; ?>&logs_user=<?php echo urlencode($logsUserFilter); ?>#logs"><?php echo $__('common_prev', '上一页'); ?></a></li>
              <?php endif; ?>
              <?php for($i=1;$i<=$logsTotalPages;$i++): ?>
                <?php if ($i == $logsPage): ?>
                  <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                <?php elseif ($i==1 || $i==$logsTotalPages || abs($i-$logsPage)<=2): ?>
                  <li class="page-item"><a class="page-link" href="?module=domain_hub&logs_page=<?php echo $i; ?>&logs_user=<?php echo urlencode($logsUserFilter); ?>#logs"><?php echo $i; ?></a></li>
                <?php elseif (abs($i-$logsPage)==3): ?>
                  <li class="page-item disabled"><span class="page-link">...</span></li>
                <?php endif; ?>
              <?php endfor; ?>
              <?php if ($logsPage < $logsTotalPages): ?>
                <li class="page-item"><a class="page-link" href="?module=domain_hub&logs_page=<?php echo $logsPage+1; ?>&logs_user=<?php echo urlencode($logsUserFilter); ?>#logs"><?php echo $__('common_next', '下一页'); ?></a></li>
              <?php endif; ?>
            </ul>
            <div class="text-center text-muted small"><?php echo sprintf($__('pagination_summary', '第 %1$d / %2$d 页（共 %3$d 条）'), $logsPage, $logsTotalPages, $logsTotal); ?></div>
          </nav>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>
