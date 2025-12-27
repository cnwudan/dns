<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$dnsUnlockLogsView = $cfAdminViewModel['dnsUnlockLogs'] ?? [];
$dnsUnlockItems = $dnsUnlockLogsView['items'] ?? [];
$dnsUnlockSearch = $dnsUnlockLogsView['search'] ?? '';
$pagination = $dnsUnlockLogsView['pagination'] ?? [];
$dnsUnlockPage = max(1, (int) ($pagination['page'] ?? 1));
$dnsUnlockTotalPages = max(1, (int) ($pagination['totalPages'] ?? 1));
$dnsUnlockTotal = max(0, (int) ($pagination['total'] ?? 0));
$perPage = max(1, (int) ($pagination['perPage'] ?? 20));

$title = $lang['dns_unlock_logs_title'] ?? 'DNS 解锁使用记录';
$searchPlaceholder = $lang['dns_unlock_logs_search_placeholder'] ?? '邮箱或解锁码';
$searchButton = $lang['dns_unlock_logs_search_button'] ?? '搜索';
$resetButton = $lang['dns_unlock_logs_reset_button'] ?? '重置';
$codeLabel = $lang['dns_unlock_logs_code'] ?? '解锁码';
$ownerLabel = $lang['dns_unlock_logs_owner'] ?? '所属用户';
$usedUserLabel = $lang['dns_unlock_logs_used_user'] ?? '使用者';
$usedEmailLabel = $lang['dns_unlock_logs_used_email'] ?? '使用者邮箱';
$usedIpLabel = $lang['dns_unlock_logs_used_ip'] ?? '使用者 IP';
$usedTimeLabel = $lang['dns_unlock_logs_used_time'] ?? '使用时间';
$emptyLabel = $lang['dns_unlock_logs_empty'] ?? '暂无解锁使用记录';

$currentUrl = $_SERVER['REQUEST_URI'] ?? '';
$parsed = $currentUrl !== '' ? @parse_url($currentUrl) : false;
$basePath = ($parsed && !empty($parsed['path'])) ? $parsed['path'] : ($_SERVER['PHP_SELF'] ?? '');
$queryArgs = [];
if ($parsed && !empty($parsed['query'])) {
    parse_str($parsed['query'], $queryArgs);
}
$queryArgs['m'] = $_GET['m'] ?? 'domain_hub';
unset($queryArgs['dns_unlock_page']);
$buildUrl = function (array $params) use ($basePath) {
    $query = http_build_query($params);
    return $basePath . ($query === '' ? '' : '?' . $query);
};
$resetArgs = $queryArgs;
unset($resetArgs['dns_unlock_search']);
$resetUrl = $buildUrl($resetArgs) . '#dns-unlock-logs';
?>
<div class="card mb-4" id="dns-unlock-logs">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-unlock-alt"></i> <?php echo htmlspecialchars($title); ?></h5>
    <form method="get" class="row g-2 align-items-center mb-3">
      <input type="hidden" name="m" value="<?php echo htmlspecialchars($queryArgs['m'] ?? 'domain_hub'); ?>">
      <?php
      foreach ($queryArgs as $key => $val) {
          if (in_array($key, ['m', 'dns_unlock_search'], true)) { continue; }
          echo '<input type="hidden" name="' . htmlspecialchars($key, ENT_QUOTES) . '" value="' . htmlspecialchars(is_array($val) ? '' : (string) $val, ENT_QUOTES) . '">';
      }
      ?>
      <div class="col-sm-6 col-md-4">
        <input type="text" name="dns_unlock_search" class="form-control" placeholder="<?php echo htmlspecialchars($searchPlaceholder); ?>" value="<?php echo htmlspecialchars($dnsUnlockSearch); ?>">
      </div>
      <div class="col-auto">
        <button type="submit" class="btn btn-primary"><?php echo htmlspecialchars($searchButton); ?></button>
      </div>
      <div class="col-auto">
        <a href="<?php echo htmlspecialchars($resetUrl); ?>" class="btn btn-outline-secondary"><?php echo htmlspecialchars($resetButton); ?></a>
      </div>
    </form>
    <div class="table-responsive">
      <table class="table table-sm table-striped align-middle">
        <thead>
          <tr>
            <th><?php echo htmlspecialchars($codeLabel); ?></th>
            <th><?php echo htmlspecialchars($ownerLabel); ?></th>
            <th><?php echo htmlspecialchars($usedUserLabel); ?></th>
            <th><?php echo htmlspecialchars($usedEmailLabel); ?></th>
            <th><?php echo htmlspecialchars($usedIpLabel); ?></th>
            <th><?php echo htmlspecialchars($usedTimeLabel); ?></th>
          </tr>
        </thead>
        <tbody>
          <?php if (!empty($dnsUnlockItems)): ?>
            <?php foreach ($dnsUnlockItems as $item): ?>
              <tr>
                <td><code><?php echo htmlspecialchars($item['unlock_code'] ?? ''); ?></code></td>
                <td>
                  <?php if (!empty($item['owner_userid'])): ?>
                    <span class="text-muted">#<?php echo intval($item['owner_userid']); ?></span>
                  <?php endif; ?>
                  <?php if (!empty($item['owner_email'])): ?>
                    <div><?php echo htmlspecialchars($item['owner_email']); ?></div>
                  <?php endif; ?>
                </td>
                <td>
                  <?php if (!empty($item['used_userid'])): ?>
                    <span class="text-muted">#<?php echo intval($item['used_userid']); ?></span>
                  <?php else: ?>
                    <span class="text-muted">-</span>
                  <?php endif; ?>
                </td>
                <td><?php echo htmlspecialchars($item['used_email'] ?? '-'); ?></td>
                <td><?php echo htmlspecialchars($item['used_ip'] ?? '-'); ?></td>
                <td><small class="text-muted"><?php echo htmlspecialchars($item['used_at'] ?? '-'); ?></small></td>
              </tr>
            <?php endforeach; ?>
          <?php else: ?>
            <tr>
              <td colspan="6" class="text-center text-muted py-4"><?php echo htmlspecialchars($emptyLabel); ?></td>
            </tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
    <?php if ($dnsUnlockTotalPages > 1): ?>
      <?php
      $prevPage = max(1, $dnsUnlockPage - 1);
      $nextPage = min($dnsUnlockTotalPages, $dnsUnlockPage + 1);
      $baseArgs = $queryArgs;
      ?>
      <nav aria-label="DNS Unlock Logs Pagination" class="mt-3">
        <ul class="pagination pagination-sm">
          <?php $baseArgs['dns_unlock_page'] = $prevPage; ?>
          <li class="page-item <?php echo $dnsUnlockPage <= 1 ? 'disabled' : ''; ?>">
            <a class="page-link" href="<?php echo htmlspecialchars($buildUrl($baseArgs) . '#dns-unlock-logs'); ?>">&laquo;</a>
          </li>
          <?php for ($i = 1; $i <= $dnsUnlockTotalPages; $i++): ?>
            <?php $baseArgs['dns_unlock_page'] = $i; ?>
            <li class="page-item <?php echo $dnsUnlockPage === $i ? 'active' : ''; ?>">
              <a class="page-link" href="<?php echo htmlspecialchars($buildUrl($baseArgs) . '#dns-unlock-logs'); ?>"><?php echo $i; ?></a>
            </li>
          <?php endfor; ?>
          <?php $baseArgs['dns_unlock_page'] = $nextPage; ?>
          <li class="page-item <?php echo $dnsUnlockPage >= $dnsUnlockTotalPages ? 'disabled' : ''; ?>">
            <a class="page-link" href="<?php echo htmlspecialchars($buildUrl($baseArgs) . '#dns-unlock-logs'); ?>">&raquo;</a>
          </li>
        </ul>
      </nav>
    <?php endif; ?>
  </div>
</div>
