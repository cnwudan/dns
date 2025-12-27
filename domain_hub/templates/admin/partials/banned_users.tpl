<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$bansView = $bansView ?? ($cfAdminViewModel['bans'] ?? []);
$banned_users = $bansView['items'] ?? [];
$defaultIp = $module_settings['default_ip'] ?? '';

$title = $lang['ban_card_title'] ?? '用户封禁管理';
$banEmailLabel = $lang['ban_email_label'] ?? '用户邮箱或子域名';
$banReasonLabel = $lang['ban_reason_label'] ?? '封禁原因';
$banTypePermanent = $lang['ban_type_permanent'] ?? '永久封禁';
$banTypeTemporary = $lang['ban_type_temporary'] ?? '临时封禁（自定义天数）';
$banTypeWeekly = $lang['ban_type_weekly'] ?? '每周封禁（7天）';
$banDaysLabel = $lang['ban_days_label'] ?? '天数（临时封禁）';
$banCleanupRecords = $lang['ban_cleanup_records'] ?? '一键删除该用户的全部解析';
$banCleanupDomains = $lang['ban_cleanup_domains'] ?? '一键删除该用户注册的域名';
$banEnforceDns = $lang['ban_enforce_dns'] ?? '处置DNS（A改指定IP，其它删）';
$banIpLabel = $lang['ban_ip_label'] ?? 'IPv4';
$banSubmitLabel = $lang['ban_submit_label'] ?? '封禁用户';
$banListEmpty = $lang['ban_empty_label'] ?? '暂无封禁用户';
$unbanButton = $lang['ban_unban_button'] ?? '解封';
$extendLabel = $lang['ban_extend_button'] ?? '延长7天';
$enforceButton = $lang['ban_enforce_button'] ?? '处置DNS';
$prevLabel = $lang['common_prev'] ?? '上一页';
$nextLabel = $lang['common_next'] ?? '下一页';

$pagination = $bansView['pagination'] ?? [];
$banPage = max(1, (int) ($pagination['page'] ?? 1));
$banTotalPages = max(1, (int) ($pagination['totalPages'] ?? 1));
$banTotalCount = max(0, (int) ($pagination['total'] ?? 0));
$paginationSummaryTpl = $lang['pagination_summary'] ?? 'Page %1$d / %2$d (Total %3$d)';
$banPaginationAria = $lang['ban_pagination_aria'] ?? '封禁列表分页';

$banCurrentUrl = function_exists('cfmod_admin_current_url_without_action') ? cfmod_admin_current_url_without_action() : ($_SERVER['REQUEST_URI'] ?? '');
$banUrlParts = $banCurrentUrl !== '' ? @parse_url($banCurrentUrl) : false;
$banPath = ($banUrlParts && !empty($banUrlParts['path'])) ? $banUrlParts['path'] : ($_SERVER['PHP_SELF'] ?? '');
$banQueryArgs = [];
if ($banUrlParts && !empty($banUrlParts['query'])) {
  parse_str($banUrlParts['query'], $banQueryArgs);
}
unset($banQueryArgs['ban_page']);
$banQueryString = http_build_query($banQueryArgs);
if ($banPath === '') {
  $banPath = 'addonmodules.php';
}
$banPageUrlTemplate = $banPath;
if ($banQueryString !== '') {
  $banPageUrlTemplate .= '?' . $banQueryString . '&ban_page=%d#ban-management';
} else {
  $banPageUrlTemplate .= '?ban_page=%d#ban-management';
}
?>

<div class="col-md-6">
  <div class="card" id="ban-management">
    <div class="card-body">
      <h5 class="card-title mb-3"><i class="fas fa-user-slash"></i> <?php echo htmlspecialchars($title); ?></h5>
      <form method="post" class="mb-3">
        <input type="hidden" name="action" value="ban_user">
        <div class="row g-2">
          <div class="col-md-5">
            <input type="text" name="user_email" class="form-control" placeholder="<?php echo htmlspecialchars($banEmailLabel); ?>" required title="输入用户邮箱或子域名（如 test.example.com）">
          </div>
          <div class="col-md-4">
            <input type="text" name="ban_reason" class="form-control" placeholder="<?php echo htmlspecialchars($banReasonLabel); ?>" required>
          </div>
        </div>
        <div class="row g-2 mt-2">
          <div class="col-md-3">
            <select name="ban_type" class="form-select">
              <option value="permanent"><?php echo htmlspecialchars($banTypePermanent); ?></option>
              <option value="temporary"><?php echo htmlspecialchars($banTypeTemporary); ?></option>
              <option value="weekly"><?php echo htmlspecialchars($banTypeWeekly); ?></option>
            </select>
          </div>
          <div class="col-md-3">
            <input type="number" name="ban_days" class="form-control" placeholder="<?php echo htmlspecialchars($banDaysLabel); ?>" min="1">
          </div>
          <div class="col-md-3">
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="delete_user_records_on_ban" name="delete_user_records_on_ban" value="1">
              <label class="form-check-label" for="delete_user_records_on_ban"><?php echo htmlspecialchars($banCleanupRecords); ?></label>
            </div>
            <div class="form-check mt-1">
              <input class="form-check-input" type="checkbox" id="delete_user_domains_on_ban" name="delete_user_domains_on_ban" value="1">
              <label class="form-check-label" for="delete_user_domains_on_ban"><?php echo htmlspecialchars($banCleanupDomains); ?></label>
            </div>
          </div>
          <div class="col-md-3">
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="enforce_dns_now" name="enforce_dns_now" value="1">
              <label class="form-check-label" for="enforce_dns_now"><?php echo htmlspecialchars($banEnforceDns); ?></label>
            </div>
            <div class="input-group input-group-sm mt-1">
              <span class="input-group-text"><?php echo htmlspecialchars($banIpLabel); ?></span>
              <input type="text" name="enforce_dns_ip4" class="form-control" placeholder="<?php echo htmlspecialchars($banIpLabel); ?>" value="<?php echo htmlspecialchars($defaultIp); ?>">
            </div>
          </div>
        </div>
        <div class="row g-2 mt-2">
          <div class="col-md-3">
            <button type="submit" class="btn btn-danger w-100"><?php echo htmlspecialchars($banSubmitLabel); ?></button>
          </div>
        </div>
      </form>

      <div class="table-responsive">
        <table class="table table-sm table-striped align-middle">
          <thead>
            <tr>
              <th>用户</th>
              <th>封禁原因</th>
              <th>类型</th>
              <th>到期时间</th>
              <th>封禁时间</th>
              <th style="width: 200px">操作</th>
            </tr>
          </thead>
          <tbody>
            <?php if ($banned_users && count($banned_users) > 0): ?>
              <?php foreach ($banned_users as $banned): ?>
              <tr>
                <td>
                  <?php echo htmlspecialchars(($banned->firstname ?? '') . ' ' . ($banned->lastname ?? '')); ?><br>
                  <span class="text-muted"><?php echo htmlspecialchars($banned->email ?? ''); ?></span>
                </td>
                <td><?php echo htmlspecialchars($banned->ban_reason ?? ''); ?></td>
                <td><?php echo htmlspecialchars($banned->ban_type ?? 'permanent'); ?></td>
                <td><?php echo htmlspecialchars($banned->ban_expires_at ?? '-'); ?></td>
                <td><?php echo date('Y-m-d H:i', strtotime($banned->banned_at ?? 'now')); ?></td>
                <td>
                  <form method="post" class="d-inline">
                    <input type="hidden" name="action" value="unban_user">
                    <input type="hidden" name="userid" value="<?php echo intval($banned->userid); ?>">
                    <button type="submit" class="btn btn-sm btn-success"><?php echo htmlspecialchars($unbanButton); ?></button>
                  </form>
                  <?php if (($banned->ban_type ?? '') === 'temporary' || ($banned->ban_type ?? '') === 'weekly'): ?>
                  <form method="post" style="display: inline;" class="ms-1">
                    <input type="hidden" name="action" value="ban_user">
                    <input type="hidden" name="user_email" value="<?php echo htmlspecialchars($banned->email ?? ''); ?>">
                    <input type="hidden" name="ban_type" value="temporary">
                    <input type="hidden" name="ban_days" value="7">
                    <input type="hidden" name="ban_reason" value="续期封禁：7天">
                    <button type="submit" class="btn btn-sm btn-outline-danger"><?php echo htmlspecialchars($extendLabel); ?></button>
                  </form>
                  <?php endif; ?>
                  <form method="post" style="display: inline;" class="ms-1" onsubmit="return confirm('将把该封禁用户的所有免费域名解析A改为指定IPv4，其它记录将被删除。确认执行？');">
                    <input type="hidden" name="action" value="enforce_ban_dns">
                    <input type="hidden" name="userid" value="<?php echo intval($banned->userid); ?>">
                    <div class="input-group input-group-sm" style="width:260px; display:inline-flex; vertical-align:middle;">
                      <span class="input-group-text">A</span>
                      <input type="text" name="enforce_dns_ip4" class="form-control" placeholder="IPv4（留空用默认）" value="<?php echo htmlspecialchars($defaultIp); ?>">
                      <button class="btn btn-sm btn-warning" type="submit"><?php echo htmlspecialchars($enforceButton); ?></button>
                    </div>
                  </form>
                </td>
              </tr>
              <?php endforeach; ?>
            <?php else: ?>
              <tr>
                <td colspan="6" class="text-muted text-center"><?php echo htmlspecialchars($banListEmpty); ?></td>
              </tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
      <?php if ($banTotalPages > 1): ?>
      <div class="d-flex flex-column flex-md-row justify-content-between align-items-center mt-3">
        <small class="text-muted mb-2 mb-md-0">
          <?php echo htmlspecialchars(sprintf($paginationSummaryTpl, $banPage, $banTotalPages, $banTotalCount)); ?>
        </small>
        <nav aria-label="<?php echo htmlspecialchars($banPaginationAria); ?>">
          <ul class="pagination pagination-sm mb-0">
            <li class="page-item <?php echo $banPage <= 1 ? 'disabled' : ''; ?>">
              <?php if ($banPage <= 1): ?>
                <span class="page-link"><?php echo htmlspecialchars($prevLabel); ?></span>
              <?php else: ?>
                <a class="page-link" href="<?php echo htmlspecialchars(sprintf($banPageUrlTemplate, $banPage - 1)); ?>"><?php echo htmlspecialchars($prevLabel); ?></a>
              <?php endif; ?>
            </li>
            <li class="page-item <?php echo $banPage >= $banTotalPages ? 'disabled' : ''; ?>">
              <?php if ($banPage >= $banTotalPages): ?>
                <span class="page-link"><?php echo htmlspecialchars($nextLabel); ?></span>
              <?php else: ?>
                <a class="page-link" href="<?php echo htmlspecialchars(sprintf($banPageUrlTemplate, $banPage + 1)); ?>"><?php echo htmlspecialchars($nextLabel); ?></a>
              <?php endif; ?>
            </li>
          </ul>
        </nav>
      </div>
      <?php endif; ?>
      </div>
      </div>
      </div>
