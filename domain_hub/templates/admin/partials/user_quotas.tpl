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
$moduleSlugAttr = $moduleSlugAttr ?? 'domain_hub';
$quotasView = $cfAdminViewModel['quotas'] ?? [];
$quotaListView = $quotasView['list'] ?? [];
$userQuotas = $quotaListView['items'] ?? [];
$quotaPage = $quotaListView['page'] ?? 1;
$quotaPerPage = $quotaListView['perPage'] ?? 20;
$quotaTotal = $quotaListView['total'] ?? (is_countable($userQuotas) ? count($userQuotas) : 0);
$quotaTotalPages = $quotaListView['totalPages'] ?? 1;
$quotaSearchView = $quotasView['search'] ?? [];
$quotaSearch = $quotaSearchView['keyword'] ?? '';
$quotaSearchResult = $quotaSearchView['result'] ?? null;
$quotaSearchError = $quotaSearchView['error'] ?? '';
$quotaPrefill = $quotasView['prefill'] ?? [];
$quotaPrefillEmail = $quotaPrefill['email'] ?? '';
$quotaPrefillUserId = $quotaPrefill['userId'] ?? 0;
$quotaPrefillMax = $quotaPrefill['max'] ?? '';
$quotaPrefillInviteLimit = $quotaPrefill['inviteLimit'] ?? '';
$quotaPrefillUsed = array_key_exists('used', $quotaPrefill) ? $quotaPrefill['used'] : null;

$buildQuotaPageUrl = static function (int $page) {
    $params = $_GET ?? [];
    $params['module'] = 'domain_hub';
    $params['quota_page'] = $page;
    return '?' . http_build_query($params) . '#quotas';
};
?>

<div class="card" id="quotas">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-user-cog"></i> <?php echo $__('quotas_card_title', '用户配额管理'); ?></h5>
    <form method="get" class="row g-2 align-items-end mb-3" action="">
      <input type="hidden" name="module" value="<?php echo htmlspecialchars($moduleSlugAttr); ?>">
      <div class="col-md-6">
        <label class="form-label"><?php echo $__('quotas_search_label', '按邮箱或用户ID搜索'); ?></label>
        <input type="text" name="quota_search" class="form-control" placeholder="<?php echo $__('quotas_search_placeholder', 'email@example.com 或 123'); ?>" value="<?php echo htmlspecialchars($quotaSearch); ?>">
      </div>
      <div class="col-md-3 d-flex align-items-end gap-2">
        <button type="submit" class="btn btn-outline-primary w-100"><?php echo $__('common_search', '搜索'); ?></button>
        <?php if ($quotaSearch !== ''): ?>
          <a class="btn btn-outline-secondary w-100" href="?module=<?php echo htmlspecialchars($moduleSlugAttr); ?>#quotas"><?php echo $__('common_clear', '清除'); ?></a>
        <?php endif; ?>
      </div>
    </form>

    <?php if ($quotaSearchResult): ?>
      <?php $quotaUser = $quotaSearchResult['user']; $quotaData = $quotaSearchResult['quota']; ?>
      <div class="alert alert-info">
        <div class="row g-2 align-items-center">
          <div class="col-md-6">
            <strong><?php echo $__('quotas_alert_user_label', '用户：'); ?></strong><?php echo htmlspecialchars(trim((($quotaUser->firstname ?? '') . ' ' . ($quotaUser->lastname ?? ''))) ?: '-'); ?>
            <span class="badge bg-secondary ms-2"><?php echo $__('common_id_label', 'ID: '); ?><?php echo intval($quotaUser->id); ?></span>
          </div>
          <div class="col-md-6">
            <strong><?php echo $__('quotas_alert_email_label', '邮箱：'); ?></strong><?php echo htmlspecialchars($quotaUser->email ?? '-'); ?>
          </div>
          <div class="col-md-4">
            <strong><?php echo $__('quotas_alert_base_quota', '基础配额：'); ?></strong><?php echo intval($quotaData->max_count ?? 0); ?>
          </div>
          <div class="col-md-4">
            <strong><?php echo $__('quotas_alert_used', '已使用：'); ?></strong><?php echo $quotaPrefillUsed !== null ? intval($quotaPrefillUsed) : 0; ?>
          </div>
          <div class="col-md-4">
            <strong><?php echo $__('quotas_alert_invite', '邀请上限：'); ?></strong><?php echo intval($quotaData->invite_bonus_limit ?? 0); ?>
          </div>
        </div>
      </div>
    <?php elseif ($quotaSearchError !== ''): ?>
      <div class="alert alert-warning mb-3"><?php echo htmlspecialchars($quotaSearchError); ?></div>
    <?php endif; ?>

    <form method="post" class="mb-3" onsubmit="return validateInviteLimit(this)">
      <input type="hidden" name="action" value="update_user_invite_limit">
      <?php if ($quotaPrefillUserId): ?>
        <input type="hidden" name="user_id" value="<?php echo intval($quotaPrefillUserId); ?>">
      <?php endif; ?>
      <div class="row g-2">
        <div class="col-md-5">
          <input type="email" name="user_email" class="form-control" placeholder="<?php echo $__('quotas_invite_form_email', '用户邮箱（覆盖邀请上限）'); ?>" value="<?php echo htmlspecialchars($quotaPrefillEmail); ?>">
        </div>
        <div class="col-md-3">
          <input type="number" name="new_invite_limit" class="form-control" placeholder="<?php echo $__('quotas_invite_form_limit', '邀请上限'); ?>" min="0" step="1" value="<?php echo $quotaPrefillInviteLimit !== '' ? htmlspecialchars($quotaPrefillInviteLimit) : ''; ?>">
          <small class="text-muted"><?php echo $__('quotas_number_hint', '最大99999999999'); ?></small>
        </div>
        <div class="col-md-4">
          <button type="submit" class="btn btn-outline-primary">&nbsp;<?php echo $__('quotas_invite_form_button', '更新邀请上限'); ?>&nbsp;</button>
        </div>
      </div>
    </form>

    <form method="post" class="mb-3" onsubmit="return validateQuotaUpdate(this)">
      <input type="hidden" name="action" value="update_user_quota">
      <?php if ($quotaPrefillUserId): ?>
        <input type="hidden" name="user_id" value="<?php echo intval($quotaPrefillUserId); ?>">
      <?php endif; ?>
      <div class="row g-2">
        <div class="col-md-5">
          <input type="email" name="user_email" class="form-control" placeholder="<?php echo $__('quotas_quota_form_email', '用户邮箱'); ?>" value="<?php echo htmlspecialchars($quotaPrefillEmail); ?>">
        </div>
        <div class="col-md-3">
          <input type="number" name="new_quota" class="form-control" placeholder="<?php echo $__('quotas_quota_form_value', '新配额数量'); ?>" min="0" step="1" value="<?php echo $quotaPrefillMax !== '' ? htmlspecialchars($quotaPrefillMax) : ''; ?>">
          <small class="text-muted"><?php echo $__('quotas_number_hint', '最大99999999999'); ?></small>
        </div>
        <div class="col-md-4">
          <button type="submit" class="btn btn-primary">&nbsp;<?php echo $__('quotas_quota_form_button', '更新配额'); ?>&nbsp;</button>
        </div>
      </div>
    </form>

    <div class="table-responsive">
      <table class="table table-sm">
        <thead>
          <tr>
            <th><?php echo $__('quotas_header_user', '用户'); ?></th>
            <th><?php echo $__('quotas_header_current', '当前配额'); ?></th>
            <th><?php echo $__('quotas_header_used', '已使用'); ?></th>
            <th><?php echo $__('quotas_header_status', '状态'); ?></th>
          </tr>
        </thead>
        <tbody>
          <?php if (!empty($userQuotas)): ?>
            <?php foreach ($userQuotas as $quota): ?>
              <tr>
                <td>
                  <small>
                    <?php echo htmlspecialchars(($quota->firstname ?? '') . ' ' . ($quota->lastname ?? '')); ?><br>
                    <span class="text-muted"><?php echo htmlspecialchars($quota->email ?? ''); ?></span>
                  </small>
                </td>
                <td><?php echo intval($quota->max_count ?? 0); ?></td>
                <td><?php echo intval($quota->used_count ?? 0); ?></td>
                <td>
                  <?php if (($quota->status ?? '') === 'Active'): ?>
                    <span class="badge bg-success"><?php echo $__('quotas_status_active', '正常'); ?></span>
                  <?php else: ?>
                    <span class="badge bg-danger"><?php echo $__('quotas_status_banned', '封禁'); ?></span>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          <?php else: ?>
            <tr><td colspan="4" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>

    <?php if ($quotaTotalPages > 1): ?>
      <nav aria-label="<?php echo $__('quotas_pagination_aria', '用户配额分页'); ?>" class="mt-2">
        <ul class="pagination pagination-sm justify-content-center">
          <?php if ($quotaPage > 1): ?>
            <li class="page-item"><a class="page-link" href="<?php echo $buildQuotaPageUrl($quotaPage - 1); ?>"><?php echo $__('common_prev', '上一页'); ?></a></li>
          <?php endif; ?>
          <?php for ($i = 1; $i <= $quotaTotalPages; $i++): ?>
            <?php if ($i === $quotaPage): ?>
              <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
            <?php elseif ($i === 1 || $i === $quotaTotalPages || abs($i - $quotaPage) <= 2): ?>
              <li class="page-item"><a class="page-link" href="<?php echo $buildQuotaPageUrl($i); ?>"><?php echo $i; ?></a></li>
            <?php elseif (abs($i - $quotaPage) === 3): ?>
              <li class="page-item disabled"><span class="page-link">...</span></li>
            <?php endif; ?>
          <?php endfor; ?>
          <?php if ($quotaPage < $quotaTotalPages): ?>
            <li class="page-item"><a class="page-link" href="<?php echo $buildQuotaPageUrl($quotaPage + 1); ?>"><?php echo $__('common_next', '下一页'); ?></a></li>
          <?php endif; ?>
        </ul>
        <div class="text-center text-muted small">
          <?php echo sprintf($__('pagination_summary', '第 %1$d / %2$d 页（共 %3$d 条）'), $quotaPage, $quotaTotalPages, $quotaTotal); ?>
        </div>
      </nav>
    <?php endif; ?>
  </div>
</div>
