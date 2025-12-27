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
$privilegedView = $cfAdminViewModel['privileged'] ?? [];
$privilegedKeyword = $privilegedView['keyword'] ?? '';
$privilegedUsers = $privilegedView['users'] ?? [];
$privilegedIds = $privilegedView['ids'] ?? [];
$privilegedSearchView = $privilegedView['search'] ?? [];
$privilegedSearchPerformed = $privilegedSearchView['performed'] ?? ($privilegedKeyword !== '');
$privilegedSearchResults = $privilegedSearchView['results'] ?? [];
$privilegedSearchCount = $privilegedSearchView['count'] ?? (is_countable($privilegedSearchResults) ? count($privilegedSearchResults) : 0);
$privilegedUserCount = $privilegedView['userCount'] ?? (is_countable($privilegedUsers) ? count($privilegedUsers) : 0);
$privilegedIdMap = [];
if (is_array($privilegedIds)) {
    foreach ($privilegedIds as $pid) {
        $privilegedIdMap[intval($pid)] = true;
    }
}
?>

<div class="card border-0 shadow-sm mb-4" id="privileged">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-star text-warning"></i> <?php echo $__('privileged_card_title', '特权用户管理'); ?></h5>
    <p class="text-muted small mb-3"><?php echo $__('privileged_card_intro', '特权用户将获得不限数量的域名注册额度，且其注册的域名默认设置为永久不过期。'); ?></p>
    <form method="get" class="row g-2 align-items-center mb-3">
      <input type="hidden" name="module" value="<?php echo htmlspecialchars($moduleSlugAttr); ?>">
      <div class="col-md-6 col-lg-4">
        <input type="text" name="privileged_keyword" class="form-control" placeholder="<?php echo $__('privileged_search_placeholder', '输入用户ID、邮箱或姓名关键字'); ?>" value="<?php echo htmlspecialchars($privilegedKeyword, ENT_QUOTES); ?>">
      </div>
      <div class="col-md-3 col-lg-2">
        <button type="submit" class="btn btn-primary w-100"><i class="fas fa-search"></i> <?php echo $__('common_search', '搜索'); ?></button>
      </div>
      <div class="col-md-3 col-lg-2">
        <a href="addonmodules.php?module=<?php echo htmlspecialchars($moduleSlugAttr); ?>&privileged_keyword=" class="btn btn-outline-secondary w-100"><?php echo $__('common_reset', '重置'); ?></a>
      </div>
    </form>

    <?php if ($privilegedSearchPerformed && $privilegedSearchCount === 0): ?>
      <div class="alert alert-warning py-2"><?php echo $__('privileged_search_empty', '未找到匹配的用户，请更换关键词重试。'); ?></div>
    <?php endif; ?>

    <?php if ($privilegedSearchCount > 0): ?>
      <div class="table-responsive mb-4">
        <table class="table table-sm table-hover align-middle">
          <thead class="table-light">
            <tr>
              <th style="width: 12%"><?php echo $__('common_user_id', '用户ID'); ?></th>
              <th style="width: 20%"><?php echo $__('common_name', '姓名'); ?></th>
              <th style="width: 28%"><?php echo $__('common_email', '邮箱'); ?></th>
              <th style="width: 20%"><?php echo $__('privileged_header_company', '公司'); ?></th>
              <th style="width: 20%" class="text-end"><?php echo $__('common_actions', '操作'); ?></th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($privilegedSearchResults as $row): $uid = intval($row->id ?? ($row['id'] ?? 0)); ?>
              <tr>
                <td><?php echo $uid; ?></td>
                <td><?php echo htmlspecialchars(trim((($row->firstname ?? $row['firstname'] ?? '') . ' ' . ($row->lastname ?? $row['lastname'] ?? ''))) ?: '-'); ?></td>
                <td><?php echo htmlspecialchars($row->email ?? $row['email'] ?? '-'); ?></td>
                <td><?php echo htmlspecialchars($row->companyname ?? $row['companyname'] ?? '-'); ?></td>
                <td class="text-end">
                  <?php if (isset($privilegedIdMap[$uid])): ?>
                    <span class="badge bg-success"><?php echo $__('privileged_badge_existing', '已特权'); ?></span>
                  <?php else: ?>
                    <form method="post" class="d-inline-flex align-items-center gap-2">
                      <input type="hidden" name="action" value="admin_add_privileged_user">
                      <input type="hidden" name="user_id" value="<?php echo $uid; ?>">
                      <input type="text" name="notes" class="form-control form-control-sm" placeholder="<?php echo $__('privileged_notes_placeholder', '备注 (可选)'); ?>" maxlength="255">
                      <button type="submit" class="btn btn-sm btn-outline-success"><i class="fas fa-plus"></i> <?php echo $__('privileged_add_button', '添加特权'); ?></button>
                    </form>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>

    <h6 class="fw-semibold"><?php echo $__('privileged_list_title', '已启用特权的用户'); ?></h6>
    <div class="table-responsive">
      <table class="table table-sm table-hover align-middle">
        <thead class="table-dark text-white">
          <tr>
            <th style="width: 10%"><?php echo $__('common_user_id', '用户ID'); ?></th>
            <th style="width: 20%"><?php echo $__('common_name', '姓名'); ?></th>
            <th style="width: 25%"><?php echo $__('common_email', '邮箱'); ?></th>
            <th style="width: 20%"><?php echo $__('privileged_header_notes', '备注'); ?></th>
            <th style="width: 15%"><?php echo $__('privileged_header_enabled_at', '启用时间'); ?></th>
            <th style="width: 10%" class="text-end"><?php echo $__('common_actions', '操作'); ?></th>
          </tr>
        </thead>
        <tbody>
          <?php if ($privilegedUserCount === 0): ?>
            <tr><td colspan="6" class="text-center text-muted"><?php echo $__('privileged_empty', '尚未设置任何特权用户。'); ?></td></tr>
          <?php else: ?>
            <?php foreach ($privilegedUsers as $privUser): $uid = intval($privUser->userid ?? ($privUser['userid'] ?? 0)); ?>
              <tr>
                <td><?php echo $uid; ?></td>
                <td><?php echo htmlspecialchars(trim((($privUser->firstname ?? $privUser['firstname'] ?? '') . ' ' . ($privUser->lastname ?? $privUser['lastname'] ?? ''))) ?: '-'); ?></td>
                <td><?php echo htmlspecialchars($privUser->email ?? $privUser['email'] ?? '-'); ?></td>
                <td><?php echo htmlspecialchars($privUser->notes ?? $privUser['notes'] ?? '-'); ?></td>
                <td><?php echo !empty($privUser->created_at ?? $privUser['created_at'] ?? '') ? htmlspecialchars(date('Y-m-d H:i', strtotime($privUser->created_at ?? $privUser['created_at']))) : '-'; ?></td>
                <td class="text-end">
                  <form method="post" onsubmit="return confirm('<?php echo addslashes($__('privileged_remove_confirm', '确认取消该用户的特权功能吗？')); ?>');">
                    <input type="hidden" name="action" value="admin_remove_privileged_user">
                    <input type="hidden" name="user_id" value="<?php echo $uid; ?>">
                    <button type="submit" class="btn btn-sm btn-outline-danger"><i class="fas fa-minus"></i> <?php echo $__('privileged_remove_button', '取消特权'); ?></button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
