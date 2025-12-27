<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$moduleSlugAttr = $moduleSlugAttr ?? 'domain_hub';
$moduleSlugAttr = htmlspecialchars($moduleSlugAttr, ENT_QUOTES, 'UTF-8');
$domainGiftsView = $domainGiftsView ?? ($cfAdminViewModel['domainGifts'] ?? []);

$giftStatusOptions = $domainGiftsView['statusOptions'] ?? [
    '' => '全部状态',
    'pending' => '进行中',
    'accepted' => '已完成',
    'cancelled' => '已取消',
    'expired' => '已过期',
];
$giftFilters = $domainGiftsView['filters'] ?? [];
$giftStatusFilter = $giftFilters['status'] ?? '';
$giftSearchTerm = $giftFilters['search'] ?? '';
$giftPagination = $domainGiftsView['pagination'] ?? [];
$giftPage = $giftPagination['page'] ?? 1;
$giftPerPage = $giftPagination['perPage'] ?? 30;
$giftTotal = $giftPagination['total'] ?? 0;
$giftTotalPages = $giftPagination['totalPages'] ?? 1;
$giftRows = $domainGiftsView['rows'] ?? [];
$giftUserMap = $domainGiftsView['users'] ?? [];

$title = $lang['domain_gift_title'] ?? '域名转赠记录';
$filterStatusLabel = $lang['domain_gift_filter_status'] ?? '状态筛选';
$searchLabel = $lang['domain_gift_filter_search'] ?? '搜索域名 / 用户ID / 转赠码';
$filterSubmitLabel = $lang['filter_submit_label'] ?? '筛选';
$filterResetLabel = $lang['filter_reset_label'] ?? '重置';
$emptyText = $lang['domain_gift_empty'] ?? '暂无转赠记录';
$cancelLabel = $lang['domain_gift_cancel'] ?? '取消';
$unlockLabel = $lang['domain_gift_unlock'] ?? '恢复锁';
$recordsSummary = $lang['domain_gift_summary'] ?? '共 %d 条记录，每页最多 30 条';

$giftBaseParams = ['module' => $moduleSlugAttr];
if ($giftStatusFilter !== '') { $giftBaseParams['gift_status'] = $giftStatusFilter; }
if ($giftSearchTerm !== '') { $giftBaseParams['gift_search'] = $giftSearchTerm; }
$buildGiftUrl = function(array $extra = []) use ($giftBaseParams) {
    return '?' . http_build_query(array_merge($giftBaseParams, $extra)) . '#domainGiftRecords';
};
$renderGiftUser = function($uid) use ($giftUserMap) {
    $uid = intval($uid);
    if ($uid <= 0) {
        return '<span class="text-muted">-</span>';
    }
    $label = 'ID: ' . $uid;
    if (isset($giftUserMap[$uid])) {
        $user = $giftUserMap[$uid];
        $parts = [];
        $name = trim(($user->firstname ?? '') . ' ' . ($user->lastname ?? ''));
        if ($name !== '') {
            $parts[] = htmlspecialchars($name, ENT_QUOTES);
        }
        if (!empty($user->email)) {
            $parts[] = htmlspecialchars($user->email, ENT_QUOTES);
        }
        if (!empty($parts)) {
            $label .= '<br><small class="text-muted">' . implode(' / ', $parts) . '</small>';
        }
    }
    return $label;
};
?>

<div class="card mb-4" id="domainGiftRecords">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-random"></i> <?php echo htmlspecialchars($title); ?></h5>
    <form method="get" class="row g-2 align-items-end mb-3" action="">
      <input type="hidden" name="module" value="<?php echo $moduleSlugAttr; ?>">
      <div class="col-md-3">
        <label class="form-label"><?php echo htmlspecialchars($filterStatusLabel); ?></label>
        <select name="gift_status" class="form-select">
          <?php foreach ($giftStatusOptions as $value => $labelText): ?>
            <option value="<?php echo htmlspecialchars($value); ?>" <?php echo $value === $giftStatusFilter ? 'selected' : ''; ?>><?php echo htmlspecialchars($labelText); ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-5">
        <label class="form-label"><?php echo htmlspecialchars($searchLabel); ?></label>
        <input type="text" name="gift_search" class="form-control" value="<?php echo htmlspecialchars($giftSearchTerm); ?>" placeholder="<?php echo htmlspecialchars($searchLabel); ?>">
      </div>
      <div class="col-md-4 d-flex gap-2">
        <button type="submit" class="btn btn-outline-primary flex-fill"><?php echo htmlspecialchars($filterSubmitLabel); ?></button>
        <?php if ($giftStatusFilter !== '' || $giftSearchTerm !== ''): ?>
          <a class="btn btn-outline-secondary flex-fill" href="?module=<?php echo $moduleSlugAttr; ?>#domainGiftRecords"><?php echo htmlspecialchars($filterResetLabel); ?></a>
        <?php endif; ?>
      </div>
    </form>
    <div class="table-responsive">
      <table class="table table-sm table-striped align-middle">
        <thead>
          <tr>
            <th style="width: 18%">域名</th>
            <th style="width: 14%">转赠码</th>
            <th style="width: 18%">赠送方</th>
            <th style="width: 18%">接收方</th>
            <th style="width: 10%">状态</th>
            <th style="width: 12%">发起时间</th>
            <th style="width: 12%">完成 / 结束时间</th>
            <th style="width: 8%" class="text-end">操作</th>
          </tr>
        </thead>
        <tbody>
          <?php if (!empty($giftRows)): ?>
            <?php
              $statusBadges = [
                'pending' => ['label' => '进行中', 'class' => 'warning'],
                'accepted' => ['label' => '已完成', 'class' => 'success'],
                'cancelled' => ['label' => '已取消', 'class' => 'secondary'],
                'expired' => ['label' => '已过期', 'class' => 'danger'],
              ];
            ?>
            <?php foreach ($giftRows as $gift): $giftId = intval($gift->id ?? 0); ?>
            <tr>
              <td>
                <code><?php echo htmlspecialchars($gift->full_domain ?? '-'); ?></code>
                <?php if (!empty($gift->subdomain_id)): ?>
                  <div class="text-muted small">Sub ID: <?php echo intval($gift->subdomain_id); ?></div>
                <?php endif; ?>
              </td>
              <td>
                <span class="badge bg-light text-dark"><?php echo htmlspecialchars($gift->code ?? '-'); ?></span>
                <?php if (!empty($gift->expires_at)): ?>
                  <div class="text-muted small">有效至 <?php echo htmlspecialchars($gift->expires_at); ?></div>
                <?php endif; ?>
              </td>
              <td><?php echo $renderGiftUser($gift->from_userid ?? 0); ?></td>
              <td><?php echo $renderGiftUser($gift->to_userid ?? 0); ?></td>
              <td>
                <?php $meta = $statusBadges[$gift->status] ?? ['label' => $gift->status, 'class' => 'secondary']; ?>
                <span class="badge bg-<?php echo $meta['class']; ?>"><?php echo htmlspecialchars($meta['label']); ?></span>
                <?php if (!empty($gift->cancelled_by_admin)): ?>
                  <span class="badge bg-dark">管理员</span>
                <?php endif; ?>
              </td>
              <td><small class="text-muted"><?php echo htmlspecialchars($gift->created_at ?? '-'); ?></small></td>
              <td>
                <?php
                  $finishText = '-';
                  if ($gift->status === 'accepted') {
                      $finishText = $gift->completed_at ?: '-';
                  } elseif ($gift->status === 'cancelled') {
                      $finishText = $gift->cancelled_at ?: '-';
                  } elseif ($gift->status === 'expired') {
                      $finishText = $gift->cancelled_at ?: ($gift->expires_at ?? '-');
                  }
                ?>
                <small class="text-muted"><?php echo htmlspecialchars($finishText); ?></small>
              </td>
              <td class="text-end">
                <?php $hasLock = intval($gift->subdomain_gift_lock_id ?? 0) === $giftId && intval($gift->subdomain_id ?? 0) > 0; ?>
                <?php if (($gift->status ?? '') === 'pending'): ?>
                  <form method="post" class="d-inline" onsubmit="return confirm('确认取消该转赠并解除锁定吗？');">
                    <input type="hidden" name="action" value="admin_cancel_domain_gift">
                    <input type="hidden" name="gift_id" value="<?php echo $giftId; ?>">
                    <button type="submit" class="btn btn-sm btn-outline-danger"><?php echo htmlspecialchars($cancelLabel); ?></button>
                  </form>
                <?php endif; ?>
                <?php if ($hasLock && ($gift->status ?? '') !== 'pending'): ?>
                  <form method="post" class="d-inline ms-1" onsubmit="return confirm('确认恢复该域名的锁定状态（解除锁定）吗？');">
                    <input type="hidden" name="action" value="admin_unlock_domain_gift_lock">
                    <input type="hidden" name="gift_id" value="<?php echo $giftId; ?>">
                    <input type="hidden" name="subdomain_id" value="<?php echo intval($gift->subdomain_id ?? 0); ?>">
                    <button type="submit" class="btn btn-sm btn-outline-secondary"><?php echo htmlspecialchars($unlockLabel); ?></button>
                  </form>
                <?php endif; ?>
                <?php if (($gift->status ?? '') !== 'pending' && !$hasLock): ?>
                  <span class="text-muted">-</span>
                <?php endif; ?>
              </td>
            </tr>
            <?php endforeach; ?>
          <?php else: ?>
            <tr><td colspan="8" class="text-center text-muted"><?php echo htmlspecialchars($emptyText); ?></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
    <div class="d-flex justify-content-between align-items-center mt-2">
      <div class="text-muted small"><?php echo sprintf($recordsSummary, intval($giftTotal)); ?></div>
      <?php if ($giftTotalPages > 1): ?>
        <nav>
          <ul class="pagination pagination-sm mb-0">
            <?php if ($giftPage > 1): ?>
              <li class="page-item"><a class="page-link" href="<?php echo $buildGiftUrl(['gift_page' => $giftPage - 1]); ?>">&laquo;</a></li>
            <?php endif; ?>
            <?php for ($i = 1; $i <= $giftTotalPages; $i++): ?>
              <?php if ($i === $giftPage || abs($i - $giftPage) <= 2 || $i === 1 || $i === $giftTotalPages): ?>
                <?php if ($i === $giftPage): ?>
                  <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                <?php else: ?>
                  <li class="page-item"><a class="page-link" href="<?php echo $buildGiftUrl(['gift_page' => $i]); ?>"><?php echo $i; ?></a></li>
                <?php endif; ?>
              <?php elseif (abs($i - $giftPage) === 3): ?>
                <li class="page-item disabled"><span class="page-link">...</span></li>
              <?php endif; ?>
            <?php endfor; ?>
            <?php if ($giftPage < $giftTotalPages): ?>
              <li class="page-item"><a class="page-link" href="<?php echo $buildGiftUrl(['gift_page' => $giftPage + 1]); ?>">&raquo;</a></li>
            <?php endif; ?>
          </ul>
        </nav>
      <?php endif; ?>
    </div>
  </div>
</div>
