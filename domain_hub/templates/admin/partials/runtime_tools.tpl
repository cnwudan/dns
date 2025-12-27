<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$runtimeView = $runtimeView ?? ($cfAdminViewModel['runtime'] ?? []);
$module_settings = $module_settings ?? [];

$title = $lang['runtime_card_title'] ?? '运行控制';
$pauseLabel = $lang['runtime_pause_free'] ?? '暂停免费域名注册';
$nsLabel = $lang['runtime_disable_ns'] ?? '禁止设置 DNS 服务器（NS 管理）';
$maintenanceLabel = $lang['runtime_maintenance'] ?? '页面维护模式（禁止前台操作）';
$dnsWriteLabel = $lang['runtime_disable_dns_write'] ?? '禁止新增/修改 DNS 解析（仅允许删除）';
$inviteFeatureLabel = $lang['runtime_hide_invite'] ?? '隐藏“邀请好友解锁注册额度”';
$clientDeleteLabel = $lang['runtime_client_delete'] ?? '启用前台自助删除域名';
$syncInviteLabel = $lang['runtime_sync_invite'] ?? '当全局上限变大时同步提升未定制用户上限';
$clientPageSizeLabel = $lang['runtime_client_page_size'] ?? '前端每页子域名数量';
$cleanupIntervalLabel = $lang['runtime_cleanup_interval'] ?? '过期域名清理间隔（小时）';
$cleanupIntervalHint = $lang['runtime_cleanup_interval_hint'] ?? '最小1小时，最大168小时，设置越小清理越频繁。';
$maintenanceMsgLabel = $lang['runtime_maintenance_message'] ?? '维护说明（展示给前台用户）';
$saveLabel = $lang['runtime_save_button'] ?? '保存设置';
$infoNote = $lang['runtime_quick_toggle_hint'] ?? '快速停止/开启根域名的注册已移动至本卡片下方的独立区域，避免与“保存设置”表单冲突。';
$quickToggleLabel = $lang['runtime_quick_toggle_label'] ?? '在此快速停止/开启某个根域名的注册';
$quickLimitLabel = $lang['runtime_quick_limit_label'] ?? '快速设置单个用户注册上限（0 = 不限制）';
$applyLabel = $lang['runtime_apply_button'] ?? '应用';
$perUserLabel = $lang['runtime_per_user_label'] ?? '个/用户';
$saveLimitLabel = $lang['runtime_save_limit_button'] ?? '保存';
$cleanupTitle = $lang['runtime_cleanup_title'] ?? '根域名本地清理（不影响云端）';
$cleanupIntro = $lang['runtime_cleanup_intro'] ?? '该操作会删除指定根域名下的所有本地子域名及关联数据，并自动归还用户配额，不会调用阿里云 API，云端解析保持不变。';
$cleanupSelectLabel = $lang['runtime_cleanup_select'] ?? '选择已有根域名';
$cleanupTarget = $lang['runtime_cleanup_target'] ?? '目标根域名';
$cleanupConfirm = $lang['runtime_cleanup_confirm'] ?? '确认根域名';
$cleanupBatch = $lang['runtime_cleanup_batch'] ?? '每批处理数量';
$cleanupHint = $lang['runtime_cleanup_hint'] ?? '本地清理不会删除阿里云中的任何记录，如需同步清理云端请在任务完成后手动处理。';
$cleanupButton = $lang['runtime_cleanup_button'] ?? '开始本地清理';
$runNowLabel = $lang['runtime_cleanup_run_now'] ?? '提交后立即尝试执行一次队列';
$selectPlaceholder = $lang['runtime_select_placeholder'] ?? '请选择一个根域名';
$maintenanceTextareaPlaceholder = $lang['runtime_maintenance_placeholder'] ?? '例如：系统维护中，预计北京时间 02:00-03:00 完成。感谢理解。';

$rootRows = $runtimeView['rootdomains'] ?? [];
$cfmodQuickRootOptions = [];
foreach ($rootRows as $r) {
    $optionLabel = htmlspecialchars($r->domain ?? '') . ' (' . htmlspecialchars($r->status ?? '') . ')';
    $cfmodQuickRootOptions[] = '<option value="id-' . intval($r->id ?? 0) . '">' . $optionLabel . '</option>';
}
$cfmodQuickRootOptionsHtml = implode("\n", $cfmodQuickRootOptions);

$maintenanceMessage = $module_settings['maintenance_message'] ?? '';
$clientPageSizeSetting = $module_settings['client_page_size'] ?? 20;
$cleanupIntervalSetting = intval($module_settings['domain_cleanup_interval_hours'] ?? 24);
if ($cleanupIntervalSetting < 1) { $cleanupIntervalSetting = 24; }
if ($cleanupIntervalSetting > 168) { $cleanupIntervalSetting = 168; }
$rateLimitSettings = [
    'rate_limit_register_per_hour' => intval($module_settings['rate_limit_register_per_hour'] ?? 30),
    'rate_limit_dns_per_hour' => intval($module_settings['rate_limit_dns_per_hour'] ?? 120),
    'rate_limit_api_key_per_hour' => intval($module_settings['rate_limit_api_key_per_hour'] ?? 20),
    'rate_limit_quota_gift_per_hour' => intval($module_settings['rate_limit_quota_gift_per_hour'] ?? 20),
    'rate_limit_ajax_per_hour' => intval($module_settings['rate_limit_ajax_per_hour'] ?? 60),
    'rate_limit_dns_unlock_per_hour' => intval($module_settings['rate_limit_dns_unlock_per_hour'] ?? 10),
];
$riskBatchLabel = $lang['runtime_risk_batch_label'] ?? '风险扫描批量大小';
$riskBatchHint = $lang['runtime_risk_batch_hint'] ?? '每次风险扫描处理的子域数量（10-1000）';
$riskBatchValue = intval($module_settings['risk_scan_batch_size'] ?? 50);

$dnsUnlockLabel = $lang['dns_unlock_label'] ?? '启用 DNS 解锁';
$dnsUnlockHint = $lang['dns_unlock_hint'] ?? '用户需要输入解锁码后才允许设置 NS 服务器。';
$dnsUnlockEnabled = in_array($module_settings['enable_dns_unlock'] ?? '0', ['1','on'], true);
$dnsUnlockShareLabel = $lang['dns_unlock_share_label'] ?? '允许分享解锁码';
$dnsUnlockShareHint = $lang['dns_unlock_share_hint'] ?? '关闭后仅保留付费解锁入口，用户界面将隐藏解锁码输入区域。';
$dnsUnlockShareEnabledSetting = in_array($module_settings['dns_unlock_share_enabled'] ?? '1', ['1','on'], true);
$dnsUnlockPurchaseLabel = $lang['dns_unlock_purchase_label'] ?? '启用余额付费解锁';
$dnsUnlockPurchaseHint = $lang['dns_unlock_purchase_hint'] ?? '允许用户通过账户余额购买解锁权限';
$dnsUnlockPurchasePriceLabel = $lang['dns_unlock_purchase_price_label'] ?? '解锁费用（账户币种）';
$dnsUnlockPurchaseEnabledSetting = in_array($module_settings['dns_unlock_purchase_enabled'] ?? '0', ['1','on'], true);
$dnsUnlockPurchasePriceSetting = (float) ($module_settings['dns_unlock_purchase_price'] ?? 0);

$orphanTitle = $lang['runtime_orphan_title'] ?? '孤儿记录扫描与清理';
$orphanIntro = $lang['runtime_orphan_intro'] ?? '扫描本地存在但云端已删除的解析记录，可选择只统计或直接删除。';
$orphanRootLabel = $lang['runtime_orphan_root'] ?? '筛选根域名（可选）';
$orphanLimitLabel = $lang['runtime_orphan_limit'] ?? '扫描子域数量';
$orphanModeLabel = $lang['runtime_orphan_mode'] ?? '执行模式';
$orphanModeDry = $lang['runtime_orphan_mode_dry'] ?? '干跑（仅统计，不删除）';
$orphanModeDelete = $lang['runtime_orphan_mode_delete'] ?? '删除孤儿记录';
$orphanHint = $lang['runtime_orphan_hint'] ?? '提示：操作会实时调用 DNS API，请根据供应商限额合理设置数量。';
$orphanButton = $lang['runtime_orphan_button'] ?? '开始扫描';
$orphanCursorLabel = $lang['runtime_orphan_cursor_label'] ?? '游标策略';
$orphanCursorResume = $lang['runtime_orphan_cursor_resume'] ?? '从上次游标继续';
$orphanCursorReset = $lang['runtime_orphan_cursor_reset'] ?? '从头开始';
$orphanCursorCurrentFmt = $lang['runtime_orphan_cursor_current'] ?? '当前默认游标：%s';
$orphanCursorListFmt = $lang['runtime_orphan_cursor_list'] ?? '各根域游标：%s';

$orphanSummary = $runtimeView['orphanCursors'] ?? ['default' => 0, 'list' => []];
$orphanCursorDefaultValue = intval($orphanSummary['default'] ?? 0);
$orphanCursorList = $orphanSummary['list'] ?? [];
$orphanCursorListText = '';
if (!empty($orphanCursorList)) {
    $pairs = [];
    foreach (array_slice($orphanCursorList, 0, 5) as $entry) {
        $pairs[] = ($entry['rootdomain'] ?? '') . ':' . ($entry['cursor'] ?? 0);
    }
    if (count($orphanCursorList) > 5) {
        $pairs[] = '...';
    }
    $orphanCursorListText = sprintf($orphanCursorListFmt, implode('，', $pairs));
}

$orphanRootOptions = [];
foreach ($rootRows as $rootRow) {
    $domainValue = strtolower(trim((string)($rootRow->domain ?? '')));
    if ($domainValue === '') { continue; }
    $orphanRootOptions[] = '<option value="' . htmlspecialchars($domainValue) . '">' . htmlspecialchars($rootRow->domain ?? '') . '</option>';
}
$cfmodOrphanRootOptionsHtml = implode("\n", $orphanRootOptions);
?>

<div class="card mb-4" id="runtime-control">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-toggle-on"></i> <?php echo htmlspecialchars($title); ?></h5>
    <form method="post" class="row g-3 align-items-center">
      <input type="hidden" name="action" value="save_runtime_switches">
      <div class="col-12 col-md-4">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="pause_free_registration" name="pause_free_registration" value="1" <?php echo (isset($module_settings['pause_free_registration']) && in_array($module_settings['pause_free_registration'], ['1','on'], true)) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="pause_free_registration"><?php echo htmlspecialchars($pauseLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="disable_ns_management" name="disable_ns_management" value="1" <?php echo (isset($module_settings['disable_ns_management']) && in_array($module_settings['disable_ns_management'], ['1','on'], true)) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="disable_ns_management"><?php echo htmlspecialchars($nsLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="maintenance_mode" name="maintenance_mode" value="1" <?php echo (isset($module_settings['maintenance_mode']) && in_array($module_settings['maintenance_mode'], ['1','on'], true)) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="maintenance_mode"><?php echo htmlspecialchars($maintenanceLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="disable_dns_write" name="disable_dns_write" value="1" <?php echo (isset($module_settings['disable_dns_write']) && in_array($module_settings['disable_dns_write'], ['1','on'], true)) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="disable_dns_write"><?php echo htmlspecialchars($dnsWriteLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="hide_invite_feature" name="hide_invite_feature" value="1" <?php echo (isset($module_settings['hide_invite_feature']) && in_array($module_settings['hide_invite_feature'], ['1','on'], true)) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="hide_invite_feature"><?php echo htmlspecialchars($inviteFeatureLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="enable_client_domain_delete" name="enable_client_domain_delete" value="1" <?php echo (isset($module_settings['enable_client_domain_delete']) && in_array($module_settings['enable_client_domain_delete'], ['1','on'], true)) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="enable_client_domain_delete"><?php echo htmlspecialchars($clientDeleteLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="sync_invite_limit_up_only" name="sync_invite_limit_up_only" value="1" <?php echo (isset($module_settings['sync_invite_limit_up_only']) && in_array($module_settings['sync_invite_limit_up_only'], ['1','on'], true)) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="sync_invite_limit_up_only"><?php echo htmlspecialchars($syncInviteLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="client_page_size"><?php echo htmlspecialchars($clientPageSizeLabel); ?></label>
        <div class="input-group">
          <input type="number" class="form-control" id="client_page_size" name="client_page_size" min="1" max="20" value="<?php echo htmlspecialchars($clientPageSizeSetting); ?>">
          <span class="input-group-text">条/页</span>
        </div>
        <small class="text-muted">可设置 1-20 条，超过部分自动限制为 20</small>
      </div>
      <div class="col-12">
        <hr>
        <h6 class="text-muted mb-2"><i class="fas fa-tachometer-alt"></i> 请求级限速（单个用户 / 每小时，0 表示不限制）</h6>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="rate_limit_register_per_hour">域名注册</label>
        <input type="number" class="form-control" id="rate_limit_register_per_hour" name="rate_limit_register_per_hour" min="0" value="<?php echo htmlspecialchars($rateLimitSettings['rate_limit_register_per_hour']); ?>">
        <small class="text-muted">限制注册/赠送入口</small>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="rate_limit_dns_per_hour">DNS 写操作</label>
        <input type="number" class="form-control" id="rate_limit_dns_per_hour" name="rate_limit_dns_per_hour" min="0" value="<?php echo htmlspecialchars($rateLimitSettings['rate_limit_dns_per_hour']); ?>">
        <small class="text-muted">新增/修改/删除解析</small>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="rate_limit_api_key_per_hour">API 密钥操作</label>
        <input type="number" class="form-control" id="rate_limit_api_key_per_hour" name="rate_limit_api_key_per_hour" min="0" value="<?php echo htmlspecialchars($rateLimitSettings['rate_limit_api_key_per_hour']); ?>">
        <small class="text-muted">创建/重置/删除</small>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="rate_limit_quota_gift_per_hour">兑换 &amp; 转赠</label>
        <input type="number" class="form-control" id="rate_limit_quota_gift_per_hour" name="rate_limit_quota_gift_per_hour" min="0" value="<?php echo htmlspecialchars($rateLimitSettings['rate_limit_quota_gift_per_hour']); ?>">
        <small class="text-muted">配额兑换 / 域名礼物</small>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="rate_limit_ajax_per_hour">敏感 AJAX</label>
        <input type="number" class="form-control" id="rate_limit_ajax_per_hour" name="rate_limit_ajax_per_hour" min="0" value="<?php echo htmlspecialchars($rateLimitSettings['rate_limit_ajax_per_hour']); ?>">
        <small class="text-muted">客户端异步写操作</small>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="rate_limit_dns_unlock_per_hour">DNS 解锁</label>
        <input type="number" class="form-control" id="rate_limit_dns_unlock_per_hour" name="rate_limit_dns_unlock_per_hour" min="0" value="<?php echo htmlspecialchars($rateLimitSettings['rate_limit_dns_unlock_per_hour']); ?>">
        <small class="text-muted">限制解锁码 / 余额解锁请求</small>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="risk_scan_batch_size"><?php echo htmlspecialchars($riskBatchLabel); ?></label>
        <div class="input-group">
          <input type="number" class="form-control" id="risk_scan_batch_size" name="risk_scan_batch_size" min="10" max="1000" value="<?php echo htmlspecialchars($riskBatchValue); ?>">
          <span class="input-group-text">子域/批</span>
        </div>
        <small class="text-muted"><?php echo htmlspecialchars($riskBatchHint); ?></small>
      </div>
      <div class="col-12 col-md-4 col-xl-3">
        <label class="form-label" for="domain_cleanup_interval_hours"><?php echo htmlspecialchars($cleanupIntervalLabel); ?></label>
        <div class="input-group">
          <input type="number" class="form-control" id="domain_cleanup_interval_hours" name="domain_cleanup_interval_hours" min="1" max="168" value="<?php echo htmlspecialchars($cleanupIntervalSetting); ?>">
          <span class="input-group-text">h</span>
        </div>
        <small class="text-muted"><?php echo htmlspecialchars($cleanupIntervalHint); ?></small>
      </div>
      <div class="col-12">
        <div class="alert alert-primary mb-2">
          <i class="fas fa-info-circle"></i> <?php echo htmlspecialchars($infoNote); ?>
        </div>
      </div>
      <div class="col-12">
        <label class="form-label" for="maintenance_message"><?php echo htmlspecialchars($maintenanceMsgLabel); ?></label>
        <textarea class="form-control" id="maintenance_message" name="maintenance_message" rows="3" placeholder="<?php echo htmlspecialchars($maintenanceTextareaPlaceholder); ?>"><?php echo htmlspecialchars($maintenanceMessage); ?></textarea>
        <small class="text-muted">当开启维护模式时，将在用户界面显示此说明。</small>
      </div>
      <div class="col-12">
        <hr>
      </div>
      <div class="col-12 col-lg-4">
        <div class="form-check form-switch mb-2">
          <input class="form-check-input" type="checkbox" id="enable_dns_unlock" name="enable_dns_unlock" value="1" <?php echo $dnsUnlockEnabled ? 'checked' : ''; ?>>
          <label class="form-check-label" for="enable_dns_unlock"><?php echo htmlspecialchars($dnsUnlockLabel); ?></label>
        </div>
        <small class="text-muted d-block mb-2"><?php echo htmlspecialchars($dnsUnlockHint); ?></small>
      </div>
      <div class="col-12 col-lg-4">
        <div class="form-check form-switch mb-2">
          <input class="form-check-input" type="checkbox" id="dns_unlock_share_enabled" name="dns_unlock_share_enabled" value="1" <?php echo !empty($dnsUnlockShareEnabledSetting) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="dns_unlock_share_enabled"><?php echo htmlspecialchars($dnsUnlockShareLabel); ?></label>
        </div>
        <small class="text-muted d-block mb-2"><?php echo htmlspecialchars($dnsUnlockShareHint); ?></small>
      </div>
      <div class="col-12 col-lg-4">
        <div class="form-check form-switch mb-2">
          <input class="form-check-input" type="checkbox" id="dns_unlock_purchase_enabled" name="dns_unlock_purchase_enabled" value="1" <?php echo !empty($dnsUnlockPurchaseEnabledSetting) ? 'checked' : ''; ?>>
          <label class="form-check-label" for="dns_unlock_purchase_enabled"><?php echo htmlspecialchars($dnsUnlockPurchaseLabel); ?></label>
        </div>
        <small class="text-muted d-block mb-2"><?php echo htmlspecialchars($dnsUnlockPurchaseHint); ?></small>
      </div>
      <div class="col-12 col-lg-4 col-xl-3">
        <label class="form-label" for="dns_unlock_purchase_price"><?php echo htmlspecialchars($dnsUnlockPurchasePriceLabel); ?></label>
        <div class="input-group">
          <input type="number" class="form-control" id="dns_unlock_purchase_price" name="dns_unlock_purchase_price" min="0" step="0.01" value="<?php echo htmlspecialchars(number_format($dnsUnlockPurchasePriceSetting, 2, '.', '')); ?>">
        </div>
      </div>
      <div class="col-12">
        <button type="submit" class="btn btn-primary mt-2"><?php echo htmlspecialchars($saveLabel); ?></button>
      </div>
    </form>
    <hr>
    <div class="row g-2 align-items-end">
      <div class="col-12 col-md-4">
        <label class="form-label"><?php echo htmlspecialchars($quickToggleLabel); ?></label>
        <form method="post" class="d-flex gap-2">
          <input type="hidden" name="action" value="set_rootdomain_status">
          <select name="rootdomain_id" class="form-select">
            <?php echo $cfmodQuickRootOptionsHtml; ?>
          </select>
          <select name="new_status" class="form-select">
            <option value="active">开启注册</option>
            <option value="suspended">停止注册</option>
          </select>
          <button type="submit" class="btn btn-outline-primary"><?php echo htmlspecialchars($applyLabel); ?></button>
        </form>
      </div>
      <div class="col-12 col-md-5 col-xl-6">
        <label class="form-label"><?php echo htmlspecialchars($quickLimitLabel); ?></label>
        <form method="post" class="d-flex flex-wrap gap-2">
          <input type="hidden" name="action" value="set_rootdomain_limit">
          <select name="rootdomain_id" class="form-select">
            <?php echo $cfmodQuickRootOptionsHtml; ?>
          </select>
          <div class="input-group" style="max-width: 220px;">
            <input type="number" name="per_user_limit" class="form-control" min="0" value="0">
            <span class="input-group-text"><?php echo htmlspecialchars($perUserLabel); ?></span>
          </div>
          <button type="submit" class="btn btn-outline-secondary"><?php echo htmlspecialchars($saveLimitLabel); ?></button>
        </form>
        <small class="text-muted d-block mt-1">设置为 0 表示不限；仅影响新增注册，已拥有的域名不会被回收。</small>
      </div>
    </div>
  </div>
</div>

<div class="card mb-4 border-warning">
  <div class="card-body">
    <h5 class="card-title mb-3 text-warning"><i class="fas fa-eraser"></i> <?php echo htmlspecialchars($cleanupTitle); ?></h5>
    <div class="alert alert-warning small mb-3">
      <i class="fas fa-info-circle"></i> <?php echo htmlspecialchars($cleanupIntro); ?>
    </div>
    <form method="post" class="row g-3" onsubmit="return confirm('确认仅删除本地数据并归还额度？该操作不可撤销。');">
      <input type="hidden" name="action" value="purge_rootdomain_local">
      <div class="col-12 col-md-4">
        <label class="form-label" for="cf-purge-root-select"><?php echo htmlspecialchars($cleanupSelectLabel); ?></label>
        <select class="form-select" id="cf-purge-root-select">
          <option value=""><?php echo htmlspecialchars($selectPlaceholder); ?></option>
          <?php
            $purgeOptions = [];
            foreach ($rootRows as $rootRow) {
                $value = strtolower($rootRow->domain ?? '');
                if ($value === '') { continue; }
                $purgeOptions[] = '<option value="' . htmlspecialchars($value) . '">' . htmlspecialchars($rootRow->domain ?? '') . ' (' . htmlspecialchars($rootRow->status ?? '') . ')</option>';
            }
            echo implode("\n", $purgeOptions);
          ?>
        </select>
        <small class="text-muted">选择后将自动填入下方输入框。</small>
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label" for="cf-purge-root-input"><?php echo htmlspecialchars($cleanupTarget); ?></label>
        <input type="text" class="form-control" name="target_rootdomain" id="cf-purge-root-input" placeholder="例如 a.com" required>
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label"><?php echo htmlspecialchars($cleanupConfirm); ?></label>
        <input type="text" class="form-control" name="confirm_rootdomain" placeholder="再次输入以确认" required>
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label"><?php echo htmlspecialchars($cleanupBatch); ?></label>
        <input type="number" class="form-control" name="batch_size" min="20" max="500" value="200">
        <small class="text-muted">建议 20-500，值越大单次处理的记录越多。</small>
      </div>
      <div class="col-12 col-md-4 d-flex align-items-center">
        <div class="form-check form-switch mt-4">
          <input class="form-check-input" type="checkbox" name="run_now" value="1" id="cf-purge-run-now" checked>
          <label class="form-check-label" for="cf-purge-run-now"><?php echo htmlspecialchars($runNowLabel); ?></label>
        </div>
      </div>
      <div class="col-12">
        <small class="text-muted"><?php echo htmlspecialchars($cleanupHint); ?></small>
      </div>
      <div class="col-12">
        <button type="submit" class="btn btn-danger"><i class="fas fa-trash-alt me-1"></i> <?php echo htmlspecialchars($cleanupButton); ?></button>
      </div>
    </form>
  </div>
</div>


<div class="card mb-4 border-info">
  <div class="card-body">
    <h5 class="card-title mb-3 text-info"><i class="fas fa-search"></i> <?php echo htmlspecialchars($orphanTitle); ?></h5>
    <div class="alert alert-info small mb-3">
      <i class="fas fa-info-circle"></i> <?php echo htmlspecialchars($orphanIntro); ?>
    </div>
    <form method="post" class="row g-3 align-items-end">
      <input type="hidden" name="action" value="scan_orphan_records">
      <div class="col-12 col-md-4">
        <label class="form-label" for="cf-orphan-root-select"><?php echo htmlspecialchars($orphanRootLabel); ?></label>
        <select class="form-select" id="cf-orphan-root-select" name="orphan_rootdomain">
          <option value=""><?php echo htmlspecialchars($selectPlaceholder); ?></option>
          <?php echo $cfmodOrphanRootOptionsHtml; ?>
        </select>
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label" for="cf-orphan-limit"><?php echo htmlspecialchars($orphanLimitLabel); ?></label>
        <input type="number" class="form-control" id="cf-orphan-limit" name="orphan_subdomain_limit" min="10" max="500" value="100">
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label" for="cf-orphan-cursor-mode"><?php echo htmlspecialchars($orphanCursorLabel); ?></label>
        <select class="form-select" id="cf-orphan-cursor-mode" name="orphan_cursor_mode">
          <option value="resume"><?php echo htmlspecialchars($orphanCursorResume); ?></option>
          <option value="reset"><?php echo htmlspecialchars($orphanCursorReset); ?></option>
        </select>
        <small class="text-muted d-block mt-1">
          <?php echo htmlspecialchars(sprintf($orphanCursorCurrentFmt, (int) $orphanCursorDefaultValue)); ?>
          <?php if ($orphanCursorListText !== '') { echo '<br>' . htmlspecialchars($orphanCursorListText); } ?>
        </small>
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label" for="cf-orphan-mode"><?php echo htmlspecialchars($orphanModeLabel); ?></label>
        <select class="form-select" id="cf-orphan-mode" name="orphan_mode">
          <option value="dry"><?php echo htmlspecialchars($orphanModeDry); ?></option>
          <option value="delete"><?php echo htmlspecialchars($orphanModeDelete); ?></option>
        </select>
      </div>
      <div class="col-12">
        <small class="text-muted"><?php echo htmlspecialchars($orphanHint); ?></small>
      </div>
      <div class="col-12">
        <button type="submit" class="btn btn-info text-white"><i class="fas fa-broom me-1"></i> <?php echo htmlspecialchars($orphanButton); ?></button>
      </div>
    </form>
  </div>
</div>


