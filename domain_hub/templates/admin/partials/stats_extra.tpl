<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$__ = static function (string $key, string $fallback = '') use ($lang): string {
    return htmlspecialchars($lang[$key] ?? $fallback, ENT_QUOTES, 'UTF-8');
};
$statsView = $cfAdminViewModel['stats'] ?? [];
$registrationTrend = $statsView['registrationTrend'] ?? [];
$popularRootdomains = $statsView['popularRootdomains'] ?? [];
$dnsRecordTypes = $statsView['dnsRecordTypes'] ?? [];
$usagePatterns = $statsView['usagePatterns'] ?? [];

$getField = static function ($row, string $field, $default = '') {
    if (is_array($row)) {
        return $row[$field] ?? $default;
    }
    if (is_object($row)) {
        return $row->$field ?? $default;
    }
    return $default;
};
?>

<div class="row mb-4" id="stats-extra">
  <div class="col-md-6">
    <div class="card h-100">
      <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-chart-line"></i> <?php echo $__('stats_trend_title', '用户注册趋势（最近30天）'); ?></h5>
        <div class="table-responsive">
          <table class="table table-sm">
            <thead>
              <tr>
                <th><?php echo $__('stats_trend_date', '日期'); ?></th>
                <th><?php echo $__('stats_trend_count', '注册数量'); ?></th>
              </tr>
            </thead>
            <tbody>
              <?php if (!empty($registrationTrend)): ?>
                <?php foreach ($registrationTrend as $trend): ?>
                  <tr>
                    <td><?php echo htmlspecialchars($getField($trend, 'date')); ?></td>
                    <td><span class="badge bg-primary"><?php echo intval($getField($trend, 'count', 0)); ?></span></td>
                  </tr>
                <?php endforeach; ?>
              <?php else: ?>
                <tr><td colspan="2" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card h-100">
      <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-user-friends"></i> <?php echo $__('stats_usage_title', '用户使用模式'); ?></h5>
        <div class="table-responsive">
          <table class="table table-sm">
            <thead>
              <tr>
                <th><?php echo $__('stats_usage_level', '使用级别'); ?></th>
                <th><?php echo $__('stats_usage_users', '用户数'); ?></th>
              </tr>
            </thead>
            <tbody>
              <?php if (!empty($usagePatterns)): ?>
                <?php foreach ($usagePatterns as $row): ?>
                  <tr>
                    <td><?php echo htmlspecialchars($getField($row, 'usage_level')); ?></td>
                    <td><span class="badge bg-secondary"><?php echo intval($getField($row, 'user_count', 0)); ?></span></td>
                  </tr>
                <?php endforeach; ?>
              <?php else: ?>
                <tr><td colspan="2" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="row mb-4">
  <div class="col-md-6">
    <div class="card h-100">
      <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-globe"></i> <?php echo $__('stats_root_title', '热门根域名统计'); ?></h5>
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead>
              <tr>
                <th><?php echo $__('stats_root_domain', '根域名'); ?></th>
                <th><?php echo $__('stats_root_count', '子域数量'); ?></th>
              </tr>
            </thead>
            <tbody>
              <?php if (!empty($popularRootdomains)): ?>
                <?php foreach ($popularRootdomains as $row): ?>
                  <tr>
                    <td><?php echo htmlspecialchars($getField($row, 'rootdomain')); ?></td>
                    <td><span class="badge bg-info text-dark"><?php echo intval($getField($row, 'count', 0)); ?></span></td>
                  </tr>
                <?php endforeach; ?>
              <?php else: ?>
                <tr><td colspan="2" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card h-100">
      <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-stream"></i> <?php echo $__('stats_dns_title', 'DNS 记录类型分布'); ?></h5>
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead>
              <tr>
                <th><?php echo $__('stats_dns_type', '记录类型'); ?></th>
                <th><?php echo $__('stats_dns_count', '数量'); ?></th>
              </tr>
            </thead>
            <tbody>
              <?php if (!empty($dnsRecordTypes)): ?>
                <?php foreach ($dnsRecordTypes as $row): ?>
                  <tr>
                    <td><?php echo htmlspecialchars($getField($row, 'type')); ?></td>
                    <td><span class="badge bg-success"><?php echo intval($getField($row, 'count', 0)); ?></span></td>
                  </tr>
                <?php endforeach; ?>
              <?php else: ?>
                <tr><td colspan="2" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>
