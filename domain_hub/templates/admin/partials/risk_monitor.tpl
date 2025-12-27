<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$riskView = $cfAdminViewModel['risk'] ?? [];

$cardTitle = $lang['risk_monitor_title'] ?? '风险监控';
$scanButton = $lang['risk_scan_button'] ?? '一键扫描';
$runQueueButton = $lang['risk_run_queue_button'] ?? '立即运行队列';
$topTitle = $lang['risk_top_title'] ?? '高风险 Top10';
$trendTitle = $lang['risk_trend_title'] ?? '近7日命中趋势';
$allTitle = $lang['risk_all_title'] ?? '全部风险域名';
$searchPlaceholder = $lang['risk_search_placeholder'] ?? '子域包含...';
$filterAll = $lang['risk_filter_all'] ?? '全部等级';
$latestEventsTitle = $lang['risk_events_title'] ?? '最新事件';
$logButton = $lang['risk_view_log_button'] ?? '查看日志';
$freezeLabel = $lang['risk_freeze_button'] ?? '冻结';
$unfreezeLabel = $lang['risk_unfreeze_button'] ?? '解冻';
$noDataLabel = $lang['no_data_text'] ?? '暂无数据';
$noEventsLabel = $lang['risk_no_events'] ?? '暂无事件';
$logHeading = $lang['risk_log_heading'] ?? '探测日志 - 子域ID：%d';
$logBack = $lang['risk_log_back'] ?? '返回';

$riskTop = $riskView['top'] ?? [];
$riskTrend = $riskView['trend'] ?? [];
$riskEventsMeta = $riskView['events'] ?? [];
$riskEvents = $riskEventsMeta['items'] ?? [];
$riskEventsPage = (int) ($riskEventsMeta['page'] ?? 1);
$riskEventsPerPage = (int) ($riskEventsMeta['perPage'] ?? 20);
$riskEventsTotal = (int) ($riskEventsMeta['total'] ?? 0);
$riskEventsTotalPages = (int) ($riskEventsMeta['totalPages'] ?? 1);
$riskListMeta = $riskView['list'] ?? [];
$riskList = $riskListMeta['items'] ?? [];
$riskListPage = (int) ($riskListMeta['page'] ?? 1);
$riskListPerPage = (int) ($riskListMeta['perPage'] ?? 20);
$riskListTotal = (int) ($riskListMeta['total'] ?? 0);
$riskListTotalPages = (int) ($riskListMeta['totalPages'] ?? 1);
$riskFilters = $riskView['filters'] ?? [];
$levelFilter = $riskFilters['level'] ?? '';
$kwFilter = $riskFilters['keyword'] ?? '';
$riskLogMeta = $riskView['log'] ?? [];
$viewRiskLogId = intval($riskLogMeta['subdomainId'] ?? 0);
$riskLogEvents = $riskLogMeta['entries'] ?? [];
?>

<?php if ($viewRiskLogId > 0): ?>
<div class="alert alert-primary">
  <div class="d-flex justify-content-between align-items-center">
    <strong><?php echo sprintf($logHeading, $viewRiskLogId); ?></strong>
    <a href="?module=domain_hub" class="btn btn-sm btn-outline-secondary"><?php echo htmlspecialchars($logBack); ?></a>
  </div>
  <div class="table-responsive mt-2">
    <table class="table table-sm">
      <thead><tr><th>ID</th><th>时间</th><th>来源</th><th>分数</th><th>级别</th><th>原因</th><th>详情</th></tr></thead>
      <tbody>
        <?php if (!empty($riskLogEvents)): foreach ($riskLogEvents as $ev): ?>
        <tr>
          <td><?php echo intval($ev->id); ?></td>
          <td><small class="text-muted"><?php echo htmlspecialchars($ev->created_at ?? ''); ?></small></td>
          <td><?php echo htmlspecialchars($ev->source ?? ''); ?></td>
          <td><?php echo intval($ev->score ?? 0); ?></td>
          <td><?php echo htmlspecialchars($ev->level ?? ''); ?></td>
          <td><small><?php echo htmlspecialchars($ev->reason ?? ''); ?></small></td>
          <td><small class="text-muted"><?php echo htmlspecialchars($ev->details_json ?? ''); ?></small></td>
        </tr>
        <?php endforeach; else: ?>
        <tr><td colspan="7" class="text-center text-muted"><?php echo htmlspecialchars($noDataLabel); ?></td></tr>
        <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>
<?php endif; ?>

<div class="card mb-4" id="risk-monitor">
  <div class="card-body">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h5 class="card-title mb-0"><i class="fas fa-shield-alt"></i> <?php echo htmlspecialchars($cardTitle); ?></h5>
      <div class="d-flex align-items-center">
        <form method="post" class="ms-2">
          <input type="hidden" name="action" value="enqueue_risk_scan">
          <button class="btn btn-sm btn-primary" type="submit"><?php echo htmlspecialchars($scanButton); ?></button>
        </form>
        <form method="post" class="ms-2">
          <input type="hidden" name="action" value="run_queue_once">
          <button class="btn btn-sm btn-outline-secondary" type="submit"><?php echo htmlspecialchars($runQueueButton); ?></button>
        </form>
      </div>
    </div>
    <div class="row g-3">
      <div class="col-md-6">
        <div class="border rounded p-3 h-100">
          <div class="small text-muted"><?php echo htmlspecialchars($topTitle); ?></div>
          <div class="table-responsive mt-2">
            <table class="table table-sm">
              <thead><tr><th>子域</th><th>分数</th><th>等级</th><th>状态</th><th>操作</th><th>日志</th></tr></thead>
              <tbody>
                <?php if (!empty($riskTop)): foreach ($riskTop as $rt): ?>
                <tr>
                  <td><code><?php echo htmlspecialchars($rt->subdomain ?? ''); ?></code></td>
                  <td><span class="badge bg-danger"><?php echo intval($rt->risk_score); ?></span></td>
                  <td><?php echo htmlspecialchars($rt->risk_level ?? ''); ?></td>
                  <td><span class="badge bg-<?php echo (($rt->status ?? '')==='suspended'?'warning':'success'); ?>"><?php echo htmlspecialchars($rt->status ?? ''); ?></span></td>
                  <td>
                    <form method="post" class="d-inline">
                      <input type="hidden" name="action" value="toggle_subdomain_status">
                      <input type="hidden" name="id" value="<?php echo intval($rt->subdomain_id ?? 0); ?>">
                      <button class="btn btn-sm btn-outline-<?php echo (($rt->status ?? '')==='suspended'?'success':'danger'); ?>"><?php echo (($rt->status ?? '')==='suspended'?htmlspecialchars($unfreezeLabel):htmlspecialchars($freezeLabel)); ?></button>
                    </form>
                    <a class="btn btn-sm btn-outline-info ms-1" href="?module=domain_hub&view_risk_log=<?php echo intval($rt->subdomain_id ?? 0); ?>"><?php echo htmlspecialchars($logButton); ?></a>
                  </td>
                  <td></td>
                </tr>
                <?php endforeach; else: ?>
                <tr><td colspan="6" class="text-muted text-center"><?php echo htmlspecialchars($noDataLabel); ?></td></tr>
                <?php endif; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="border rounded p-3 h-100">
          <div class="small text-muted"><?php echo htmlspecialchars($trendTitle); ?></div>
          <div class="mt-2">
            <?php if (!empty($riskTrend)): foreach ($riskTrend as $t): ?>
              <span class="badge bg-secondary me-1"><?php echo htmlspecialchars($t->d); ?>：<?php echo intval($t->c); ?></span>
            <?php endforeach; else: ?>
              <span class="text-muted"><?php echo htmlspecialchars($noDataLabel); ?></span>
            <?php endif; ?>
          </div>
        </div>
      </div>
    </div>

    <div class="border rounded p-3 mt-3">
      <div class="d-flex justify-content-between align-items-center mb-2">
        <div class="small text-muted"><?php echo htmlspecialchars($allTitle); ?></div>
        <form method="get" class="d-flex gap-2">
          <input type="hidden" name="module" value="domain_hub">
          <div class="input-group input-group-sm me-2" style="width: 240px;">
            <span class="input-group-text">搜索</span>
            <input type="text" name="risk_kw" class="form-control" value="<?php echo htmlspecialchars($kwFilter); ?>" placeholder="<?php echo htmlspecialchars($searchPlaceholder); ?>">
          </div>
          <select name="risk_level" class="form-select form-select-sm me-2" style="width: 140px;">
            <option value=""><?php echo htmlspecialchars($filterAll); ?></option>
            <option value="high" <?php echo ($levelFilter==='high'?'selected':''); ?>>high</option>
            <option value="medium" <?php echo ($levelFilter==='medium'?'selected':''); ?>>medium</option>
            <option value="low" <?php echo ($levelFilter==='low'?'selected':''); ?>>low</option>
          </select>
          <button class="btn btn-sm btn-outline-secondary" type="submit">筛选</button>
        </form>
      </div>
      <div class="table-responsive">
        <table class="table table-sm">
          <thead><tr><th>子域</th><th>分数</th><th>等级</th><th>状态</th><th>最近检查</th><th>操作</th><th>日志</th></tr></thead>
          <tbody>
            <?php if (!empty($riskList)): foreach ($riskList as $r): ?>
            <tr>
              <td><code><?php echo htmlspecialchars($r->subdomain ?? ''); ?></code></td>
              <td><span class="badge bg-<?php echo (intval($r->risk_score)>=80?'danger':(intval($r->risk_score)>=40?'warning':'secondary')); ?>"><?php echo intval($r->risk_score); ?></span></td>
              <td><?php echo htmlspecialchars($r->risk_level ?? ''); ?></td>
              <td><span class="badge bg-<?php echo (($r->status ?? '')==='suspended'?'warning':'success'); ?>"><?php echo htmlspecialchars($r->status ?? ''); ?></span></td>
              <td><small class="text-muted"><?php echo htmlspecialchars($r->last_checked_at ?? ''); ?></small></td>
              <td>
                <form method="post" class="d-inline">
                  <input type="hidden" name="action" value="toggle_subdomain_status">
                  <input type="hidden" name="id" value="<?php echo intval($r->subdomain_id ?? 0); ?>">
                  <button class="btn btn-sm btn-outline-<?php echo (($r->status ?? '')==='suspended'?'success':'danger'); ?>"><?php echo (($r->status ?? '')==='suspended'?htmlspecialchars($unfreezeLabel):htmlspecialchars($freezeLabel)); ?></button>
                </form>
              </td>
              <td>
                <a class="btn btn-sm btn-outline-info" href="?module=domain_hub&view_risk_log=<?php echo intval($r->subdomain_id ?? 0); ?>"><?php echo htmlspecialchars($logButton); ?></a>
              </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="7" class="text-muted text-center"><?php echo htmlspecialchars($noDataLabel); ?></td></tr>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
      <?php if ($riskListTotalPages > 1): ?>
      <nav>
        <ul class="pagination pagination-sm">
          <?php for ($p = 1; $p <= $riskListTotalPages; $p++): ?>
            <li class="page-item <?php echo ($p == $riskListPage ? 'active' : ''); ?>">
              <a class="page-link" href="?module=domain_hub&risk_page=<?php echo $p; ?>&risk_level=<?php echo urlencode($levelFilter); ?>&risk_kw=<?php echo urlencode($kwFilter); ?>"><?php echo $p; ?></a>
            </li>
          <?php endfor; ?>
        </ul>
      </nav>
      <?php endif; ?>
    </div>

    <div class="border rounded p-3 mt-3" id="risk-events">
      <div class="small text-muted"><?php echo htmlspecialchars($latestEventsTitle); ?></div>
      <div class="table-responsive mt-2">
        <table class="table table-sm">
          <thead><tr><th>时间</th><th>子域</th><th>来源</th><th>分数</th><th>级别</th><th>原因</th></tr></thead>
          <tbody>
            <?php if (!empty($riskEvents)): foreach ($riskEvents as $re): ?>
            <tr>
              <td><small class="text-muted"><?php echo htmlspecialchars($re->created_at ?? ''); ?></small></td>
              <td><code><?php echo htmlspecialchars($re->subdomain ?? ''); ?></code></td>
              <td><?php echo htmlspecialchars($re->source ?? ''); ?></td>
              <td><?php echo intval($re->score ?? 0); ?></td>
              <td><?php echo htmlspecialchars($re->level ?? ''); ?></td>
              <td><small class="text-muted"><?php echo htmlspecialchars($re->reason ?? ''); ?></small></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="6" class="text-center text-muted"><?php echo htmlspecialchars($noEventsLabel); ?></td></tr>
            <?php endif; ?>
          </tbody>
        </table>
        <?php if ($riskEventsTotalPages > 1): ?>
        <?php
          $riskEventQueryParams = $_GET;
          $riskEventQueryParams['module'] = 'domain_hub';
          unset($riskEventQueryParams['risk_event_page']);
          $riskEventQueryString = http_build_query($riskEventQueryParams);
          if ($riskEventQueryString !== '') { $riskEventQueryString .= '&'; }
        ?>
        <nav aria-label="风险事件分页" class="mt-2">
          <ul class="pagination pagination-sm justify-content-center">
            <?php if ($riskEventsPage > 1): ?>
              <li class="page-item"><a class="page-link" href="?<?php echo $riskEventQueryString; ?>risk_event_page=<?php echo $riskEventsPage-1; ?>#risk-events">上一页</a></li>
            <?php endif; ?>
            <?php for ($i=1;$i<=$riskEventsTotalPages;$i++): ?>
              <?php if ($i == $riskEventsPage): ?>
                <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
              <?php elseif ($i==1 || $i==$riskEventsTotalPages || abs($i-$riskEventsPage)<=2): ?>
                <li class="page-item"><a class="page-link" href="?<?php echo $riskEventQueryString; ?>risk_event_page=<?php echo $i; ?>#risk-events"><?php echo $i; ?></a></li>
              <?php elseif (abs($i-$riskEventsPage)==3): ?>
                <li class="page-item disabled"><span class="page-link">...</span></li>
              <?php endif; ?>
            <?php endfor; ?>
            <?php if ($riskEventsPage < $riskEventsTotalPages): ?>
              <li class="page-item"><a class="page-link" href="?<?php echo $riskEventQueryString; ?>risk_event_page=<?php echo $riskEventsPage+1; ?>#risk-events">下一页</a></li>
            <?php endif; ?>
          </ul>
          <div class="text-center text-muted small">第 <?php echo $riskEventsPage; ?> / <?php echo $riskEventsTotalPages; ?> 页（共 <?php echo $riskEventsTotal; ?> 条）</div>
        </nav>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>
