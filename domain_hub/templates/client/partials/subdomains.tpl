            <!-- 已注册子域名 -->
            <div class="card border-0 shadow-sm">
                <div class="card-body">
                    <div class="d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-2 mb-2">
                        <h5 class="card-title mb-0">
                          <h5 class="card-title mb-0" style="white-space: nowrap;">
    <i class="fas fa-list text-success"></i> <?php echo cfclient_lang('cfclient.subdomains.section_title', '我注册的域名', [], true); ?>
</h5>


                        <div class="d-flex flex-column flex-md-row align-items-md-center w-100 w-md-auto gap-2">
                            <?php if ($domainGiftEnabled): ?>
                            <button type="button" class="btn btn-outline-success" onclick="openDomainGiftModal('initiate')">
                                <i class="fas fa-exchange-alt"></i> <?php echo cfclient_lang('cfclient.subdomains.button.gift', '域名转赠', [], true); ?>
                            </button>
                            <?php endif; ?>
                            <?php if ($dnsUnlockFeatureEnabled): ?>
                            <button type="button" class="btn <?php echo $dnsUnlockRequired ? 'btn-outline-warning' : 'btn-outline-success'; ?>" onclick="showDnsUnlockModal()">
                                <i class="fas <?php echo $dnsUnlockRequired ? 'fa-unlock-alt' : 'fa-unlock'; ?>"></i> <?php echo cfclient_lang('cfclient.subdomains.button.dns_unlock', 'DNS解锁', [], true); ?>
                            </button>
                            <?php endif; ?>
                            <form class="row g-1 align-items-center mb-0 flex-grow-1" method="get" action="">
                                <input type="hidden" name="m" value="<?php echo htmlspecialchars($moduleSlug); ?>">
                                <?php
                                $preserveKeys = ['filter_type','filter_name','dns_page','dns_for'];
                                foreach ($preserveKeys as $preserveKey) {
                                    if (isset($_GET[$preserveKey]) && $_GET[$preserveKey] !== '') {
                                        echo '<input type="hidden" name="' . htmlspecialchars($preserveKey, ENT_QUOTES) . '" value="' . htmlspecialchars($_GET[$preserveKey], ENT_QUOTES) . '">';
                                    }
                                }
                                ?>
                                <div class="col-sm-6 col-md-4 col-lg-3">
                                    <input type="text" class="form-control" name="domain_search" placeholder="<?php echo cfclient_lang('cfclient.subdomains.search.placeholder', '输入域名关键字搜索', [], true); ?>" value="<?php echo htmlspecialchars($domainSearchTerm, ENT_QUOTES); ?>">
                                </div>
                                <div class="col-auto">
                                    <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> <?php echo cfclient_lang('cfclient.subdomains.search.button', '搜索', [], true); ?></button>
                                </div>
                                <?php if ($domainSearchTerm !== ''): ?>
                                <div class="col-auto">
                                    <a href="<?php echo htmlspecialchars($domainSearchClearUrl, ENT_QUOTES); ?>" class="btn btn-outline-secondary"><i class="fas fa-undo"></i> <?php echo cfclient_lang('cfclient.subdomains.search.clear', '清除搜索', [], true); ?></a>
                                </div>
                                <?php endif; ?>
                            </form>
                        </div>
                    </div>

                    <?php if ($domainSearchTerm !== ''): ?>
                        <div class="alert alert-<?php echo $existing_total > 0 ? 'info' : 'warning'; ?> mb-3" role="alert">
                            <?php echo cfclient_lang('cfclient.subdomains.search.alert.result', '搜索关键字：“%1$s”，共找到 %2$s 个匹配结果。', [$domainSearchTerm, $existing_total], true); ?>
                            <?php if ($existing_total === 0): ?>
                                <?php echo cfclient_lang('cfclient.subdomains.search.alert.empty', '未找到匹配的域名，请尝试使用不同关键词或清除搜索条件后再试。', [], true); ?>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                    
                    <?php $clientDeleteEnabled = !empty($clientDeleteEnabled); ?>
                    <?php $dnsUnlock = $dnsUnlock ?? []; ?>
                    <?php $dnsUnlockRequired = !empty($dnsUnlockRequired); ?>
                    <?php $dnsUnlockFeatureEnabled = !empty($dnsUnlockFeatureEnabled); ?>
                    <?php if(count($existing) > 0): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th><?php echo cfclient_lang('cfclient.subdomains.table.domain', '域名', [], true); ?></th>
                                        <th><?php echo cfclient_lang('cfclient.subdomains.table.root', '根域名', [], true); ?></th>
                                        <th><?php echo cfclient_lang('cfclient.subdomains.table.status', '状态', [], true); ?></th>
                                        <th><?php echo cfclient_lang('cfclient.subdomains.table.created_at', '注册时间', [], true); ?></th>
                                        <th><?php echo cfclient_lang('cfclient.subdomains.table.expires_at', '到期时间', [], true); ?></th>
                                        <th><?php echo cfclient_lang('cfclient.subdomains.table.remaining', '剩余时间', [], true); ?></th>
                                        <th><?php echo cfclient_lang('cfclient.subdomains.table.actions', '操作', [], true); ?></th>
                                    </tr>
                                </thead>

                                    <?php 
                                    // 按注册时间倒序显示，确保最新注册的域名排在最前
                                    usort($existing, function($a, $b) {
                                        $timeA = $a->created_at ? strtotime($a->created_at) : 0;
                                        $timeB = $b->created_at ? strtotime($b->created_at) : 0;
                                        return $timeB <=> $timeA;
                                    });
                                    $nowTsForDisplay = time();
                                    $freeWindowDaysSetting = max(0, intval($module_settings['domain_free_renew_window_days'] ?? 30));
                                    $freeWindowSecondsSetting = $freeWindowDaysSetting * 86400;
                                    $graceDaysSettingRaw = $module_settings['domain_grace_period_days'] ?? ($module_settings['domain_auto_delete_grace_days'] ?? 45);
                                    $graceDaysSetting = is_numeric($graceDaysSettingRaw) ? (int)$graceDaysSettingRaw : 45;
                                    if ($graceDaysSetting < 0) { $graceDaysSetting = 0; }
                                    $graceSecondsSetting = $graceDaysSetting * 86400;
                                    $redemptionDaysSettingRaw = $module_settings['domain_redemption_days'] ?? 0;
                                    $redemptionDaysSetting = is_numeric($redemptionDaysSettingRaw) ? (int)$redemptionDaysSettingRaw : 0;
                                    if ($redemptionDaysSetting < 0) { $redemptionDaysSetting = 0; }
                                    $redemptionSecondsSetting = $redemptionDaysSetting * 86400;
                                    foreach($existing as $e):
                                        $neverExpires = intval($e->never_expires ?? 0) === 1;
                                        $expiresRaw = $e->expires_at ?? null;
                                        $expiresTs = $expiresRaw ? strtotime($expiresRaw) : null;
                                        $expiryDisplay = $neverExpires
                                            ? cfclient_lang('cfclient.subdomains.expires.never', '永久有效')
                                            : ($expiresTs ? date('Y-m-d H:i', $expiresTs) : cfclient_lang('cfclient.subdomains.expires.unset', '未设置'));
                                        $remainingBadgeClass = 'secondary';
                                        $remainingLabel = $neverExpires
                                            ? cfclient_lang('cfclient.subdomains.expires.never', '永久有效')
                                            : cfclient_lang('cfclient.subdomains.remaining.not_set', '未设置');
                                        if (!$neverExpires && $expiresTs) {
                                            $diffSeconds = $expiresTs - $nowTsForDisplay;
                                            if ($diffSeconds >= 0) {
                                                $diffDays = (int) ceil($diffSeconds / 86400);
                                                if ($diffDays <= 0) {
                                                    $remainingLabel = cfclient_lang('cfclient.subdomains.remaining.less_than_day', '不足1天');
                                                } else {
                                                    $remainingLabel = cfclient_lang('cfclient.subdomains.remaining.days', '%s 天', [$diffDays]);
                                                }
                                                if ($diffSeconds <= 3 * 86400) {
                                                    $remainingBadgeClass = 'warning';
                                                } else {
                                                    $remainingBadgeClass = 'success';
                                                }
                                            } else {
                                                $overSecondsAbs = abs($diffSeconds);
                                                $overDays = (int) ceil($overSecondsAbs / 86400);
                                                $overDaysLabel = $overDays <= 0
                                                    ? cfclient_lang('cfclient.subdomains.remaining.less_than_day', '不足1天')
                                                    : cfclient_lang('cfclient.subdomains.remaining.days', '%s 天', [$overDays]);
                                                $remainingLabel = cfclient_lang('cfclient.subdomains.remaining.expired', '逾期 %1$s', [$overDaysLabel]);
                                                if ($graceSecondsSetting > 0 && $overSecondsAbs <= $graceSecondsSetting) {
                                                    $remainingLabel .= cfclient_lang('cfclient.subdomains.remaining.grace_suffix', ' (宽限期)');
                                                } elseif ($redemptionSecondsSetting > 0 && $overSecondsAbs <= ($graceSecondsSetting + $redemptionSecondsSetting)) {
                                                    $remainingLabel .= $redemptionModeSetting === 'auto_charge'
                                                        ? cfclient_lang('cfclient.subdomains.remaining.redemption_auto_suffix', ' (赎回期-自动扣费)')
                                                        : cfclient_lang('cfclient.subdomains.remaining.redemption_suffix', ' (赎回期)');
                                                }
                                                $remainingBadgeClass = 'danger';
                                            }
                                        }
                                        $statusLower = strtolower($e->status ?? '');
                                        $pendingDelete = in_array($statusLower, ['pending_delete', 'pending_remove'], true);
                                        $deleteLocked = intval($e->gift_lock_id ?? 0) > 0;
                                        $deleteConfirmAttr = htmlspecialchars(cfclient_lang('cfclient.subdomains.delete.confirm', '删除后不可恢复，确定删除 %s 吗？', [$e->subdomain], false), ENT_QUOTES);
                                        $canRenew = false;
                                        $canRedeemWithCharge = false;
                                        if (!$neverExpires && $expiresTs && ($statusLower === 'active' || $statusLower === 'pending')) {
                                            if ($freeWindowSecondsSetting <= 0 || $nowTsForDisplay >= ($expiresTs - $freeWindowSecondsSetting)) {
                                                $canRenew = true;
                                            }
                                            if ($graceSecondsSetting > 0 && $nowTsForDisplay > ($expiresTs + $graceSecondsSetting)) {
                                                $canRenew = false;
                                            }
                                        }
                                        $inRedemptionWindow = false;
                                        if (!$neverExpires && $expiresTs && $redemptionSecondsSetting > 0 && ($statusLower === 'active' || $statusLower === 'pending')) {
                                            $graceDeadlineForStage = $expiresTs + $graceSecondsSetting;
                                            $redemptionDeadlineForStage = $graceDeadlineForStage + $redemptionSecondsSetting;
                                            if ($nowTsForDisplay > $graceDeadlineForStage && $nowTsForDisplay <= $redemptionDeadlineForStage) {
                                                $inRedemptionWindow = true;
                                            }
                                        }
                                        if ($inRedemptionWindow && $redemptionModeSetting === 'auto_charge') {
                                            $canRenew = true;
                                            $canRedeemWithCharge = true;
                                        }
                                    ?>
                                    <tr>
                                        <td>
                                            <strong class="text-primary">
                                                <i class="fas fa-link"></i> <?php echo htmlspecialchars($e->subdomain); ?>
                                            </strong>
                                            <?php if ($domainGiftEnabled && $deleteLocked): ?>
                                                <span class="badge bg-info text-dark ms-2"><i class="fas fa-lock"></i> <?php echo cfclient_lang('cfclient.subdomains.badge.gifting', '转赠中', [], true); ?></span>
                                            <?php endif; ?>
                                            <?php if ($clientDeleteEnabled && $pendingDelete): ?>
                                                <span class="badge bg-danger ms-2"><i class="fas fa-clock"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.badge', '待删除', [], true); ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($e->rootdomain); ?></td>
                                        <td>
                                            <?php 
                                            // 检查是否有任何DNS记录（包括三级域名记录）
                                            $hasAnyDnsRecords = (($dnsTotalsBySubId[$e->id] ?? 0) > 0);
                                            $hasDnsHistory = intval($e->has_dns_history ?? 0) === 1;
                                            if (!$hasDnsHistory && $hasAnyDnsRecords) {
                                                $hasDnsHistory = true;
                                            }
                                            $canDisplayDelete = $clientDeleteEnabled && !$hasDnsHistory;
                                            if($hasAnyDnsRecords): ?>
                                                <span class="badge bg-success">
                                                    <i class="fas fa-check"></i> <?php echo cfclient_lang('cfclient.subdomains.status.resolved', '已解析', [], true); ?>
                                                </span>
                                            <?php else: ?>
                                                <span class="badge bg-warning">
                                                    <i class="fas fa-exclamation-triangle"></i> <?php echo cfclient_lang('cfclient.subdomains.status.pending', '未解析', [], true); ?>
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo date('Y-m-d H:i', strtotime($e->created_at)); ?></td>
                                        <td>
                                            <?php if ($neverExpires): ?>
                                            <span class="text-body"><?php echo cfclient_lang('cfclient.subdomains.expires.never', '永久有效', [], true); ?></span>
                                            <?php elseif ($expiresTs): ?>
                                            <span class="<?php echo $expiresTs < $nowTsForDisplay ? 'text-danger fw-semibold' : 'fw-normal text-body'; ?>"><?php echo htmlspecialchars($expiryDisplay); ?></span>
                                            <?php else: ?>
                                                <span class="text-muted"><?php echo cfclient_lang('cfclient.subdomains.expires.unset', '未设置', [], true); ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ($neverExpires): ?>
                                            <span class="text-muted">-</span>
                                            <?php elseif ($expiresTs): ?>
                                            <?php
                                                $remainingTextClass = 'text-secondary';
                                                if ($remainingBadgeClass === 'success') {
                                                    $remainingTextClass = 'text-success fw-semibold';
                                                } elseif ($remainingBadgeClass === 'warning') {
                                                    $remainingTextClass = 'text-warning fw-semibold';
                                                } elseif ($remainingBadgeClass === 'danger') {
                                                    $remainingTextClass = 'text-danger fw-semibold';
                                                }
                                            ?>
                                            <span class="<?php echo $remainingTextClass; ?>"><?php echo htmlspecialchars($remainingLabel); ?></span>
                                            <?php else: ?>
                                                <span class="text-muted"><?php echo cfclient_lang('cfclient.subdomains.remaining.not_set', '未设置', [], true); ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <button type="button" class="btn btn-outline-primary" 
                                                        onclick="showDnsForm(<?php echo $e->id; ?>, '<?php echo htmlspecialchars($e->subdomain); ?>', false)">
                                                    <i class="fas fa-plus"></i> <?php echo cfclient_lang('cfclient.subdomains.button.add_dns', '添加解析', [], true); ?>
                                                </button>
                                                <?php if(!$disableNsManagement): ?>
                                                <button type="button" class="btn btn-outline-secondary" 
                                                        onclick="showNsModal(<?php echo $e->id; ?>, '<?php echo htmlspecialchars($e->subdomain); ?>')">
                                                    <i class="fas fa-server"></i> <?php echo cfclient_lang('cfclient.subdomains.button.ns', 'DNS服务器', [], true); ?>
                                                </button>
                                                <?php else: ?>
                                                <button type="button" class="btn btn-outline-secondary" disabled title="<?php echo cfclient_lang('cfclient.subdomains.tooltip.ns_disabled', '已禁止设置 DNS 服务器', [], true); ?>">
                                                    <i class="fas fa-server"></i> <?php echo cfclient_lang('cfclient.subdomains.button.ns', 'DNS服务器', [], true); ?>
                                                </button>
                                                <?php endif; ?>
                                                <button type="button" class="btn btn-outline-info" 
                                                        onclick="toggleSubdomainDetails(<?php echo $e->id; ?>)">
                                                    <i class="fas fa-eye"></i> <?php echo cfclient_lang('cfclient.subdomains.button.view_details', '查看详情', [], true); ?>
                                                </button>
                                            </div>
                                            <?php if ($canRenew): ?>
                                            <?php
                                                $renewButtonText = $canRedeemWithCharge
                                                    ? cfclient_lang('cfclient.subdomains.button.renew.redeem', '赎回期续费（扣费￥%s）', [number_format($redemptionFeeSetting, 2)], true)
                                                    : cfclient_lang('cfclient.subdomains.button.renew.free', '免费续期', [], true);
                                                $renewButtonClass = $canRedeemWithCharge ? 'btn btn-outline-warning btn-sm' : 'btn btn-outline-success btn-sm';
                                            ?>

                                                <form method="post" class="mt-2">
                                                    <input type="hidden" name="cfmod_csrf_token" value="<?php echo htmlspecialchars($_SESSION['cfmod_csrf'] ?? ''); ?>">
                                                    <input type="hidden" name="action" value="renew">
                                                    <input type="hidden" name="subdomain_id" value="<?php echo intval($e->id); ?>">
                                                    <button type="submit" class="<?php echo $renewButtonClass; ?>">
                                                        <i class="fas fa-redo"></i> <?php echo $renewButtonText; ?>
                                                    </button>
                                                </form>
                                            <?php elseif ($inRedemptionWindow && $redemptionModeSetting !== 'auto_charge'): ?>
                                            <a class="btn btn-outline-success btn-sm ms-2" href="<?php echo htmlspecialchars($redeemTicketUrl, ENT_QUOTES); ?>" target="_blank" rel="noopener noreferrer">
                                                <i class="fas fa-life-ring"></i> <?php echo cfclient_lang('cfclient.subdomains.button.redeem_ticket', '申请恢复域名', [], true); ?>
                                            </a>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    
                                    <!-- 展开的详情行 -->
                                    <tr id="details_<?php echo $e->id; ?>" style="display: none;">
                                        <td colspan="7">
                                            <div class="p-3 bg-light">
                                                <h6 class="mb-3"><?php echo cfclient_lang('cfclient.subdomains.details.title', 'DNS解析记录', [], true); ?></h6>
                                                <?php
                                                    $totalRecords = $dnsTotalsBySubId[$e->id] ?? 0;
                                                    $recordBundle = $filteredBySubId[$e->id] ?? [];
                                                    $recordsForDisplay = [];
                                                    $bundlePage = 1;
                                                    if (is_array($recordBundle) && array_key_exists('items', $recordBundle)) {
                                                        $recordsForDisplay = $recordBundle['items'];
                                                        $bundlePage = intval($recordBundle['page'] ?? 1);
                                                    } elseif (is_array($recordBundle)) {
                                                        $recordsForDisplay = $recordBundle;
                                                    }
                                                    $dnsPages = $totalRecords > 0 ? max(1, (int) ceil($totalRecords / $dnsPageSize)) : 1;
                                                    $activeDnsPage = ($dnsPageFor === intval($e->id)) ? $dnsPage : $bundlePage;
                                                    if ($activeDnsPage > $dnsPages) {
                                                        $activeDnsPage = $dnsPages;
                                                    }
                                                ?>
                                                <?php if($totalRecords > 0): ?>
                                                    <div class="table-responsive">
                                                        <table class="table table-sm table-bordered">
                                                            <thead class="table-light">
                                                                <tr>
                                                                    <th class="text-dark fw-bold"><?php echo cfclient_lang('cfclient.subdomains.details.table.name', '名称', [], true); ?></th>
                                                                    <th class="text-dark fw-bold"><?php echo cfclient_lang('cfclient.subdomains.details.table.type', '类型', [], true); ?></th>
                                                                    <th class="text-dark fw-bold"><?php echo cfclient_lang('cfclient.subdomains.details.table.content', '内容', [], true); ?></th>
                                                                    <th class="text-dark fw-bold">TTL</th>
                                                                    <th class="text-dark fw-bold"><?php echo cfclient_lang('cfclient.subdomains.details.table.line', '线路', [], true); ?></th>
                                                                    <th class="text-dark fw-bold"><?php echo cfclient_lang('cfclient.subdomains.details.table.actions', '操作', [], true); ?></th>
                                                                </tr>
                                                            </thead>
                                                            <tbody>
                                                                <?php if(!empty($recordsForDisplay)): ?>
                                                                    <?php foreach ($recordsForDisplay as $r): ?>
                                                                    <tr>
                                                                        <td>
                                                                            <span class="dns-record-name">
                                                                                <?php if($r->name === '@'): ?>
                                                                                    <span class="badge bg-primary fs-6 fw-bold">@</span>
                                                                                <?php else: ?>
                                                                                    <span class="dns-name-text"><?php echo htmlspecialchars($r->name); ?></span>
                                                                                <?php endif; ?>
                                                                            </span>
                                                                        </td>
                                                                        <td>
                                                                            <span class="badge bg-info text-dark"><?php echo htmlspecialchars($r->type); ?></span>
                                                                        </td>
                                                                        <td>
                                                                            <div class="d-flex align-items-center">
                                                                                <span class="text-dark fw-medium"><?php echo htmlspecialchars($r->content); ?></span>
                                                                                <button type="button" class="btn btn-link btn-sm p-0 ms-2" onclick="copyText('<?php echo htmlspecialchars(addslashes($r->content)); ?>')" title="<?php echo cfclient_lang('cfclient.subdomains.tooltip.copy', '复制内容', [], true); ?>">
                                                                                    <i class="fas fa-copy text-primary"></i>
                                                                                </button>
                                                                            </div>
                                                                        </td>
                                                                        <td>
                                                                            <span class="text-muted fw-medium"><?php echo intval($r->ttl); ?></span>
                                                                        </td>
                                                                        <td>
                                                                        <?php
                                                                        $lineKey = 'cfclient.subdomains.line.default';
                                                                        $ln = strtolower($r->line ?? '');
                                                                        if ($ln === 'telecom') { $lineKey = 'cfclient.subdomains.line.telecom'; }
                                                                        elseif ($ln === 'unicom') { $lineKey = 'cfclient.subdomains.line.unicom'; }
                                                                        elseif ($ln === 'mobile') { $lineKey = 'cfclient.subdomains.line.mobile'; }
                                                                        elseif ($ln === 'oversea') { $lineKey = 'cfclient.subdomains.line.oversea'; }
                                                                        elseif ($ln === 'edu') { $lineKey = 'cfclient.subdomains.line.edu'; }
                                                                        $lineLabel = cfclient_lang($lineKey, '默认', [], true);
                                                                        ?>
                                                                        <span class="badge bg-secondary"><?php echo cfclient_lang('cfclient.subdomains.line.prefix', '线路：', [], true); ?><?php echo $lineLabel; ?></span>
                                                                        </td>
                                                                        <td>
                                                                            <div class="btn-group btn-group-sm">
                                                                                <button type="button" class="btn btn-outline-primary" onclick="showDnsForm(<?php echo $e->id; ?>, '<?php echo htmlspecialchars($e->subdomain); ?>', true, '<?php echo htmlspecialchars($r->record_id); ?>', '<?php echo htmlspecialchars(str_replace('.' . $e->subdomain, '', $r->name) === $r->name ? '@' : str_replace('.' . $e->subdomain, '', $r->name)); ?>', '<?php echo htmlspecialchars($r->type); ?>', '<?php echo htmlspecialchars($r->content); ?>')"><?php echo cfclient_lang('cfclient.subdomains.details.button.edit', '编辑', [], true); ?></button>
                                                                                <form method="post" class="ms-1" onsubmit="return confirm('<?php echo cfclient_lang('cfclient.subdomains.confirm.delete_dns', '确定删除该DNS记录？', [], true); ?>');">
                                                                                    <input type="hidden" name="action" value="delete_dns_record">
                                                                                    <input type="hidden" name="subdomain_id" value="<?php echo $e->id; ?>">
                                                                                    <input type="hidden" name="record_id" value="<?php echo htmlspecialchars($r->record_id); ?>">
                                                                                    <button type="submit" class="btn btn-outline-danger"><?php echo cfclient_lang('cfclient.subdomains.details.button.delete', '删除', [], true); ?></button>
                                                                                </form>
                                                                            </div>
                                                                        </td>
                                                                    </tr>
                                                                    <?php endforeach; ?>
                                                                <?php else: ?>
                                                                    <tr>
                                                                        <td colspan="6" class="text-center text-muted py-3"><?php echo cfclient_lang('cfclient.subdomains.details.table.empty_page', '当前页暂无记录', [], true); ?></td>
                                                                    </tr>
                                                                <?php endif; ?>
                                                            </tbody>
                                                        </table>
                                                        <?php if($dnsPages > 1): ?>
                                                        <?php
                                                            $dnsPaginationBase = $_GET;
                                                            $dnsPaginationBase['m'] = $moduleSlug;
                                                            $dnsPaginationBase['p'] = $domainPage;
                                                            if (!empty($filter_type)) { $dnsPaginationBase['filter_type'] = $filter_type; } else { unset($dnsPaginationBase['filter_type']); }
                                                            if (!empty($filter_name)) { $dnsPaginationBase['filter_name'] = $filter_name; } else { unset($dnsPaginationBase['filter_name']); }
                                                            $dnsPaginationBase['dns_for'] = intval($e->id);
                                                            unset($dnsPaginationBase['page']);
                                                            unset($dnsPaginationBase['dns_page']);
                                                        ?>
                                                        <nav aria-label="<?php echo cfclient_lang('cfclient.subdomains.pagination.dns_aria', 'DNS记录分页', [], true); ?>">
                                                            <ul class="pagination pagination-sm mb-0">
                                                                <?php if($activeDnsPage > 1): ?>
                                                                    <?php $prevQuery = $dnsPaginationBase; $prevQuery['dns_page'] = $activeDnsPage - 1; ?>
                                                                    <li class="page-item">
                                                                        <a class="page-link" href="?<?php echo htmlspecialchars(http_build_query($prevQuery), ENT_QUOTES); ?>#details_<?php echo intval($e->id); ?>" aria-label="<?php echo cfclient_lang('cfclient.subdomains.pagination.prev', '上一页', [], true); ?>">&laquo;</a>
                                                                    </li>
                                                                <?php else: ?>
                                                                    <li class="page-item disabled"><span class="page-link">&laquo;</span></li>
                                                                <?php endif; ?>
                                                                <?php for($i=1;$i<=$dnsPages;$i++): ?>
                                                                    <?php $dnsQuery = $dnsPaginationBase; $dnsQuery['dns_page'] = $i; ?>
                                                                    <li class="page-item <?php echo $i === $activeDnsPage ? 'active' : ''; ?>">
                                                                        <a class="page-link" href="?<?php echo htmlspecialchars(http_build_query($dnsQuery), ENT_QUOTES); ?>#details_<?php echo intval($e->id); ?>"><?php echo $i; ?></a>
                                                                    </li>
                                                                <?php endfor; ?>
                                                                <?php if($activeDnsPage < $dnsPages): ?>
                                                                    <?php $nextQuery = $dnsPaginationBase; $nextQuery['dns_page'] = $activeDnsPage + 1; ?>
                                                                    <li class="page-item">
                                                                        <a class="page-link" href="?<?php echo htmlspecialchars(http_build_query($nextQuery), ENT_QUOTES); ?>#details_<?php echo intval($e->id); ?>" aria-label="<?php echo cfclient_lang('cfclient.subdomains.pagination.next', '下一页', [], true); ?>">&raquo;</a>
                                                                    </li>
                                                                <?php else: ?>
                                                                    <li class="page-item disabled"><span class="page-link">&raquo;</span></li>
                                                                <?php endif; ?>
                                                            </ul>
                                                        </nav>
                                                        <?php endif; ?>
                                                    </div>
                                                <?php else: ?>
                                                    <div class="text-center text-muted py-3">
                                                        <i class="fas fa-inbox fa-2x mb-2"></i>
                                                        <p><?php echo cfclient_lang('cfclient.subdomains.details.empty', '暂无DNS解析记录', [], true); ?></p>
                                                        <button type="button" class="btn btn-sm btn-primary"
                                                                onclick="showDnsForm(<?php echo $e->id; ?>, '<?php echo htmlspecialchars($e->subdomain); ?>', false)">
                                                            <?php echo cfclient_lang('cfclient.subdomains.details.button.add', '立即添加解析记录', [], true); ?>
                                                        </button>
                                                        <?php if ($canDisplayDelete): ?>
                                                            <?php if ($pendingDelete): ?>
                                                                <button type="button" class="btn btn-sm btn-outline-secondary ms-2" disabled>
                                                                    <i class="fas fa-clock"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.pending_short', '已提交，待清理', [], true); ?>
                                                                </button>
                                                            <?php elseif ($deleteLocked): ?>
                                                                <button type="button" class="btn btn-sm btn-outline-secondary ms-2" disabled>
                                                                    <i class="fas fa-lock"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.disabled_gift_short', '锁定中，暂不可删', [], true); ?>
                                                                </button>
                                                            <?php else: ?>
                                                                <form method="post" class="d-inline-block ms-2" onsubmit="return confirm('<?php echo $deleteConfirmAttr; ?>');">
                                                                    <input type="hidden" name="cfmod_csrf_token" value="<?php echo htmlspecialchars($_SESSION['cfmod_csrf'] ?? ''); ?>">
                                                                    <input type="hidden" name="action" value="delete_subdomain">
                                                                    <input type="hidden" name="subdomain_id" value="<?php echo intval($e->id); ?>">
                                                                    <button type="submit" class="btn btn-sm btn-outline-danger">
                                                                        <i class="fas fa-trash-alt"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.button', '删除域名', [], true); ?>
                                                                    </button>
                                                                </form>
                                                            <?php endif; ?>
                                                        <?php endif; ?>
                                                    </div>
                                                <?php endif; ?>

                                                <?php if ($clientDeleteEnabled): ?>
                                                    <?php if ($canDisplayDelete): ?>
                                                        <?php
                                                            $deleteHelpMessage = '';
                                                            if ($pendingDelete) {
                                                                $deleteHelpMessage = cfclient_lang('cfclient.subdomains.delete.pending', '删除申请已提交，系统稍后会自动处理。', [], true);
                                                            } elseif ($deleteLocked) {
                                                                $deleteHelpMessage = cfclient_lang('cfclient.subdomains.delete.disabled_gift', '域名当前处于转赠或锁定状态，请先取消后再尝试删除。', [], true);
                                                            }
                                                        ?>
                                                        <div class="alert <?php echo $pendingDelete ? 'alert-warning' : ($deleteHelpMessage !== '' ? 'alert-secondary' : 'alert-danger'); ?> p-3 mt-3">
                                                            <?php if ($deleteHelpMessage !== ''): ?>
                                                                <i class="fas <?php echo $pendingDelete ? 'fa-clock' : 'fa-lock'; ?>"></i> <?php echo $deleteHelpMessage; ?>
                                                            <?php elseif (!$hasAnyDnsRecords): ?>
                                                                <div>
                                                                    <h6 class="mb-1 text-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.title', '删除此域名', [], true); ?></h6>
                                                                    <p class="mb-0 small text-muted"><?php echo cfclient_lang('cfclient.subdomains.delete.description', '提交后域名将进入删除队列，系统会在每日清理任务中自动处理，期间无法撤销。', [], true); ?></p>
                                                                </div>
                                                            <?php else: ?>
                                                                <div class="d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-2">
                                                                    <div>
                                                                        <h6 class="mb-1 text-danger"><i class="fas fa-exclamation-triangle"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.title', '删除此域名', [], true); ?></h6>
                                                                        <p class="mb-0 small text-muted"><?php echo cfclient_lang('cfclient.subdomains.delete.description', '提交后域名将进入删除队列，系统会在每日清理任务中自动处理，期间无法撤销。', [], true); ?></p>
                                                                    </div>
                                                                    <form method="post" class="text-md-end" onsubmit="return confirm('<?php echo $deleteConfirmAttr; ?>');">
                                                                        <input type="hidden" name="cfmod_csrf_token" value="<?php echo htmlspecialchars($_SESSION['cfmod_csrf'] ?? ''); ?>">
                                                                        <input type="hidden" name="action" value="delete_subdomain">
                                                                        <input type="hidden" name="subdomain_id" value="<?php echo intval($e->id); ?>">
                                                                        <button type="submit" class="btn btn-sm btn-outline-danger">
                                                                            <i class="fas fa-trash-alt"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.button', '删除域名', [], true); ?>
                                                                        </button>
                                                                    </form>
                                                                </div>
                                                            <?php endif; ?>
                                                        </div>
                                                    <?php else: ?>
                                                        <div class="alert alert-secondary p-3 mt-3">
                                                            <small class="text-muted"><i class="fas fa-info-circle"></i> <?php echo cfclient_lang('cfclient.subdomains.delete.history_blocked', '该域名曾添加过解析记录，如需删除请联系人工支持。', [], true); ?></small>
                                                        </div>
                                                    <?php endif; ?>
                                                <?php else: ?>
                                                    <div class="alert alert-secondary p-2 mt-3">
                                                        <small class="text-muted"><i class="fas fa-info-circle"></i> <?php echo cfclient_lang('cfclient.subdomains.details.delete_notice', '注册成功的域名暂不支持删除,如有问题请联系客服获取帮助。', [], true); ?></small>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php if ($domainTotalPages > 1): ?>
                        <?php
                            $domainPaginationBaseParams = $_GET;
                            $domainPaginationBaseParams['m'] = $moduleSlug;
                            if (!empty($filter_type)) { $domainPaginationBaseParams['filter_type'] = $filter_type; } else { unset($domainPaginationBaseParams['filter_type']); }
                            if (!empty($filter_name)) { $domainPaginationBaseParams['filter_name'] = $filter_name; } else { unset($domainPaginationBaseParams['filter_name']); }
                            if ($dnsPage > 1) { $domainPaginationBaseParams['dns_page'] = $dnsPage; } else { unset($domainPaginationBaseParams['dns_page']); }
                            if ($dnsPageFor > 0) { $domainPaginationBaseParams['dns_for'] = $dnsPageFor; } else { unset($domainPaginationBaseParams['dns_for']); }
                            if ($domainSearchTerm !== '') { $domainPaginationBaseParams['domain_search'] = $domainSearchTerm; } else { unset($domainPaginationBaseParams['domain_search']); }
                            unset($domainPaginationBaseParams['p']);
                            unset($domainPaginationBaseParams['page']);
                        ?>
                        <div class="d-flex flex-column flex-md-row align-items-md-center justify-content-between mt-3 gap-2">
                            <div class="small text-muted">
                                <?php echo cfclient_lang('cfclient.subdomains.pagination.summary', '共 %1$s 个域名，每页显示 %2$s 个', [$existing_total, $domainPageSize], true); ?>
                            </div>
                            <nav aria-label="<?php echo cfclient_lang('cfclient.subdomains.pagination.aria', '域名列表分页', [], true); ?>">
                                <ul class="pagination pagination-sm mb-0">
                                    <?php if ($domainPage > 1): ?>
                                        <?php $prevDomainQuery = $domainPaginationBaseParams; $prevDomainQuery['p'] = $domainPage - 1; ?>
                                        <li class="page-item">
                                            <a class="page-link" href="?<?php echo htmlspecialchars(http_build_query($prevDomainQuery), ENT_QUOTES); ?>" aria-label="<?php echo cfclient_lang('cfclient.subdomains.pagination.prev', '上一页', [], true); ?>">&laquo;</a>
                                        </li>
                                    <?php else: ?>
                                        <li class="page-item disabled"><span class="page-link">&laquo;</span></li>
                                    <?php endif; ?>
                                    <?php for ($i = 1; $i <= $domainTotalPages; $i++): ?>
                                        <?php $domainQuery = $domainPaginationBaseParams; $domainQuery['p'] = $i; ?>
                                        <li class="page-item <?php echo $i === $domainPage ? 'active' : ''; ?>">
                                            <a class="page-link" href="?<?php echo htmlspecialchars(http_build_query($domainQuery), ENT_QUOTES); ?>"><?php echo $i; ?></a>
                                        </li>
                                    <?php endfor; ?>
                                    <?php if ($domainPage < $domainTotalPages): ?>
                                        <?php $nextDomainQuery = $domainPaginationBaseParams; $nextDomainQuery['p'] = $domainPage + 1; ?>
                                        <li class="page-item">
                                            <a class="page-link" href="?<?php echo htmlspecialchars(http_build_query($nextDomainQuery), ENT_QUOTES); ?>" aria-label="<?php echo cfclient_lang('cfclient.subdomains.pagination.next', '下一页', [], true); ?>">&raquo;</a>
                                        </li>
                                    <?php else: ?>
                                        <li class="page-item disabled"><span class="page-link">&raquo;</span></li>
                                    <?php endif; ?>
                                </ul>
                            </nav>
                        </div>
                        <?php endif; ?>
                    <?php else: ?>
                        <?php if ($domainSearchTerm !== ''): ?>
                            <div class="text-center py-5">
                                <i class="fas fa-search-minus fa-4x text-muted mb-4"></i>
                                <h5 class="text-muted"><?php echo cfclient_lang('cfclient.subdomains.empty.search_title', '未找到匹配的域名', [], true); ?></h5>
                                <p class="text-muted"><?php echo cfclient_lang('cfclient.subdomains.empty.search_body', '请尝试使用不同关键词或清除搜索条件后再试。', [], true); ?></p>
                                <a class="btn btn-outline-secondary btn-custom" href="<?php echo htmlspecialchars($domainSearchClearUrl, ENT_QUOTES); ?>">
                                    <i class="fas fa-undo"></i> <?php echo cfclient_lang('cfclient.subdomains.empty.clear_filters', '清除搜索条件', [], true); ?>
                                </a>
                            </div>
                        <?php else: ?>
                            <div class="text-center py-5">
                                <i class="fas fa-inbox fa-4x text-muted mb-4"></i>
                                <h5 class="text-muted"><?php echo cfclient_lang('cfclient.subdomains.empty.none_title', '您还没有注册任何免费域名', [], true); ?></h5>
                                <p class="text-muted"><?php echo cfclient_lang('cfclient.subdomains.empty.none_body', '开始注册您的第一个免费域名吧！', [], true); ?></p>
                                <button class="btn btn-primary btn-custom" data-bs-toggle="modal" data-bs-target="#registerModal">
                                    <i class="fas fa-plus"></i> <?php echo cfclient_lang('cfclient.subdomains.empty.none_cta', '立即注册', [], true); ?>
                                </button>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- 域名知识小贴士 -->
