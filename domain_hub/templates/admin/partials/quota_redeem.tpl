<?php
$redeemView = $quotasView['redeem'] ?? [];
$redeemEnabled = !empty($redeemView['enabled']);

$redeemCodes = $redeemView['codes']['items'] ?? [];
$redeemCodePage = $redeemView['codes']['page'] ?? 1;
$redeemCodePerPage = $redeemView['codes']['perPage'] ?? 20;
$redeemCodeTotal = $redeemView['codes']['total'] ?? (is_countable($redeemCodes) ? count($redeemCodes) : 0);
$redeemCodeTotalPages = $redeemView['codes']['totalPages'] ?? 1;
$redeemCodeSearch = $redeemView['codes']['search'] ?? '';

$redeemHistory = $redeemView['history']['items'] ?? [];
$redeemHistoryPage = $redeemView['history']['page'] ?? 1;
$redeemHistoryPerPage = $redeemView['history']['perPage'] ?? 20;
$redeemHistoryTotal = $redeemView['history']['total'] ?? (is_countable($redeemHistory) ? count($redeemHistory) : 0);
$redeemHistoryTotalPages = $redeemView['history']['totalPages'] ?? 1;
$redeemHistoryFilters = $redeemView['history']['filters'] ?? [];
$redeemHistoryUserFilter = $redeemHistoryFilters['user'] ?? '';
$redeemHistoryCodeFilter = $redeemHistoryFilters['code'] ?? '';
?>

<div class="card mb-4" id="quotaRedeem">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="card-title mb-0"><i class="fas fa-exchange-alt"></i> 额度兑换管理</h5>
            <form method="post" class="d-inline-flex align-items-center gap-2">
                <input type="hidden" name="action" value="admin_toggle_quota_redeem">
                <input type="hidden" name="enable_quota_redeem" value="<?php echo $redeemEnabled ? '0' : '1'; ?>">
                <button type="submit" class="btn btn-sm <?php echo $redeemEnabled ? 'btn-outline-danger' : 'btn-outline-success'; ?>">
                    <?php echo $redeemEnabled ? '<i class="fas fa-pause"></i> 关闭兑换功能' : '<i class="fas fa-play"></i> 启用兑换功能'; ?>
                </button>
            </form>
        </div>

        <div class="alert alert-info">
            <i class="fas fa-info-circle"></i> 启用后，用户可在客户端通过兑换码增加注册额度。您可以手动创建兑换码或批量生成矩阵码，并设置有效期与可使用次数。
        </div>

        <div class="row g-3 mb-4">
            <div class="col-md-6">
                <div class="border rounded p-3 h-100">
                    <h6 class="mb-3"><i class="fas fa-key"></i> 手动创建兑换码</h6>
                    <form method="post" class="row g-2 align-items-end">
                        <input type="hidden" name="action" value="admin_create_redeem_code">
                        <div class="col-md-6">
                            <label class="form-label">兑换码（留空自动生成）</label>
                            <input type="text" name="code" class="form-control" placeholder="例如：VIP2024">
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">增加额度</label>
                            <input type="number" name="grant_amount" class="form-control" min="1" value="1" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">模式</label>
                            <select name="mode" class="form-select">
                                <option value="single_use">单人专用（首个用户）</option>
                                <option value="multi_use">多人可用（每人一次）</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">总可用次数（0=不限）</label>
                            <input type="number" name="max_total_uses" class="form-control" min="0" value="1">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">每位用户可用次数</label>
                            <input type="number" name="per_user_limit" class="form-control" min="1" value="1">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">有效截止时间</label>
                            <input type="datetime-local" name="valid_to" class="form-control">
                        </div>
                        <div class="col-12">
                            <label class="form-label">备注</label>
                            <textarea name="notes" class="form-control" rows="2" placeholder="可选：用于标记用途或活动"></textarea>
                        </div>
                        <div class="col-12 text-end">
                            <button type="submit" class="btn btn-primary"><i class="fas fa-save"></i> 保存兑换码</button>
                        </div>
                    </form>
                </div>
            </div>
            <div class="col-md-6">
                <div class="border rounded p-3 h-100">
                    <h6 class="mb-3"><i class="fas fa-layer-group"></i> 批量生成随机兑换码</h6>
                    <form method="post" class="row g-2 align-items-end">
                        <input type="hidden" name="action" value="admin_generate_redeem_codes">
                        <div class="col-md-3">
                            <label class="form-label">生成数量</label>
                            <input type="number" name="count" class="form-control" min="1" max="200" value="20" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">每个增加额度</label>
                            <input type="number" name="grant_amount" class="form-control" min="1" value="1" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">模式</label>
                            <select name="mode" class="form-select">
                                <option value="single_use">单人专用</option>
                                <option value="multi_use" selected>多人可用</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">总次数（0=不限）</label>
                            <input type="number" name="max_total_uses" class="form-control" min="0" value="0">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">每人最多使用</label>
                            <input type="number" name="per_user_limit" class="form-control" min="1" value="1">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">有效天数（0=不限）</label>
                            <input type="number" name="valid_days" class="form-control" min="0" value="30">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">批次标签</label>
                            <input type="text" name="batch_tag" class="form-control" placeholder="例如：春季活动">
                        </div>
                        <div class="col-12">
                            <label class="form-label">备注</label>
                            <textarea name="notes" class="form-control" rows="2" placeholder="可选：说明此批次的用途"></textarea>
                        </div>
                        <div class="col-12 text-end">
                            <button type="submit" class="btn btn-outline-primary"><i class="fas fa-bolt"></i> 一键生成</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <div class="row g-4">
            <div class="col-lg-7">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h6 class="mb-0"><i class="fas fa-list-ul"></i> 兑换码列表</h6>
                    <form method="get" class="d-flex gap-2" action="">
                        <input type="hidden" name="module" value="<?php echo htmlspecialchars($moduleSlugAttr); ?>">
                        <input type="text" name="redeem_code_search" class="form-control form-control-sm" placeholder="按兑换码/批次搜索" value="<?php echo htmlspecialchars($redeemCodeSearch); ?>">
                        <button type="submit" class="btn btn-sm btn-outline-secondary">搜索</button>
                    </form>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>ID</th>
                                <th>兑换码</th>
                                <th>增加额度</th>
                                <th>模式</th>
                                <th>有效期</th>
                                <th>使用情况</th>
                                <th>状态</th>
                                <th class="text-end">操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($redeemCodes)): ?>
                                <?php foreach ($redeemCodes as $codeRow): ?>
                                    <?php
                                        $maxUses = intval($codeRow->max_total_uses ?? 0);
                                        $used = intval($codeRow->redeemed_total ?? 0);
                                        $usageText = $maxUses > 0 ? ($used . '/' . $maxUses) : ($used . '/∞');
                                        $validFrom = $codeRow->valid_from ? date('Y-m-d H:i', strtotime($codeRow->valid_from)) : '-';
                                        $validTo = $codeRow->valid_to ? date('Y-m-d H:i', strtotime($codeRow->valid_to)) : '无限期';
                                        $status = strtolower($codeRow->status ?? 'active');
                                        $statusBadge = 'success';
                                        if ($status === 'disabled') { $statusBadge = 'secondary'; }
                                        elseif ($status === 'exhausted') { $statusBadge = 'warning'; }
                                        elseif ($status === 'expired') { $statusBadge = 'danger'; }
                                    ?>
                                    <tr>
                                        <td>#<?php echo intval($codeRow->id); ?></td>
                                        <td><code><?php echo htmlspecialchars($codeRow->code); ?></code><br><small class="text-muted"><?php echo htmlspecialchars($codeRow->batch_tag ?? ''); ?></small></td>
                                        <td>+<?php echo intval($codeRow->grant_amount ?? 0); ?></td>
                                        <td><?php echo htmlspecialchars($codeRow->mode === 'multi_use' ? '多人可用' : '单人专用'); ?></td>
                                        <td><small class="text-muted"><?php echo $validFrom; ?> → <?php echo $validTo; ?></small></td>
                                        <td><?php echo $usageText; ?></td>
                                        <td><span class="badge bg-<?php echo $statusBadge; ?>"><?php echo htmlspecialchars($status); ?></span></td>
                                        <td class="text-end">
                                            <form method="post" class="d-inline">
                                                <input type="hidden" name="action" value="admin_toggle_redeem_code_status">
                                                <input type="hidden" name="code_id" value="<?php echo intval($codeRow->id); ?>">
                                                <input type="hidden" name="target_status" value="<?php echo $status === 'active' ? 'disabled' : 'active'; ?>">
                                                <button type="submit" class="btn btn-sm <?php echo $status === 'active' ? 'btn-outline-warning' : 'btn-outline-success'; ?>">
                                                    <?php echo $status === 'active' ? '停用' : '启用'; ?>
                                                </button>
                                            </form>
                                            <form method="post" class="d-inline ms-1" onsubmit="return confirm('确认删除此兑换码？')">
                                                <input type="hidden" name="action" value="admin_delete_redeem_code">
                                                <input type="hidden" name="code_id" value="<?php echo intval($codeRow->id); ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger"><i class="fas fa-trash"></i></button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr><td colspan="8" class="text-center text-muted">暂无兑换码</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <?php if ($redeemCodeTotalPages > 1): ?>
                    <?php
                        $codeParams = $_GET;
                        $codeParams['module'] = htmlspecialchars($moduleSlugAttr);
                        unset($codeParams['redeem_code_page']);
                        $baseQuery = http_build_query($codeParams);
                        if ($baseQuery !== '') { $baseQuery .= '&'; }
                    ?>
                    <nav class="mt-2" aria-label="兑换码分页">
                        <ul class="pagination pagination-sm justify-content-center">
                            <?php if ($redeemCodePage > 1): ?>
                                <li class="page-item"><a class="page-link" href="?<?php echo $baseQuery; ?>redeem_code_page=<?php echo $redeemCodePage - 1; ?>#quotaRedeem">上一页</a></li>
                            <?php endif; ?>
                            <?php for ($i = 1; $i <= $redeemCodeTotalPages; $i++): ?>
                                <?php if ($i === $redeemCodePage): ?>
                                    <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                                <?php else: ?>
                                    <li class="page-item"><a class="page-link" href="?<?php echo $baseQuery; ?>redeem_code_page=<?php echo $i; ?>#quotaRedeem"><?php echo $i; ?></a></li>
                                <?php endif; ?>
                            <?php endfor; ?>
                            <?php if ($redeemCodePage < $redeemCodeTotalPages): ?>
                                <li class="page-item"><a class="page-link" href="?<?php echo $baseQuery; ?>redeem_code_page=<?php echo $redeemCodePage + 1; ?>#quotaRedeem">下一页</a></li>
                            <?php endif; ?>
                        </ul>
                        <div class="text-center text-muted small">第 <?php echo $redeemCodePage; ?> / <?php echo $redeemCodeTotalPages; ?> 页（共 <?php echo $redeemCodeTotal; ?> 条）</div>
                    </nav>
                <?php endif; ?>
            </div>
            <div class="col-lg-5">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h6 class="mb-0"><i class="fas fa-history"></i> 兑换历史</h6>
                    <form method="get" class="row g-1 align-items-end" action="">
                        <input type="hidden" name="module" value="<?php echo htmlspecialchars($moduleSlugAttr); ?>">
                        <div class="col-md-5">
                            <label class="form-label">用户（ID/邮箱）</label>
                            <input type="text" name="redeem_history_user" class="form-control form-control-sm" value="<?php echo htmlspecialchars($redeemHistoryUserFilter); ?>">
                        </div>
                        <div class="col-md-5">
                            <label class="form-label">兑换码</label>
                            <input type="text" name="redeem_history_code" class="form-control form-control-sm" value="<?php echo htmlspecialchars($redeemHistoryCodeFilter); ?>">
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">&nbsp;</label>
                            <div>
                                <button type="submit" class="btn btn-sm btn-outline-secondary">筛选</button>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>ID</th>
                                <th>用户</th>
                                <th>兑换码</th>
                                <th>增加额度</th>
                                <th>时间</th>
                                <th>状态</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($redeemHistory)): ?>
                                <?php foreach ($redeemHistory as $historyRow): ?>
                                    <tr>
                                        <td>#<?php echo intval($historyRow->id); ?></td>
                                        <td>
                                            <div class="small">
                                                <?php echo htmlspecialchars(trim(($historyRow->firstname ?? '') . ' ' . ($historyRow->lastname ?? ''))); ?><br>
                                                <span class="text-muted">ID: <?php echo intval($historyRow->userid ?? 0); ?></span><br>
                                                <span class="text-muted"><?php echo htmlspecialchars($historyRow->email ?? ''); ?></span>
                                            </div>
                                        </td>
                                        <td><code><?php echo htmlspecialchars($historyRow->code); ?></code></td>
                                        <td>+<?php echo intval($historyRow->grant_amount ?? 0); ?></td>
                                        <td><small class="text-muted"><?php echo $historyRow->created_at ? date('Y-m-d H:i', strtotime($historyRow->created_at)) : '-'; ?></small></td>
                                        <td><span class="badge bg-<?php echo ($historyRow->status === 'success') ? 'success' : 'secondary'; ?>"><?php echo htmlspecialchars($historyRow->status); ?></span></td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr><td colspan="6" class="text-center text-muted">暂无兑换记录</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <?php if ($redeemHistoryTotalPages > 1): ?>
                    <?php
                        $historyParams = $_GET;
                        $historyParams['module'] = htmlspecialchars($moduleSlugAttr);
                        unset($historyParams['redeem_history_page']);
                        $historyQuery = http_build_query($historyParams);
                        if ($historyQuery !== '') { $historyQuery .= '&'; }
                    ?>
                    <nav class="mt-2" aria-label="兑换历史分页">
                        <ul class="pagination pagination-sm justify-content-center">
                            <?php if ($redeemHistoryPage > 1): ?>
                                <li class="page-item"><a class="page-link" href="?<?php echo $historyQuery; ?>redeem_history_page=<?php echo $redeemHistoryPage - 1; ?>#quotaRedeem">上一页</a></li>
                            <?php endif; ?>
                            <?php for ($i = 1; $i <= $redeemHistoryTotalPages; $i++): ?>
                                <?php if ($i === $redeemHistoryPage): ?>
                                    <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                                <?php else: ?>
                                    <li class="page-item"><a class="page-link" href="?<?php echo $historyQuery; ?>redeem_history_page=<?php echo $i; ?>#quotaRedeem"><?php echo $i; ?></a></li>
                                <?php endif; ?>
                            <?php endfor; ?>
                            <?php if ($redeemHistoryPage < $redeemHistoryTotalPages): ?>
                                <li class="page-item"><a class="page-link" href="?<?php echo $historyQuery; ?>redeem_history_page=<?php echo $redeemHistoryPage + 1; ?>#quotaRedeem">下一页</a></li>
                            <?php endif; ?>
                        </ul>
                        <div class="text-center text-muted small">第 <?php echo $redeemHistoryPage; ?> / <?php echo $redeemHistoryTotalPages; ?> 页（共 <?php echo $redeemHistoryTotal; ?> 条）</div>
                    </nav>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
