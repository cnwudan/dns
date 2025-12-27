<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$providersView = $cfAdminViewModel['providers'] ?? [];

$providerAccounts = $providersView['accounts'] ?? [];
$providerAccountMap = $providersView['accountMap'] ?? [];
$activeProviderAccounts = $providersView['activeAccounts'] ?? [];
$providerUsageCounts = $providersView['usageCounts'] ?? [];
$providerAccountsError = $providersView['error'] ?? '';
$defaultProviderAccountId = $providersView['defaultAccountId'] ?? 0;
$defaultProviderSelectId = $providersView['defaultSelectId'] ?? 0;
$hasActiveProviderAccounts = $providersView['hasActive'] ?? false;
$cfmodProviderTypeLabels = $cfmodProviderTypeLabels ?? [
    'alidns' => '阿里云 DNS (AliDNS)',
    'dnspod_legacy' => 'DNSPod 国际版 Legacy API',
    'dnspod_intl' => 'DNSPod 国际版 API 3.0',
    'powerdns' => 'PowerDNS (自建)',
];
?>

<div class="card mb-4" id="providerAccounts">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="card-title mb-0"><i class="fas fa-server"></i> DNS 供应商账户</h5>
            <span class="text-muted small">默认账号 ID：<?php echo $defaultProviderAccountId ?: '未设置'; ?></span>
        </div>
        <?php if ($providerAccountsError !== ''): ?>
            <div class="alert alert-warning mb-3">
                <i class="fas fa-exclamation-triangle me-1"></i>
                <?php echo htmlspecialchars($providerAccountsError, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        <div class="border rounded p-3 mb-4 bg-light">
            <h6 class="fw-bold mb-3"><i class="fas fa-plus-circle me-1"></i> 新增账号</h6>
            <form method="post" class="row g-3">
                <input type="hidden" name="action" value="admin_provider_create">
                <div class="col-md-3">
                    <label class="form-label">账户名称</label>
                    <input type="text" class="form-control" name="provider_name" placeholder="例如：主账号" required>
                </div>
                <div class="col-md-3">
                    <label class="form-label">AccessKey ID</label>
                    <input type="text" class="form-control" name="access_key_id" required>
                </div>
                <div class="col-md-3">
                    <label class="form-label">AccessKey Secret</label>
                    <input type="password" class="form-control" name="access_key_secret" required>
                    <div class="form-text text-muted">
                        阿里云：AccessKey ID/Secret 为阿里云控制台提供的密钥；DNSPod Legacy：ID = Token ID，Secret = Token Value；DNSPod Intl：ID = SecretId，Secret = SecretKey；PowerDNS：ID = API URL（如 http://127.0.0.1:8081/api/v1），Secret = X-API-Key。
                    </div>
                </div>
                <div class="col-md-3">
                    <label class="form-label">供应商类型</label>
                    <select class="form-select" name="provider_type">
                        <?php foreach ($cfmodProviderTypeLabels as $typeValue => $typeLabel): ?>
                            <option value="<?php echo htmlspecialchars($typeValue); ?>" <?php echo $typeValue === 'alidns' ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($typeLabel); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label class="form-label">API 速率限制 (次/分钟)</label>
                    <input type="number" class="form-control" name="provider_rate_limit" min="1" value="60">
                </div>
                <div class="col-md-5">
                    <label class="form-label">备注</label>
                    <input type="text" class="form-control" name="provider_notes" placeholder="可选，例如账号用途" maxlength="500">
                </div>
                <div class="col-md-4 d-flex align-items-center">
                    <div class="form-check mt-4">
                        <input class="form-check-input" type="checkbox" id="createProviderDefault" name="set_as_default" value="1" <?php echo count($providerAccounts) === 0 ? 'checked' : ''; ?>>
                        <label class="form-check-label" for="createProviderDefault">创建后设为默认账号</label>
                    </div>
                </div>
                <div class="col-md-12 text-end">
                    <button type="submit" class="btn btn-primary"><i class="fas fa-save me-1"></i> 保存账号</button>
                </div>
            </form>
        </div>

        <div class="table-responsive">
            <table class="table table-striped align-middle">
                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>账号名称</th>
                        <th>类型</th>
                        <th>凭据</th>
                        <th>速率限制</th>
                        <th>状态 / 备注</th>
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (count($providerAccounts) === 0): ?>
                        <tr>
                            <td colspan="8" class="text-center text-muted">尚未配置供应商账号</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($providerAccounts as $provider): ?>
                            <?php
                                $providerId = intval($provider->id);
                                $isDefault = intval($provider->is_default ?? 0) === 1;
                                $statusRaw = strtolower($provider->status ?? 'active');
                                $statusBadge = $statusRaw === 'active' ? 'success' : 'secondary';
                                $statusLabel = $statusRaw === 'active' ? '启用' : '停用';
                                $secretPreview = cfmod_preview_provider_secret($provider->access_key_secret ?? '');
                                $providerTypeRaw = strtolower($provider->provider_type ?? 'alidns');
                                $providerTypeLabel = $cfmodProviderTypeLabels[$providerTypeRaw] ?? strtoupper($providerTypeRaw);
                                $modalId = 'providerEditModal' . $providerId;
                                $rateLimitValue = intval($provider->rate_limit ?? 0);
                                $usageCount = $providerUsageCounts[$providerId] ?? 0;
                            ?>
                            <tr>
                                <td><?php echo $providerId; ?></td>
                                <td>
                                    <strong><?php echo htmlspecialchars($provider->name ?? ''); ?></strong>
                                    <?php if ($isDefault): ?>
                                        <span class="badge bg-primary ms-2">默认</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo htmlspecialchars($providerTypeLabel); ?></td>
                                <td>
                                    <div class="small text-muted">ID: <?php echo htmlspecialchars($provider->access_key_id ?? ''); ?></div>
                                    <div class="small">Secret: <code><?php echo htmlspecialchars($secretPreview); ?></code></div>
                                </td>
                                <td><?php echo $rateLimitValue > 0 ? $rateLimitValue : '—'; ?></td>
                                <td>
                                    <span class="badge bg-<?php echo $statusBadge; ?>"><?php echo $statusLabel; ?></span>
                                    <?php if ($usageCount > 0): ?>
                                        <div class="small text-muted">绑定根域：<?php echo $usageCount; ?></div>
                                    <?php endif; ?>
                                    <?php if (!empty($provider->notes)): ?>
                                        <div class="small text-muted mt-1"><?php echo htmlspecialchars($provider->notes); ?></div>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $provider->created_at ? date('Y-m-d H:i', strtotime($provider->created_at)) : '-'; ?></td>
                                <td>
                                    <button type="button" class="btn btn-sm btn-outline-primary" data-toggle="modal" data-target="#<?php echo $modalId; ?>" data-bs-toggle="modal" data-bs-target="#<?php echo $modalId; ?>">编辑</button>
                                    <form method="post" class="d-inline ms-1" onsubmit="return confirm('确定要切换该账号状态吗？');">
                                        <input type="hidden" name="action" value="admin_provider_toggle_status">
                                        <input type="hidden" name="provider_id" value="<?php echo $providerId; ?>">
                                        <input type="hidden" name="target_status" value="<?php echo $statusRaw === 'active' ? 'disabled' : 'active'; ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-<?php echo $statusRaw === 'active' ? 'warning' : 'success'; ?>">
                                            <?php echo $statusRaw === 'active' ? '停用' : '启用'; ?>
                                        </button>
                                    </form>
                                    <form method="post" class="d-inline ms-1">
                                        <input type="hidden" name="action" value="admin_provider_set_default">
                                        <input type="hidden" name="provider_id" value="<?php echo $providerId; ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-primary" <?php echo $isDefault ? 'disabled' : ''; ?>>设为默认</button>
                                    </form>
                                    <form method="post" class="d-inline ms-1">
                                        <input type="hidden" name="action" value="admin_provider_test">
                                        <input type="hidden" name="provider_id" value="<?php echo $providerId; ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-info">测试连通性</button>
                                    </form>
                                    <form method="post" class="d-inline ms-1" onsubmit="return confirm('确定删除该账号？');">
                                        <input type="hidden" name="action" value="admin_provider_delete">
                                        <input type="hidden" name="provider_id" value="<?php echo $providerId; ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger" <?php echo ($isDefault || $usageCount > 0) ? 'disabled' : ''; ?>>删除</button>
                                    </form>
                                    <?php if ($usageCount > 0): ?>
                                        <div class="small text-muted mt-1">请先迁移绑定的根域。</div>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php if (count($providerAccounts) > 0): ?>
            <?php foreach ($providerAccounts as $provider): ?>
                <?php
                    $providerId = intval($provider->id);
                    $modalId = 'providerEditModal' . $providerId;
                    $providerTypeRaw = strtolower($provider->provider_type ?? 'alidns');
                    $rateLimitValue = intval($provider->rate_limit ?? 60);
                    $isDefault = intval($provider->is_default ?? 0) === 1;
                ?>
                <div class="modal fade" id="<?php echo $modalId; ?>" tabindex="-1" aria-labelledby="<?php echo $modalId; ?>Label" aria-hidden="true">
                    <div class="modal-dialog modal-lg">
                        <div class="modal-content">
                            <form method="post">
                                <input type="hidden" name="action" value="admin_provider_update">
                                <input type="hidden" name="provider_id" value="<?php echo $providerId; ?>">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="<?php echo $modalId; ?>Label">编辑供应商账号</h5>
                                    <button type="button" class="close" data-dismiss="modal" data-bs-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                                </div>
                                <div class="modal-body">
                                    <div class="row g-3">
                                        <div class="col-md-6">
                                            <label class="form-label">账户名称</label>
                                            <input type="text" class="form-control" name="provider_name" value="<?php echo htmlspecialchars($provider->name ?? ''); ?>" required>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">供应商类型</label>
                                            <select class="form-select" name="provider_type">
                                                <?php foreach ($cfmodProviderTypeLabels as $typeValue => $typeLabel): ?>
                                                    <option value="<?php echo htmlspecialchars($typeValue); ?>" <?php echo $providerTypeRaw === $typeValue ? 'selected' : ''; ?>>
                                                        <?php echo htmlspecialchars($typeLabel); ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">AccessKey ID</label>
                                            <input type="text" class="form-control" name="access_key_id" value="<?php echo htmlspecialchars($provider->access_key_id ?? ''); ?>" required>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">AccessKey Secret</label>
                                            <input type="password" class="form-control" name="access_key_secret" placeholder="留空则保持不变">
                                            <div class="form-text">出于安全考虑，暂不展示原始 Secret。</div>
                                            <div class="form-text text-muted">
                                                阿里云：AccessKey ID/Secret 为阿里云控制台提供的密钥；DNSPod Legacy：ID = Token ID，Secret = Token Value；DNSPod Intl：ID = SecretId，Secret = SecretKey；PowerDNS：ID = API URL（如 http://127.0.0.1:8081/api/v1），Secret = X-API-Key，可在备注中添加 server_id=xxx 指定服务器（默认 localhost）。
                                            </div>
                                        </div>
                                        <div class="col-md-4">
                                            <label class="form-label">API 速率限制</label>
                                            <input type="number" class="form-control" name="provider_rate_limit" min="1" value="<?php echo $rateLimitValue > 0 ? $rateLimitValue : 60; ?>">
                                        </div>
                                        <div class="col-md-8">
                                            <label class="form-label">备注</label>
                                            <textarea class="form-control" name="provider_notes" rows="2" maxlength="500" placeholder="可选"><?php echo htmlspecialchars($provider->notes ?? ''); ?></textarea>
                                        </div>
                                        <div class="col-md-12">
                                            <div class="form-check">
                                                <input class="form-check-input" type="checkbox" id="providerDefault<?php echo $providerId; ?>" name="set_as_default" value="1" <?php echo $isDefault ? 'checked' : ''; ?>>
                                                <label class="form-check-label" for="providerDefault<?php echo $providerId; ?>">保存后设为默认账号</label>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-dismiss="modal" data-bs-dismiss="modal">取消</button>
                                    <button type="submit" class="btn btn-primary">保存变更</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>
