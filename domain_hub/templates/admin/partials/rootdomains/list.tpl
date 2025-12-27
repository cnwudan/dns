<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$rootdomainsView = $cfAdminViewModel['rootdomains'] ?? [];
$hasActiveProviderAccounts = $rootdomainsView['hasActiveProviderAccounts'] ?? false;
$activeProviderAccounts = $rootdomainsView['activeProviderAccounts'] ?? [];
$defaultProviderSelectId = $rootdomainsView['defaultProviderSelectId'] ?? 0;
$rootdomains = $rootdomainsView['rootdomains'] ?? [];
$providerAccountMap = $rootdomainsView['providerAccountMap'] ?? [];
$forbiddenDomains = $rootdomainsView['forbiddenDomains'] ?? [];
$allKnownRootdomains = $rootdomainsView['allKnownRootdomains'] ?? [];
$orderHeader = $lang['rootdomain_order_header'] ?? '排序';
$orderHint = $lang['rootdomain_order_hint'] ?? '数值越小越靠前';
$orderSaveLabel = $lang['rootdomain_order_save'] ?? '保存排序';
?>

<!-- 根域名白名单管理 -->
<div class="card mb-4" id="rootdomainWhitelist">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="card-title mb-0"><i class="fas fa-sitemap"></i> 根域名白名单</h5>
        </div>
        <div class="alert alert-info small">
            <i class="fas fa-lightbulb me-1"></i> 所有可注册根域名必须在此处维护，旧版 <code>root_domains</code> 配置已自动迁移并不再生效。
        </div>
        <?php if (!$hasActiveProviderAccounts): ?>
            <div class="alert alert-warning">
                <i class="fas fa-info-circle me-1"></i> 请先在上方 “DNS 供应商账户” 中配置并启用至少一个账号后再添加根域。
            </div>
        <?php endif; ?>
        <form method="post" class="row g-3 mb-3" onsubmit="return validateRootDomain(this)">
            <input type="hidden" name="action" value="add_rootdomain">
            <div class="col-md-3">
                <input type="text" name="domain" class="form-control" placeholder="example.com" required>
            </div>
            <div class="col-md-2">
                <input type="number" name="max_subdomains" class="form-control" placeholder="最大数量" value="1000" min="1" step="1">
                <small class="text-muted">最大99999999999</small>
            </div>
            <div class="col-md-2">
                <input type="number" name="default_term_years" class="form-control" placeholder="默认年限" value="0" min="0" step="1">
                <small class="text-muted">0 表示使用全局</small>
            </div>
            <div class="col-md-3">
                <select name="provider_account_id" class="form-select" <?php echo $hasActiveProviderAccounts ? '' : 'disabled'; ?> required>
                    <?php if ($hasActiveProviderAccounts): ?>
                        <?php foreach ($activeProviderAccounts as $provider): ?>
                            <option value="<?php echo intval($provider->id); ?>" <?php echo intval($provider->id) === $defaultProviderSelectId ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($provider->name ?? ('ID ' . $provider->id)); ?>
                            </option>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <option value="">暂无可用供应商</option>
                    <?php endif; ?>
                </select>
                <small class="text-muted">DNS 供应商</small>
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary w-100" <?php echo $hasActiveProviderAccounts ? '' : 'disabled'; ?>>添加根域名</button>
            </div>
            <div class="col-md-12">
                <input type="text" name="description" class="form-control" placeholder="描述（可选）">
            </div>
            <div class="col-md-12 text-muted mt-2">
                将自动尝试匹配阿里云解析域名；也可先添加，后续在阿里云中绑定。
            </div>
        </form>
        
        <form method="post" id="rootdomain-order-form" class="d-flex align-items-center gap-2 mb-3">
            <input type="hidden" name="action" value="update_rootdomain_order">
            <button type="submit" class="btn btn-outline-primary btn-sm"><?php echo htmlspecialchars($orderSaveLabel); ?></button>
            <small class="text-muted"><?php echo htmlspecialchars($orderHint); ?></small>
        </form>
        
        <div class="table-responsive">
            <table class="table table-sm align-middle">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>根域名</th>
                        <th><?php echo htmlspecialchars($orderHeader); ?></th>
                        <th>Zone ID</th>
                        <th>DNS 供应商</th>
                        <th>最大数量</th>
                        <th>单用户上限</th>
                        <th>默认年限</th>
                        <th>描述</th>
                        <th>状态</th>
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($rootdomains as $rd): ?>
                    <?php
                        $rdProviderId = intval($rd->provider_account_id ?? 0);
                        $rdProvider = $rdProviderId > 0 && isset($providerAccountMap[$rdProviderId]) ? $providerAccountMap[$rdProviderId] : null;
                        $rdProviderStatus = $rdProvider ? strtolower($rdProvider->status ?? '') : '';
                        $rdProviderLabel = $rdProvider ? ($rdProvider->name ?: ('ID ' . $rdProvider->id)) : null;
                    ?>
                    <tr>
                        <td><?php echo $rd->id; ?></td>
                        <td><code><?php echo htmlspecialchars($rd->domain); ?></code></td>
                        <td style="width:110px;">
                            <input type="number" class="form-control form-control-sm" name="display_order[<?php echo intval($rd->id); ?>]" value="<?php echo intval($rd->display_order ?? 0); ?>" form="rootdomain-order-form">
                        </td>
                        <td><small class="text-muted"><?php echo htmlspecialchars($rd->cloudflare_zone_id ?? ''); ?></small></td>
                        <td>
                            <?php if ($rdProvider): ?>
                                <strong><?php echo htmlspecialchars($rdProviderLabel); ?></strong>
                                <div class="small text-muted">ID <?php echo intval($rdProvider->id); ?></div>
                                <?php if ($rdProviderStatus !== 'active'): ?>
                                    <span class="badge bg-warning text-dark">已停用</span>
                                <?php endif; ?>
                            <?php else: ?>
                                <span class="text-muted">未绑定</span>
                            <?php endif; ?>
                        </td>
                        <td><?php echo intval($rd->max_subdomains ?? 1000); ?></td>
                        <td><?php echo (intval($rd->per_user_limit ?? 0) > 0) ? intval($rd->per_user_limit) : '不限'; ?></td>
                        <td><?php echo $rdDefaultTerm > 0 ? ($rdDefaultTerm . ' 年') : '沿用全局'; ?></td>
                        <td><?php echo htmlspecialchars($rd->description ?? ''); ?></td>
                        <td>
                            <span class="badge bg-<?php echo $rd->status==='active'?'success':'secondary'; ?>"><?php echo $rd->status==='active'?'可注册':'已停止注册'; ?></span>
                        </td>
                        <td><?php echo date('Y-m-d H:i', strtotime($rd->created_at)); ?></td>
                        <td>
                            <div class="btn-group">
                                <button type="button" class="btn btn-sm btn-outline-secondary" data-toggle="modal" data-target="#rootdomainEditModal<?php echo $rd->id; ?>" data-bs-toggle="modal" data-bs-target="#rootdomainEditModal<?php echo $rd->id; ?>">编辑</button>
                                <form method="post" class="d-inline" onsubmit="return confirm('确定切换状态？');">
                                    <input type="hidden" name="action" value="toggle_rootdomain">
                                    <input type="hidden" name="id" value="<?php echo $rd->id; ?>">
                                    <button type="submit" class="btn btn-sm btn-outline-<?php echo $rd->status==='active'?'warning':'success'; ?>">
                                        <?php echo $rd->status==='active'?'停止注册':'重新开启注册'; ?>
                                    </button>
                                </form>
                                <form method="post" class="d-inline" onsubmit="return confirm('确定删除该根域名？');">
                                    <input type="hidden" name="action" value="delete_rootdomain">
                                    <input type="hidden" name="id" value="<?php echo $rd->id; ?>">
                                    <button type="submit" class="btn btn-sm btn-outline-danger">删除</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php if (count($rootdomains) > 0): ?>
    <?php foreach ($rootdomains as $rd): ?>
        <?php
            $rdProviderId = intval($rd->provider_account_id ?? 0);
            $rdProvider = $rdProviderId > 0 && isset($providerAccountMap[$rdProviderId]) ? $providerAccountMap[$rdProviderId] : null;
            $rdProviderStatus = $rdProvider ? strtolower($rdProvider->status ?? '') : '';
            $rdSelectedProviderId = $rdProviderId > 0 ? $rdProviderId : ($defaultProviderSelectId > 0 ? $defaultProviderSelectId : 0);
            $rdMax = intval($rd->max_subdomains ?? 1000);
            if ($rdMax <= 0) { $rdMax = 1000; }
            $rdPerUser = intval($rd->per_user_limit ?? 0);
            if ($rdPerUser < 0) { $rdPerUser = 0; }
            $rdDefaultTerm = intval($rd->default_term_years ?? 0);
        ?>
        <div class="modal fade" id="rootdomainEditModal<?php echo $rd->id; ?>" tabindex="-1" aria-labelledby="rootdomainEditModalLabel<?php echo $rd->id; ?>" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <form method="post">
                        <input type="hidden" name="action" value="admin_rootdomain_update">
                        <input type="hidden" name="rootdomain_id" value="<?php echo $rd->id; ?>">
                        <div class="modal-header">
                            <h5 class="modal-title" id="rootdomainEditModalLabel<?php echo $rd->id; ?>">编辑根域名</h5>
                            <button type="button" class="close" data-dismiss="modal" data-bs-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                        </div>
                        <div class="modal-body">
                            <div class="row g-3">
                                <div class="col-md-6">
                                    <label class="form-label">根域名</label>
                                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($rd->domain); ?>" readonly>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">Zone ID</label>
                                    <input type="text" class="form-control" name="cloudflare_zone_id" value="<?php echo htmlspecialchars($rd->cloudflare_zone_id ?? ''); ?>" placeholder="可选">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">DNS 供应商</label>
                                    <select name="provider_account_id" class="form-select" <?php echo $hasActiveProviderAccounts ? '' : 'disabled'; ?> required>
                                        <?php if ($rdProvider && $rdProviderStatus !== 'active'): ?>
                                            <option value="<?php echo $rdProviderId; ?>" selected disabled><?php echo htmlspecialchars(($rdProvider->name ?: ('ID ' . $rdProvider->id)) . '（已停用）'); ?></option>
                                        <?php endif; ?>
                                        <?php foreach ($activeProviderAccounts as $provider): ?>
                                            <option value="<?php echo intval($provider->id); ?>" <?php echo intval($provider->id) === $rdSelectedProviderId ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($provider->name ?? ('ID ' . $provider->id)); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                    <?php if (!$hasActiveProviderAccounts): ?>
                                        <div class="form-text text-danger">暂无可用供应商账号，无法保存。</div>
                                    <?php elseif ($rdProvider && $rdProviderStatus !== 'active'): ?>
                                        <div class="form-text text-danger">当前绑定账号已停用，请切换至其他账号。</div>
                                    <?php endif; ?>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">描述</label>
                                    <input type="text" class="form-control" name="description" value="<?php echo htmlspecialchars($rd->description ?? ''); ?>" maxlength="255" placeholder="可选">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">最大子域数量</label>
                                    <input type="number" class="form-control" name="max_subdomains" min="1" value="<?php echo $rdMax; ?>">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">单用户上限</label>
                                    <input type="number" class="form-control" name="per_user_limit" min="0" value="<?php echo $rdPerUser; ?>">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">默认注册年限（年）</label>
                                    <input type="number" class="form-control" name="default_term_years" min="0" value="<?php echo $rdDefaultTerm; ?>">
                                    <div class="form-text">0 表示使用系统默认配置</div>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-dismiss="modal" data-bs-dismiss="modal">取消</button>
                            <button type="submit" class="btn btn-primary" <?php echo $hasActiveProviderAccounts ? '' : 'disabled'; ?>>保存</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
<?php endif; ?>

<!-- 域名平台迁移 -->
<div class="card mb-4" id="rootdomainTransfer">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h5 class="card-title mb-0"><i class="fas fa-random"></i> 域名平台迁移</h5>
        </div>
        <p class="text-muted small mb-3">将指定根域名下的所有解析批量复制到新的 DNS 供应商，可选暂停前端注册并在完成后自动恢复。</p>
        <?php if (!$hasActiveProviderAccounts || empty($allKnownRootdomains)): ?>
            <div class="alert alert-warning mb-0">
                <i class="fas fa-info-circle me-1"></i> 请先确保已添加根域名并至少启用一个供应商账号后再使用此功能。
            </div>
        <?php else: ?>
            <form method="post" class="row g-3">
                <input type="hidden" name="action" value="transfer_rootdomain_provider">
                <div class="col-md-4">
                    <label class="form-label">选择根域名</label>
                    <select name="transfer_rootdomain" class="form-select" required>
                        <option value="">-- 请选择 --</option>
                        <?php foreach ($allKnownRootdomains as $domain): ?>
                            <option value="<?php echo htmlspecialchars($domain); ?>"><?php echo htmlspecialchars($domain); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-4">
                    <label class="form-label">目标 DNS 供应商</label>
                    <select name="target_provider_account_id" class="form-select" required>
                        <?php foreach ($activeProviderAccounts as $provider): ?>
                            <option value="<?php echo intval($provider->id); ?>"><?php echo htmlspecialchars($provider->name ?? ('ID ' . $provider->id)); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-4">
                    <label class="form-label">批次大小</label>
                    <input type="number" class="form-control" name="transfer_batch_size" value="200" min="25" max="500">
                    <div class="form-text">每批处理的子域数量，建议 50-200</div>
                </div>
                <div class="col-md-6">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="transfer_pause_registration" name="transfer_pause_registration" value="1">
                        <label class="form-check-label" for="transfer_pause_registration">迁移期间暂停该根域当前端注册</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="transfer_auto_resume" name="transfer_auto_resume" value="1" checked>
                        <label class="form-check-label" for="transfer_auto_resume">任务完成后自动恢复原状态</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="transfer_delete_old" name="transfer_delete_old" value="1">
                        <label class="form-check-label" for="transfer_delete_old">迁移成功后删除旧平台的解析记录</label>
                    </div>
                </div>
                <div class="col-md-6">
                    <label class="form-label d-block">执行方式</label>
                    <div class="form-check">
                        <input class="form-check-input" type="radio" name="transfer_run_mode" id="transfer_run_mode_queue" value="queue" checked>
                        <label class="form-check-label" for="transfer_run_mode_queue">加入队列（推荐）</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="radio" name="transfer_run_mode" id="transfer_run_mode_now" value="now">
                        <label class="form-check-label" for="transfer_run_mode_now">立即执行（大量数据可能耗时）</label>
                    </div>
                </div>
                <div class="col-12">
                    <button type="submit" class="btn btn-warning">开始迁移</button>
                    <small class="text-muted ms-2">系统将逐批迁移解析并在完成后更新根域名绑定。</small>
                </div>
            </form>
        <?php endif; ?>
    </div>
</div>

<!-- 禁止注册域名管理 -->
<div class="card mb-4">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="card-title mb-0"><i class="fas fa-ban"></i> 禁止注册域名</h5>
        </div>
        <form method="post" class="row g-3 mb-3">
            <input type="hidden" name="action" value="add_forbidden">
            <div class="col-md-4">
                <input type="text" name="ban_domain" class="form-control" placeholder="foo.example.com" required>
            </div>
            <div class="col-md-3">
                <input type="text" name="ban_root" class="form-control" placeholder="根域名（可选）">
            </div>
            <div class="col-md-3">
                <input type="text" name="ban_reason" class="form-control" placeholder="原因（可选）">
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary">添加</button>
            </div>
        </form>
        <div class="table-responsive">
            <table class="table table-sm align-middle">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>域名</th>
                        <th>根域</th>
                        <th>原因</th>
                        <th>时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach($forbiddenDomains as $fd): ?>
                    <tr>
                        <td><?php echo $fd->id; ?></td>
                        <td><code><?php echo htmlspecialchars($fd->domain); ?></code></td>
                        <td><?php echo htmlspecialchars($fd->rootdomain ?? ''); ?></td>
                        <td><?php echo htmlspecialchars($fd->reason ?? ''); ?></td>
                        <td><?php echo date('Y-m-d H:i', strtotime($fd->created_at)); ?></td>
                        <td>
                            <form method="post" class="d-inline" onsubmit="return confirm('确定移除该禁止项？');">
                                <input type="hidden" name="action" value="delete_forbidden">
                                <input type="hidden" name="id" value="<?php echo $fd->id; ?>">
                                <button type="submit" class="btn btn-sm btn-outline-danger">删除</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- 一键替换根域名（高级） -->
<div class="card mb-5">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h5 class="card-title mb-0"><i class="fas fa-exchange-alt"></i> 一键替换根域名</h5>
        </div>
        <form method="post" class="row g-3">
            <input type="hidden" name="action" value="replace_rootdomain">
            <div class="col-md-4">
                <label class="form-label">选择旧根域名</label>
                <select name="from_root" class="form-select" required>
                    <option value="">-- 请选择 --</option>
                    <?php foreach ($allKnownRootdomains as $domain): ?>
                        <option value="<?php echo htmlspecialchars($domain); ?>"><?php echo htmlspecialchars($domain); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-md-4">
                <label class="form-label">输入新根域名</label>
                <input type="text" name="to_root" class="form-control" placeholder="new-example.com" required>
            </div>
            <div class="col-md-4">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="delete_old_records" name="delete_old_records" value="1">
                    <label class="form-check-label" for="delete_old_records">迁移后删除旧域名下的解析记录</label>
                </div>
                <div class="form-check mt-1">
                    <input class="form-check-input" type="radio" id="run_queue" name="run_mode" value="queue" checked>
                    <label class="form-check-label" for="run_queue">加入队列执行</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="radio" id="run_now" name="run_mode" value="now">
                    <label class="form-check-label" for="run_now">立即执行</label>
                </div>
            </div>
            <div class="col-12">
                <button type="submit" class="btn btn-warning">开始替换</button>
                <small class="text-muted ms-2">将把所选旧根域名下的所有二级域和解析迁移至新根域名。</small>
            </div>
        </form>
    </div>
</div>

<!-- 根域名数据导出 / 导入 -->
<div class="card mb-4">
    <div class="card-body">
        <h5 class="card-title mb-3"><i class="fas fa-file-export"></i> 根域名数据导出 / 导入</h5>
        <div class="row g-4">
            <div class="col-md-6">
                <form method="post">
                    <input type="hidden" name="action" value="export_rootdomain">
                    <label class="form-label">选择根域名导出</label>
                    <select name="export_rootdomain_value" class="form-select" required>
                        <option value="">-- 请选择 --</option>
                        <?php foreach ($allKnownRootdomains as $domain): ?>
                            <option value="<?php echo htmlspecialchars($domain); ?>"><?php echo htmlspecialchars($domain); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <div class="mt-3 d-flex align-items-start">
                        <button type="submit" class="btn btn-success me-2"><i class="fas fa-download me-1"></i> 导出数据</button>
                        <span class="text-muted small">导出的 JSON 文件包含本地子域、DNS 记录、风险数据以及同步差异等信息，可用于快速恢复。</span>
                    </div>
                </form>
            </div>
            <div class="col-md-6">
                <form method="post" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="import_rootdomain">
                    <label class="form-label">上传导出文件</label>
                    <input type="file" class="form-control" name="import_rootdomain_file" accept=".json,.json.gz" required>
                    <div class="form-text text-muted">支持 JSON 或 GZ 压缩文件；如存在同名子域，将自动覆盖为导入内容。</div>
                    <button type="submit" class="btn btn-primary mt-3"><i class="fas fa-upload me-1"></i> 导入恢复</button>
                </form>
            </div>
        </div>
    </div>
</div>
