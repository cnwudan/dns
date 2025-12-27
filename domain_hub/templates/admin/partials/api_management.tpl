<?php
$apiCollapseClasses = 'collapse';
if (!empty($apiSectionShouldExpand)) {
    $apiCollapseClasses .= ' show in';
}
$apiToggleExpandedAttribute = !empty($apiSectionShouldExpand) ? 'true' : 'false';
$apiToggleCollapsedClass = !empty($apiSectionShouldExpand) ? '' : ' collapsed';
?>
<div class="card mb-4" id="api-management">
    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <button class="btn btn-link text-white text-decoration-none p-0 d-flex align-items-center<?php echo $apiToggleCollapsedClass; ?>" type="button" data-toggle="collapse" data-target="#apiManagementBody" data-bs-toggle="collapse" data-bs-target="#apiManagementBody" aria-expanded="<?php echo $apiToggleExpandedAttribute; ?>" aria-controls="apiManagementBody">
            <span class="h5 mb-0 d-flex align-items-center">
                <i class="fas fa-key me-2"></i>
                <span>API密钥管理</span>
            </span>
            <i class="fas <?php echo !empty($apiSectionShouldExpand) ? 'fa-chevron-up' : 'fa-chevron-down'; ?> ms-2" id="apiManagementToggleIcon"></i>
        </button>
        <button type="button" class="btn btn-light btn-sm" onclick="document.getElementById('createApiModal').style.display='block'">
            <i class="fas fa-plus"></i> 为用户创建API
        </button>
    </div>
    <div class="card-body <?php echo $apiCollapseClasses; ?>" id="apiManagementBody">
        
        <!-- 显示成功/错误消息 -->
        <?php if (isset($_SESSION['admin_api_success'])): ?>
            <div class="alert alert-success alert-dismissible fade in" role="alert">
                <?php echo $_SESSION['admin_api_success']; unset($_SESSION['admin_api_success']); ?>
                <button type="button" class="close" data-dismiss="alert" aria-label="Close" onclick="this.parentElement.style.display='none'"><span aria-hidden="true">&times;</span></button>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['admin_api_error'])): ?>
            <div class="alert alert-danger alert-dismissible fade in" role="alert">
                <?php echo $_SESSION['admin_api_error']; unset($_SESSION['admin_api_error']); ?>
                <button type="button" class="close" data-dismiss="alert" aria-label="Close" onclick="this.parentElement.style.display='none'"><span aria-hidden="true">&times;</span></button>
            </div>
        <?php endif; ?>
        
        <!-- 搜索表单 -->
        <div class="card mb-4">
            <div class="card-body bg-light">
                <form method="get" action="" class="row g-3 align-items-end">
                    <input type="hidden" name="module" value="domain_hub">
                    <div class="col-md-4">
                        <label for="api_search" class="form-label">
                            <i class="fas fa-search"></i> 搜索关键词
                            <small class="text-muted">(快捷键: Ctrl+K)</small>
                        </label>
                        <input 
                            type="text" 
                            class="form-control" 
                            id="api_search" 
                            name="api_search" 
                            value="<?php echo htmlspecialchars($apiSearchKeyword); ?>" 
                            placeholder="输入用户ID或邮箱...">
                    </div>
                    <div class="col-md-3">
                        <label for="api_search_type" class="form-label">搜索类型</label>
                        <select class="form-select" id="api_search_type" name="api_search_type">
                            <option value="all" <?php echo $apiSearchType === 'all' ? 'selected' : ''; ?>>全部</option>
                            <option value="userid" <?php echo $apiSearchType === 'userid' ? 'selected' : ''; ?>>用户ID</option>
                            <option value="email" <?php echo $apiSearchType === 'email' ? 'selected' : ''; ?>>邮箱</option>
                        </select>
                    </div>
                    <div class="col-md-5">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search"></i> 搜索
                        </button>
                        <?php if (!empty($apiSearchKeyword)): ?>
                            <a href="?module=domain_hub" class="btn btn-secondary">
                                <i class="fas fa-times"></i> 清除搜索
                            </a>
                            <span class="text-muted ms-2">
                                找到 <strong><?php echo $totalApiKeys; ?></strong> 条结果
                            </span>
                        <?php endif; ?>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- API统计 -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="border rounded p-3">
                    <div class="small text-muted">总密钥数</div>
                    <div class="h4 mb-0"><?php echo $totalApiKeys; ?></div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="border rounded p-3">
                    <div class="small text-muted">活跃密钥</div>
                    <div class="h4 mb-0 text-success"><?php echo $activeApiKeys; ?></div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="border rounded p-3">
                    <div class="small text-muted">总请求数</div>
                    <div class="h4 mb-0"><?php echo number_format($totalApiRequests); ?></div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="border rounded p-3">
                    <div class="small text-muted">今日请求</div>
                    <div class="h4 mb-0 text-info"><?php echo number_format($todayApiRequests); ?></div>
                </div>
            </div>
        </div>

        <!-- API密钥列表 -->
        <div class="table-responsive">
            <table class="table table-bordered table-hover table-sm">
                <thead class="table-light">
                    <tr>
                        <th>ID</th>
                        <th>用户</th>
                        <th>密钥名称</th>
                        <th>API Key</th>
                        <th>状态</th>
                        <th>请求次数</th>
                        <th>速率限制<br><small>(次/分钟)</small></th>
                        <th>最后使用</th>
                        <th>创建时间</th>
                        <th style="min-width: 200px;">操作</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($totalApiKeys > 0): ?>
                        <?php foreach ($allApiKeysArray as $key): ?>
                        <tr>
                            <td><?php echo isset($key['id']) ? $key['id'] : ''; ?></td>
                            <td>
                                <?php 
                                $firstname = isset($key['firstname']) ? $key['firstname'] : '';
                                $lastname = isset($key['lastname']) ? $key['lastname'] : '';
                                $email = isset($key['email']) ? $key['email'] : '';
                                $userId = isset($key['userid']) ? $key['userid'] : 0;
                                ?>
                                <div>
                                    <strong><?php echo htmlspecialchars($firstname . ' ' . $lastname); ?></strong>
                                    <span class="badge bg-info ms-1">ID:<?php echo $userId; ?></span>
                                </div>
                                <small class="text-muted"><?php echo htmlspecialchars($email); ?></small>
                            </td>
                            <td>
                                <?php 
                                $keyName = isset($key['key_name']) ? $key['key_name'] : '';
                                echo htmlspecialchars($keyName); 
                                ?>
                            </td>
                            <td>
                                <code>
                                    <?php 
                                    $apiKey = isset($key['api_key']) ? $key['api_key'] : '';
                                    echo htmlspecialchars($apiKey); 
                                    ?>
                                </code>
                            </td>
                            <td>
                                <?php 
                                $status = isset($key['status']) ? $key['status'] : '';
                                if ($status === 'active'): 
                                ?>
                                    <span class="badge bg-success">启用</span>
                                <?php else: ?>
                                    <span class="badge bg-danger">禁用</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php 
                                $requestCount = isset($key['request_count']) ? $key['request_count'] : 0;
                                echo number_format($requestCount); 
                                ?>
                            </td>
                            <td>
                                <?php 
                                $rateLimit = isset($key['rate_limit']) ? $key['rate_limit'] : 60;
                                $keyId = isset($key['id']) ? $key['id'] : 0;
                                ?>
                                <span id="rate_display_<?php echo $keyId; ?>"><?php echo $rateLimit; ?></span>
                                <button type="button" class="btn btn-xs btn-link p-0" onclick="editRateLimit(<?php echo $keyId; ?>, <?php echo $rateLimit; ?>)" title="修改速率限制">
                                    <i class="fas fa-edit"></i>
                                </button>
                            </td>
                            <td>
                                <?php 
                                $lastUsedAt = isset($key['last_used_at']) ? $key['last_used_at'] : null;
                                echo $lastUsedAt ? date('Y-m-d H:i', strtotime($lastUsedAt)) : '从未使用'; 
                                ?>
                            </td>
                            <td>
                                <?php 
                                $createdAt = isset($key['created_at']) ? $key['created_at'] : '';
                                echo $createdAt ? date('Y-m-d H:i', strtotime($createdAt)) : ''; 
                                ?>
                            </td>
                            <td>
                                <?php 
                                $keyId = isset($key['id']) ? $key['id'] : 0;
                                $keyStatus = isset($key['status']) ? $key['status'] : '';
                                $userId = isset($key['userid']) ? $key['userid'] : 0;
                                $userFirstname = isset($key['firstname']) ? $key['firstname'] : '';
                                $userLastname = isset($key['lastname']) ? $key['lastname'] : '';
                                ?>
                                <div class="btn-group btn-group-sm" role="group">
                                    <?php if ($keyStatus === 'active'): ?>
                                        <form method="post" style="display: inline;">
                                            <input type="hidden" name="action" value="admin_disable_api_key">
                                            <input type="hidden" name="key_id" value="<?php echo $keyId; ?>">
                                            <button type="submit" class="btn btn-warning" title="禁用">
                                                <i class="fas fa-ban"></i>
                                            </button>
                                        </form>
                                    <?php else: ?>
                                        <form method="post" style="display: inline;">
                                            <input type="hidden" name="action" value="admin_enable_api_key">
                                            <input type="hidden" name="key_id" value="<?php echo $keyId; ?>">
                                            <button type="submit" class="btn btn-success" title="启用">
                                                <i class="fas fa-check"></i>
                                            </button>
                                        </form>
                                    <?php endif; ?>
                                    <button type="button" class="btn btn-info" onclick="manageUserQuota(<?php echo $userId; ?>, '<?php echo htmlspecialchars($userFirstname . ' ' . $userLastname, ENT_QUOTES); ?>')" title="管理配额">
                                        <i class="fas fa-calculator"></i>
                                    </button>
                                    <form method="post" style="display: inline;" onsubmit="return confirm('确定要删除此API密钥吗？');">
                                        <input type="hidden" name="action" value="admin_delete_api_key">
                                        <input type="hidden" name="key_id" value="<?php echo $keyId; ?>">
                                        <button type="submit" class="btn btn-danger" title="删除">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="10" class="text-center text-muted">暂无API密钥</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        
        <!-- 分页导航 -->
        <?php if ($apiTotalPages > 1): ?>
        <?php
        // 构建分页URL参数
        $paginationParams = 'module=domain_hub';
        if (!empty($apiSearchKeyword)) {
            $paginationParams .= '&api_search=' . urlencode($apiSearchKeyword);
            $paginationParams .= '&api_search_type=' . urlencode($apiSearchType);
        }
        ?>
        <nav aria-label="API密钥分页" class="mt-3">
            <ul class="pagination pagination-sm justify-content-center">
                <?php if ($apiPage > 1): ?>
                    <li class="page-item">
                        <a class="page-link" href="?<?php echo $paginationParams; ?>&api_page=<?php echo $apiPage - 1; ?>#api-management">上一页</a>
                    </li>
                <?php endif; ?>
                
                <?php for ($i = 1; $i <= $apiTotalPages; $i++): ?>
                    <?php if ($i == $apiPage): ?>
                        <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                    <?php elseif ($i == 1 || $i == $apiTotalPages || abs($i - $apiPage) <= 2): ?>
                        <li class="page-item">
                            <a class="page-link" href="?<?php echo $paginationParams; ?>&api_page=<?php echo $i; ?>#api-management"><?php echo $i; ?></a>
                        </li>
                    <?php elseif (abs($i - $apiPage) == 3): ?>
                        <li class="page-item disabled"><span class="page-link">...</span></li>
                    <?php endif; ?>
                <?php endfor; ?>
                
                <?php if ($apiPage < $apiTotalPages): ?>
                    <li class="page-item">
                        <a class="page-link" href="?<?php echo $paginationParams; ?>&api_page=<?php echo $apiPage + 1; ?>#api-management">下一页</a>
                    </li>
                <?php endif; ?>
            </ul>
            <div class="text-center text-muted small">
                第 <?php echo $apiPage; ?> 页，共 <?php echo $apiTotalPages; ?> 页（共 <?php echo $totalApiKeys; ?> 条记录）
                <?php if (!empty($apiSearchKeyword)): ?>
                    <span class="text-info">（搜索结果）</span>
                <?php endif; ?>
            </div>
        </nav>
        <?php endif; ?>

        <!-- 最近API请求日志 -->
        <h6 class="mt-4 mb-3"><i class="fas fa-history"></i> 最近API请求（最新50条）</h6>
        <div class="table-responsive">
            <table class="table table-sm table-bordered">
                <thead class="table-light">
                    <tr>
                        <th>时间</th>
                        <th>用户</th>
                        <th>端点</th>
                        <th>方法</th>
                        <th>响应码</th>
                        <th>耗时(秒)</th>
                        <th>IP</th>
                    </tr>
                </thead>
                <tbody>
                                        <?php if ($recentLogsCount > 0): ?>
                        <?php foreach ($recentLogsArray as $log): ?>
                        <tr>
                            <?php
                            // 使用数组格式
                            $logCreatedAt = isset($log['created_at']) ? $log['created_at'] : '';
                            $logEmail = isset($log['email']) ? $log['email'] : '';
                            $logEndpoint = isset($log['endpoint']) ? $log['endpoint'] : '';
                            $logMethod = isset($log['method']) ? $log['method'] : '';
                            $logResponseCode = isset($log['response_code']) ? $log['response_code'] : 0;
                            $logExecutionTime = isset($log['execution_time']) ? $log['execution_time'] : 0;
                            $logIp = isset($log['ip']) ? $log['ip'] : '';
                            ?>
                            <td><?php echo $logCreatedAt ? date('Y-m-d H:i:s', strtotime($logCreatedAt)) : ''; ?></td>
                            <td><small><?php echo htmlspecialchars($logEmail); ?></small></td>
                            <td><code><?php echo htmlspecialchars($logEndpoint); ?></code></td>
                            <td><span class="badge bg-secondary"><?php echo htmlspecialchars($logMethod); ?></span></td>
                            <td>
                                <?php
                                $codeClass = 'secondary';
                                if ($logResponseCode >= 200 && $logResponseCode < 300) $codeClass = 'success';
                                elseif ($logResponseCode >= 400 && $logResponseCode < 500) $codeClass = 'warning';
                                elseif ($logResponseCode >= 500) $codeClass = 'danger';
                                ?>
                                <span class="badge bg-<?php echo $codeClass; ?>"><?php echo $logResponseCode; ?></span>
                            </td>
                            <td><?php echo number_format($logExecutionTime, 3); ?>s</td>
                            <td><small><?php echo htmlspecialchars($logIp); ?></small></td>
                        </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="7" class="text-center text-muted">暂无API请求记录</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php if (($apiTablesExist ?? false) && ($apiLogsTotalPages ?? 0) > 1): ?>
        <nav aria-label="API日志分页" class="mt-2">
            <ul class="pagination pagination-sm justify-content-center">
                <?php if ($apiLogPage > 1): ?>
                    <li class="page-item"><a class="page-link" href="?module=domain_hub&api_log_page=<?php echo $apiLogPage-1; ?>#api-logs">上一页</a></li>
                <?php endif; ?>
                <?php for($i=1;$i<=$apiLogsTotalPages;$i++): ?>
                    <?php if ($i == $apiLogPage): ?>
                        <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                    <?php elseif ($i==1 || $i==$apiLogsTotalPages || abs($i-$apiLogPage)<=2): ?>
                        <li class="page-item"><a class="page-link" href="?module=domain_hub&api_log_page=<?php echo $i; ?>#api-logs"><?php echo $i; ?></a></li>
                    <?php elseif (abs($i-$apiLogPage)==3): ?>
                        <li class="page-item disabled"><span class="page-link">...</span></li>
                    <?php endif; ?>
                <?php endfor; ?>
                <?php if ($apiLogPage < $apiLogsTotalPages): ?>
                    <li class="page-item"><a class="page-link" href="?module=domain_hub&api_log_page=<?php echo $apiLogPage+1; ?>#api-logs">下一页</a></li>
                <?php endif; ?>
            </ul>
            <div class="text-center text-muted small">第 <?php echo $apiLogPage; ?> / <?php echo $apiLogsTotalPages; ?> 页（共 <?php echo $apiLogsTotal; ?> 条）</div>
        </nav>
        <?php endif; ?>
    </div>
</div>

<!-- 创建API密钥模态框 -->
<div id="createApiModal" class="modal" style="display:none; position: fixed; z-index: 1050; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <form method="post" action="">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title">为用户创建API密钥</h5>
                    <button type="button" class="close" aria-label="Close" onclick="document.getElementById('createApiModal').style.display='none'"><span aria-hidden="true">&times;</span></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-primary">
                        <i class="fas fa-info-circle"></i> 
                        <strong>提示：</strong>如不知道用户ID，可以先
                        <a href="javascript:void(0)" onclick="document.getElementById('createApiModal').style.display='none'; document.getElementById('api_search').focus();">
                            <strong>使用邮箱搜索</strong>
                        </a>
                        查找用户
                    </div>
                    <div class="mb-3">
                        <label for="user_id" class="form-label">用户ID *</label>
                        <input type="number" class="form-control" id="user_id" name="user_id" required min="1" placeholder="例如：123">
                        <small class="text-muted">请输入WHMCS用户ID（数字）</small>
                    </div>
                    <div class="mb-3">
                        <label for="key_name" class="form-label">密钥名称 *</label>
                        <input type="text" class="form-control" id="key_name" name="key_name" required maxlength="100" placeholder="例如：生产环境API">
                    </div>
                    <div class="mb-3">
                        <label for="rate_limit" class="form-label">速率限制（次/分钟）*</label>
                        <input type="number" class="form-control" id="rate_limit" name="rate_limit" value="60" required min="1" max="10000">
                        <small class="text-muted">默认60次/分钟，可设置1-10000</small>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="action" value="admin_create_api_key">
                    <button type="button" class="btn btn-secondary" onclick="document.getElementById('createApiModal').style.display='none'">取消</button>
                    <button type="submit" class="btn btn-primary">创建API密钥</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- 编辑速率限制模态框 -->
<div id="editRateLimitModal" class="modal" style="display:none; position: fixed; z-index: 1050; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <form method="post" action="">
                <div class="modal-header bg-info text-white">
                    <h5 class="modal-title">修改API速率限制</h5>
                    <button type="button" class="close" aria-label="Close" onclick="document.getElementById('editRateLimitModal').style.display='none'"><span aria-hidden="true">&times;</span></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="edit_rate_key_id" name="key_id">
                    <div class="mb-3">
                        <label for="edit_rate_limit" class="form-label">速率限制（次/分钟）*</label>
                        <input type="number" class="form-control" id="edit_rate_limit" name="rate_limit" required min="1" max="10000">
                        <small class="text-muted">可设置1-10000次/分钟</small>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="action" value="admin_set_rate_limit">
                    <button type="button" class="btn btn-secondary" onclick="document.getElementById('editRateLimitModal').style.display='none'">取消</button>
                    <button type="submit" class="btn btn-primary">保存</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- 管理用户配额模态框 -->
<div id="manageQuotaModal" class="modal" style="display:none; position: fixed; z-index: 1050; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <form method="post" action="">
                <div class="modal-header bg-success text-white">
                    <h5 class="modal-title">管理用户配额</h5>
                    <button type="button" class="close" aria-label="Close" onclick="document.getElementById('manageQuotaModal').style.display='none'"><span aria-hidden="true">&times;</span></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" id="quota_user_id" name="user_id">
                    <div class="alert alert-primary">
                        <strong>用户：</strong><span id="quota_user_name"></span>
                    </div>
                    <div class="mb-3">
                        <label for="max_count" class="form-label">基础配额 *</label>
                        <input type="number" class="form-control" id="max_count" name="max_count" required min="0" step="1">
                        <small class="text-muted">最多可设置 99999999999 个</small>
                    </div>
                    <div class="mb-3">
                        <label for="invite_bonus_limit" class="form-label">邀请奖励上限 *</label>
                        <input type="number" class="form-control" id="invite_bonus_limit" name="invite_bonus_limit" required min="0" step="1">
                        <small class="text-muted">通过邀请好友可获得的额外配额上限</small>
                    </div>
                </div>
                <div class="modal-footer">
                    <input type="hidden" name="action" value="admin_set_user_quota">
                    <button type="button" class="btn btn-secondary" onclick="document.getElementById('manageQuotaModal').style.display='none'">取消</button>
                    <button type="submit" class="btn btn-primary" onclick="return validateQuotaForm()">保存配额</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    var collapseEl = document.getElementById('apiManagementBody');
    var iconEl = document.getElementById('apiManagementToggleIcon');
    if (!collapseEl || !iconEl) {
        return;
    }
    var updateIconState = function () {
        var isExpanded = collapseEl.classList.contains('show') || collapseEl.classList.contains('in');
        if (isExpanded) {
            iconEl.classList.add('fa-chevron-up');
            iconEl.classList.remove('fa-chevron-down');
        } else {
            iconEl.classList.add('fa-chevron-down');
            iconEl.classList.remove('fa-chevron-up');
        }
    };
    collapseEl.addEventListener('shown.bs.collapse', updateIconState);
    collapseEl.addEventListener('hidden.bs.collapse', updateIconState);
    updateIconState();
});
</script>

