<?php
// 获取用户API密钥
$userId = $_SESSION['uid'];
$apiKeys = \WHMCS\Database\Capsule::table('mod_cloudflare_api_keys')
    ->where('userid', $userId)
    ->orderBy('created_at', 'desc')
    ->get();

$moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
$moduleSlugAttr = htmlspecialchars($moduleSlug, ENT_QUOTES);
$moduleSlugUrl = urlencode($moduleSlug);

// 获取模块设置
$settings = [];
$rows = \WHMCS\Database\Capsule::table('tbladdonmodules')
    ->where('module', $moduleSlug)
    ->get();
if (count($rows) === 0) {
    $rows = \WHMCS\Database\Capsule::table('tbladdonmodules')
        ->where('module', defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : 'cloudflare_subdomain')
        ->get();
}
foreach ($rows as $r) {
    $settings[$r->setting] = $r->value;
}

$apiEnabled = ($settings['enable_user_api'] ?? 'on') === 'on';
$maxApiKeys = intval($settings['api_keys_per_user'] ?? 3);
$requireQuota = intval($settings['api_require_quota'] ?? 1);
$ipWhitelistEnabled = ($settings['api_enable_ip_whitelist'] ?? 'no') === 'on';

// 获取用户配额
$quota = \WHMCS\Database\Capsule::table('mod_cloudflare_subdomain_quotas')
    ->where('userid', $userId)
    ->first();
$totalQuota = intval($quota->max_count ?? 0);
$canCreateApi = $totalQuota >= $requireQuota;

if (!$apiEnabled) {
    return;
}

$apiSectionShouldExpand = false;
$cfApiText = static function (string $key, string $default, array $params = [], bool $escape = true): string {
    return cfclient_lang($key, $default, $params, $escape);
};
?>

<div class="card mt-4" id="api-management-card">
    <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <button class="btn btn-link text-white text-decoration-none p-0 d-flex align-items-center gap-2" type="button" id="apiManagementToggleBtn" aria-expanded="<?php echo $apiSectionShouldExpand ? 'true' : 'false'; ?>" aria-controls="apiManagementBody">
            <span class="h5 mb-0 d-flex align-items-center gap-2">
                <i class="fas fa-key"></i>
                <span><?php echo $cfApiText('cfclient.api.card.title', 'API密钥管理', [], true); ?></span>
            </span>
            <i class="fas fa-chevron-down small" id="apiManagementToggleIcon"></i>
        </button>
    </div>
    <div class="card-body collapse <?php echo $apiSectionShouldExpand ? 'show' : ''; ?>" id="apiManagementBody">
        
        <!-- API说明 -->
        <div class="alert alert-info">
            <i class="fas fa-info-circle"></i> 
            <strong><?php echo $cfApiText('cfclient.api.alert.title', 'API功能：', [], true); ?></strong><?php echo $cfApiText('cfclient.api.alert.body', '通过API密钥，您可以在程序中自动管理域名和DNS记录，无需手动操作。', [], true); ?>
            <a href="#" data-bs-toggle="modal" data-bs-target="#apiDocModal" class="alert-link"><?php echo $cfApiText('cfclient.api.alert.docs', '查看API文档', [], true); ?></a>
        </div>

        <?php if (!$canCreateApi): ?>
        <div class="alert alert-warning">
            <i class="fas fa-exclamation-triangle"></i>
            <?php echo $cfApiText('cfclient.api.warning.requirement', '您的配额不足，需要至少有 %1$s 个域名注册配额才能创建API密钥。', [sprintf('<strong>%s</strong>', $requireQuota)], false); ?>
            <br>
            <?php echo $cfApiText('cfclient.api.warning.current_quota', '当前注册额度：%s', [sprintf('<strong>%s</strong>', $totalQuota)], false); ?>
        </div>
        <?php endif; ?>

        <!-- 创建API密钥按钮 -->
        <?php if (count($apiKeys) < $maxApiKeys && $canCreateApi): ?>
        <div class="mb-3">
            <button type="button" class="btn btn-success" data-bs-toggle="modal" data-bs-target="#createApiKeyModal">
                <i class="fas fa-plus"></i> <?php echo $cfApiText('cfclient.api.button.create', '创建API密钥', [], true); ?>
            </button>
            <span class="text-muted ms-2">
                <?php echo $cfApiText('cfclient.api.stats.created', '已创建 %1$s / %2$s 个', [number_format(count($apiKeys)), number_format($maxApiKeys)], true); ?>
            </span>
        </div>
        <?php endif; ?>

        <!-- API密钥列表 -->
        <?php if (count($apiKeys) > 0): ?>
        <div class="table-responsive">
            <table class="table table-bordered table-hover">
                <thead class="table-light">
                    <tr>
                        <th><?php echo $cfApiText('cfclient.api.table.name', '密钥名称', [], true); ?></th>
                        <th>API Key</th>
                        <th><?php echo $cfApiText('cfclient.api.table.status', '状态', [], true); ?></th>
                        <th><?php echo $cfApiText('cfclient.api.table.requests', '请求次数', [], true); ?></th>
                        <th><?php echo $cfApiText('cfclient.api.table.last_used', '最后使用', [], true); ?></th>
                        <th><?php echo $cfApiText('cfclient.api.table.created_at', '创建时间', [], true); ?></th>
                        <th><?php echo $cfApiText('cfclient.api.table.actions', '操作', [], true); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($apiKeys as $key): ?>
                    <tr>
                        <td>
                            <strong><?php echo htmlspecialchars($key->key_name); ?></strong>
                        </td>
                        <td>
                            <code class="user-select-all"><?php echo htmlspecialchars($key->api_key); ?></code>
                            <button type="button" class="btn btn-sm btn-outline-secondary" onclick="copyToClipboard('<?php echo htmlspecialchars($key->api_key); ?>')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </td>
                        <td>
                            <?php if ($key->status === 'active'): ?>
                                <span class="badge bg-success"><?php echo $cfApiText('cfclient.api.status.active', '启用', [], true); ?></span>
                            <?php else: ?>
                                <span class="badge bg-danger"><?php echo $cfApiText('cfclient.api.status.disabled', '禁用', [], true); ?></span>
                            <?php endif; ?>
                        </td>
                        <td><?php echo number_format($key->request_count); ?></td>
                        <td><?php echo $key->last_used_at ? date('Y-m-d H:i', strtotime($key->last_used_at)) : $cfApiText('cfclient.api.table.never_used', '从未使用', [], true); ?></td>
                        <td><?php echo date('Y-m-d H:i', strtotime($key->created_at)); ?></td>
                        <td>
                            <?php if ($key->status === 'disabled'): ?>
                                <div class="text-danger small">
                                    <i class="fas fa-lock"></i> <?php echo $cfApiText('cfclient.api.status.disabled_by_admin', '已被管理员禁用', [], true); ?>
                                    <br>
                                    <button type="button" class="btn btn-sm btn-info mt-1" onclick="showApiKeyDetails(<?php echo $key->id; ?>)" title="<?php echo htmlspecialchars($cfApiText('cfclient.api.actions.view', '查看详情', [], true)); ?>">
                                        <i class="fas fa-eye"></i> <?php echo $cfApiText('cfclient.api.actions.view', '查看', [], true); ?>
                                    </button>
                                </div>
                            <?php else: ?>
                                <div class="btn-group btn-group-sm">
                                    <button type="button" class="btn btn-info" onclick="showApiKeyDetails(<?php echo $key->id; ?>)" title="<?php echo htmlspecialchars($cfApiText('cfclient.api.actions.view', '查看详情', [], true)); ?>">
                                        <i class="fas fa-eye"></i>
                                    </button>
                                    <button type="button" class="btn btn-warning" onclick="regenerateApiKey(<?php echo $key->id; ?>)" title="<?php echo htmlspecialchars($cfApiText('cfclient.api.actions.regenerate', '重新生成', [], true)); ?>">
                                        <i class="fas fa-sync"></i>
                                    </button>
                                    <button type="button" class="btn btn-danger" onclick="deleteApiKey(<?php echo $key->id; ?>)" title="<?php echo htmlspecialchars($cfApiText('cfclient.api.actions.delete', '删除', [], true)); ?>">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php else: ?>
        <div class="alert alert-secondary text-center">
            <i class="fas fa-key fa-3x mb-3 text-muted"></i>
            <p><?php echo $cfApiText('cfclient.api.empty.message', '您还没有创建任何API密钥', [], true); ?></p>
            <?php if ($canCreateApi): ?>
            <button type="button" class="btn btn-success" data-bs-toggle="modal" data-bs-target="#createApiKeyModal">
                <i class="fas fa-plus"></i> <?php echo $cfApiText('cfclient.api.button.create_now', '立即创建', [], true); ?>
            </button>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- API端点信息 -->
        <div class="mt-3">
            <h6><?php echo $cfApiText('cfclient.api.endpoint.title', 'API端点链接地址：', [], true); ?></h6>
<div class="input-group">
    <input type="text" class="form-control" id="apiEndpoint" readonly
        value="https://api005.dnshe.com/index.php?m=<?php echo $moduleSlug; ?>">
    <button class="btn btn-outline-secondary" type="button"
        onclick="copyToClipboard(document.getElementById('apiEndpoint').value)">
        <i class="fas fa-copy"></i> <?php echo $cfApiText('cfclient.api.actions.copy', '复制', [], true); ?>
 
                </button>
            </div>
        </div>
    </div>
</div>

<!-- 创建API密钥模态框 -->
<div class="modal fade" id="createApiKeyModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><?php echo $cfApiText('cfclient.api.modal.create.title', '创建API密钥', [], true); ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="createApiKeyForm">
                    <div class="mb-3">
                        <label class="form-label"><?php echo $cfApiText('cfclient.api.modal.create.name_label', '密钥名称 *', [], true); ?></label>
                        <input type="text" class="form-control" name="key_name" required 
                            placeholder="<?php echo htmlspecialchars($cfApiText('cfclient.api.modal.create.name_placeholder', '例如：生产环境、测试环境', [], true)); ?>">
                        <small class="form-text text-muted"><?php echo $cfApiText('cfclient.api.modal.create.name_hint', '用于识别此密钥的用途', [], true); ?></small>
                    </div>
                    <?php if ($ipWhitelistEnabled): ?>
                    <div class="mb-3">
                        <label class="form-label"><?php echo $cfApiText('cfclient.api.modal.create.ip_label', 'IP白名单（可选）', [], true); ?></label>
                        <textarea class="form-control" name="ip_whitelist" rows="3" 
                            placeholder="<?php echo htmlspecialchars($cfApiText('cfclient.api.modal.create.ip_placeholder', '192.168.1.1\n192.168.1.2\n留空则允许所有IP', [], true)); ?>"></textarea>
                        <small class="form-text text-muted"><?php echo $cfApiText('cfclient.api.modal.create.ip_hint', '每行一个IP地址，只有这些IP可以使用此密钥', [], true); ?></small>
                    </div>
                    <?php endif; ?>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><?php echo $cfApiText('cfclient.api.modal.button.cancel', '取消', [], true); ?></button>
                <button type="button" class="btn btn-primary" onclick="createApiKey()"><?php echo $cfApiText('cfclient.api.modal.button.create', '创建', [], true); ?></button>
            </div>
        </div>
    </div>
</div>

<!-- API密钥详情模态框 -->
<div class="modal fade" id="apiKeyDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><?php echo $cfApiText('cfclient.api.modal.detail.title', 'API密钥详情', [], true); ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="apiKeyDetailsContent">
                <!-- 动态加载内容 -->
            </div>
        </div>
    </div>
</div>

<!-- API新密钥显示模态框 -->
<div class="modal fade" id="newApiKeyModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header bg-success text-white">
                <h5 class="modal-title"><i class="fas fa-check-circle"></i> <?php echo $cfApiText('cfclient.api.modal.secret.title', 'API密钥创建成功', [], true); ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong><?php echo $cfApiText('cfclient.api.modal.secret.important', '重要：', [], true); ?></strong><?php echo $cfApiText('cfclient.api.modal.secret.notice', 'API Secret只会显示一次，请立即保存！', [], true); ?>
                </div>
                <div class="mb-3">
                    <label class="form-label"><strong>API Key：</strong></label>
                    <div class="input-group">
                        <input type="text" class="form-control" id="newApiKey" readonly>
                        <button class="btn btn-outline-secondary" onclick="copyToClipboard(document.getElementById('newApiKey').value)">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="mb-3">
                    <label class="form-label"><strong>API Secret：</strong></label>
                    <div class="input-group">
                        <input type="text" class="form-control" id="newApiSecret" readonly>
                        <button class="btn btn-outline-secondary" onclick="copyToClipboard(document.getElementById('newApiSecret').value)">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
                <div class="alert alert-info">
                  <strong><?php echo $cfApiText('cfclient.api.modal.secret.examples', '使用方法示例：', [], true); ?></strong>
<pre class="mb-0"><code>curl -X GET "https://api005.dnshe.com/index.php?m=<?php echo $moduleSlug; ?>&endpoint=subdomains&action=list" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "X-API-Secret: YOUR_API_SECRET"</code></pre>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-bs-dismiss="modal"><?php echo $cfApiText('cfclient.api.modal.secret.button_saved', '我已保存密钥', [], true); ?></button>
            </div>
        </div>
    </div>
</div>

<!-- API文档模态框 -->
<div class="modal fade" id="apiDocModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-book"></i> <?php echo $cfApiText('cfclient.api.docs.modal.title', 'API使用文档', [], true); ?></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" style="max-height: 70vh; overflow-y: auto;">
                <div class="mb-4">
                    <h6><?php echo $cfApiText('cfclient.api.docs.section1.title', '1. 认证方式', [], true); ?></h6>
                    <p><?php echo $cfApiText('cfclient.api.docs.section1.body', '所有API请求需要携带API Key和API Secret进行认证。', [], true); ?></p>
                    <p><strong><?php echo $cfApiText('cfclient.api.docs.section1.method_header', '方式1：HTTP Header（推荐使用）', [], true); ?></strong></p>
                    <pre><code>X-API-Key: cfsd_xxxxxxxxxx
X-API-Secret: yyyyyyyyyyyy</code></pre>
                    <p><strong><?php echo $cfApiText('cfclient.api.docs.section1.method_query', '方式2：URL参数（已废弃）', [], true); ?></strong></p>
                    <pre><code>?api_key=cfsd_xxxxxxxxxx&amp;api_secret=yyyyyyyyyyyy</code></pre>
                </div>

                <div class="mb-4">
                    <h6><?php echo $cfApiText('cfclient.api.docs.section2.title', '2. 可用端点', [], true); ?></h6>
                    <ul>
                        <li><code>subdomains</code> - <?php echo $cfApiText('cfclient.api.docs.section2.subdomains', '子域名管理', [], true); ?></li>
                        <li><code>dns_records</code> - <?php echo $cfApiText('cfclient.api.docs.section2.records', 'DNS记录管理', [], true); ?></li>
                        <li><code>keys</code> - <?php echo $cfApiText('cfclient.api.docs.section2.keys', 'API密钥管理', [], true); ?></li>
                        <li><code>quota</code> - <?php echo $cfApiText('cfclient.api.docs.section2.quota', '配额查询', [], true); ?></li>
                    </ul>
                </div>

                <div class="mb-4">
                 <h6><?php echo $cfApiText('cfclient.api.docs.section3.title', '3. 示例：列出子域名', [], true); ?></h6>
<pre><code>curl -X GET "https://api005.dnshe.com/index.php?m=<?php echo $moduleSlug; ?>&endpoint=subdomains&action=list" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy"
</code></pre>


                <div class="mb-4">
                    <h6><?php echo $cfApiText('cfclient.api.docs.section4.title', '4. 示例：注册子域名', [], true); ?></h6>
<pre><code>curl -X POST "https://api005.dnshe.com/index.php?m=<?php echo $moduleSlug; ?>&endpoint=subdomains&action=register" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "subdomain": "myapp",
    "rootdomain": "example.com"
  }'
</code></pre>

                </div>

                <div class="mb-4">
                    <h6><?php echo $cfApiText('cfclient.api.docs.section5.title', '5. 示例：创建DNS记录', [], true); ?></h6>
                 <pre><code>curl -X POST "https://api005.dnshe.com/index.php?m=<?php echo $moduleSlug; ?>&endpoint=dns_records&action=create" \
  -H "X-API-Key: cfsd_xxxxxxxxxx" \
  -H "X-API-Secret: yyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "subdomain_id": 1,
    "type": "A",
    "content": "192.168.1.1",
    "ttl": 600
  }'
</code></pre>

                </div>

              <div class="alert alert-info">
    <i class="fas fa-download"></i>
    <strong><?php echo $cfApiText('cfclient.api.docs.full.title', '完整API文档：', [], true); ?></strong>
    <a href="https://my.dnshe.com/knowledgebase/1/Free-Domain-Name-Service-API-User-Manual.html"
       target="_blank"
       class="alert-link">
        <?php echo $cfApiText('cfclient.api.docs.full.link', '点击查看完整文档', [], true); ?>
    </a>

                </div>
            </div>
        </div>
    </div>
</div>

<script>
// 复制到剪贴板
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        alert(cfLang('api.copySuccess', '已复制到剪贴板'));
    }, function(err) {
        console.error(cfLang('api.copyFailed', '复制失败：'), err);
    });
}

// 创建API密钥
function createApiKey() {
    const form = document.getElementById('createApiKeyForm');
    const formData = new FormData(form);
    
    // 转换为JSON
    const data = {};
    formData.forEach((value, key) => {
        data[key] = value;
    });
    
    // 如果有IP白名单，转换为逗号分隔
    if (data.ip_whitelist) {
        data.ip_whitelist = data.ip_whitelist.split('\n').map(ip => ip.trim()).filter(ip => ip).join(',');
    }
    
    fetch('?m=<?php echo $moduleSlugAttr; ?>&action=ajax_create_api_key', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': (window.CF_MOD_CSRF || '')
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // 关闭创建模态框
            const createModal = bootstrap.Modal.getInstance(document.getElementById('createApiKeyModal'));
            createModal.hide();
            
            // 显示新密钥
            document.getElementById('newApiKey').value = result.api_key;
            document.getElementById('newApiSecret').value = result.api_secret;
            const newKeyModal = new bootstrap.Modal(document.getElementById('newApiKeyModal'));
            newKeyModal.show();
            
            // 刷新页面
            newKeyModal._element.addEventListener('hidden.bs.modal', function() {
                location.reload();
            });
        } else {
            alert(cfLang('api.createFailedWithReason', '创建失败：') + result.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert(cfLang('api.createFailedGeneric', '创建失败，请重试'));
    });
}

// 查看API密钥详情
function showApiKeyDetails(keyId) {
    fetch('?m=<?php echo $moduleSlugAttr; ?>&action=ajax_get_api_key_details&key_id=' + keyId)
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                const key = result.key;
                const html = `
                    <dl class="row">
                        <dt class="col-sm-3"><?php echo $cfApiText('cfclient.api.modal.detail.name_label', '密钥名称：', [], true); ?></dt>
                        <dd class="col-sm-9">${key.key_name}</dd>
                        
                        <dt class="col-sm-3"><?php echo $cfApiText('cfclient.api.modal.detail.key_label', 'API Key：', [], true); ?></dt>
                        <dd class="col-sm-9"><code>${key.api_key}</code></dd>
                        
                        <dt class="col-sm-3"><?php echo $cfApiText('cfclient.api.modal.detail.status_label', '状态：', [], true); ?></dt>
                        <dd class="col-sm-9">
                            <span class="badge bg-${key.status === 'active' ? 'success' : 'danger'}">
                                ${key.status === 'active' ? cfLang('api.statusActive', '启用') : cfLang('api.statusDisabled', '禁用')}
                            </span>
                        </dd>
                        
                        <dt class="col-sm-3"><?php echo $cfApiText('cfclient.api.modal.detail.requests_label', '请求次数：', [], true); ?></dt>
                        <dd class="col-sm-9">${key.request_count.toLocaleString()}</dd>
                        
                        <dt class="col-sm-3"><?php echo $cfApiText('cfclient.api.modal.detail.last_used_label', '最后使用：', [], true); ?></dt>
                        <dd class="col-sm-9">${key.last_used_at || cfLang('api.neverUsed', '从未使用')}</dd>
                        
                        <dt class="col-sm-3"><?php echo $cfApiText('cfclient.api.modal.detail.created_label', '创建时间：', [], true); ?></dt>
                        <dd class="col-sm-9">${key.created_at}</dd>
                        
                        ${key.ip_whitelist ? `
                        <dt class="col-sm-3"><?php echo $cfApiText('cfclient.api.modal.detail.ip_label', 'IP白名单：', [], true); ?></dt>
                        <dd class="col-sm-9"><pre>${key.ip_whitelist.split(',').join('\n')}</pre></dd>
                        ` : ''}
                    </dl>
                `;
                document.getElementById('apiKeyDetailsContent').innerHTML = html;
                const modal = new bootstrap.Modal(document.getElementById('apiKeyDetailsModal'));
                modal.show();
            } else {
                alert(cfLang('api.detailsFailed', '获取详情失败：') + result.error);
            }
        });
}

// 重新生成API密钥
function regenerateApiKey(keyId) {
    if (!confirm(cfLang('api.regenerateConfirm', '重新生成后，旧的API Secret将立即失效，确定继续吗？'))) {
        return;
    }
    
    fetch('?m=<?php echo $moduleSlugAttr; ?>&action=ajax_regenerate_api_key', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': (window.CF_MOD_CSRF || '')
        },
        body: JSON.stringify({ key_id: keyId })
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            document.getElementById('newApiKey').value = result.api_key;
            document.getElementById('newApiSecret').value = result.api_secret;
            const modal = new bootstrap.Modal(document.getElementById('newApiKeyModal'));
            modal.show();
        } else {
            alert(cfLang('api.regenerateFailed', '重新生成失败：') + result.error);
        }
    });
}

// 删除API密钥
function deleteApiKey(keyId) {
    if (!confirm(cfLang('api.deleteConfirm', '确定要删除此API密钥吗？删除后无法恢复！'))) {
        return;
    }
    
    fetch('?m=<?php echo $moduleSlugAttr; ?>&action=ajax_delete_api_key', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': (window.CF_MOD_CSRF || '')
        },
        body: JSON.stringify({ key_id: keyId })
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            alert(cfLang('api.deleteSuccess', '删除成功'));
            location.reload();
        } else {
            alert(cfLang('api.deleteFailed', '删除失败：') + result.error);
        }
    });
}

document.addEventListener('DOMContentLoaded', function () {
    var collapseEl = document.getElementById('apiManagementBody');
    var iconEl = document.getElementById('apiManagementToggleIcon');
    var toggleBtn = document.getElementById('apiManagementToggleBtn');
    if (!collapseEl || !iconEl) {
        return;
    }
    var collapseInstance = null;
    if (typeof bootstrap !== 'undefined' && bootstrap.Collapse) {
        collapseInstance = bootstrap.Collapse.getOrCreateInstance(collapseEl, { toggle: false });
        if (collapseEl.classList.contains('show')) {
            collapseInstance.show();
        } else {
            collapseInstance.hide();
        }
    }
    if (toggleBtn && collapseInstance) {
        toggleBtn.addEventListener('click', function (event) {
            event.preventDefault();
            collapseInstance.toggle();
            var expanded = toggleBtn.getAttribute('aria-expanded') === 'true';
            toggleBtn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
        });
    }
    var updateIcon = function () {
        var isExpanded = collapseEl.classList.contains('show');
        if (iconEl) {
            if (isExpanded) {
                iconEl.classList.remove('fa-chevron-down');
                iconEl.classList.add('fa-chevron-up');
            } else {
                iconEl.classList.remove('fa-chevron-up');
                iconEl.classList.add('fa-chevron-down');
            }
        }
        if (toggleBtn) {
            toggleBtn.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
        }
    };
    collapseEl.addEventListener('shown.bs.collapse', updateIcon);
    collapseEl.addEventListener('hidden.bs.collapse', updateIcon);
    updateIcon();
});
</script>

<style>
#api-management-card code {
    background-color: #f8f9fa;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.9em;
}

#api-management-card pre {
    background-color: #f8f9fa;
    padding: 10px;
    border-radius: 5px;
    overflow-x: auto;
}

#api-management-card .user-select-all {
    user-select: all;
}
</style>

