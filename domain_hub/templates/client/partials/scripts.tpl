    <!-- Bootstrap JS -->
    <script src="<?php echo htmlspecialchars($cfmodAssetsBase . '/js/bootstrap.bundle.min.js', ENT_QUOTES); ?>"></script>

    <script>
        window.CF_CLIENT_LANG = <?php echo json_encode($cfClientJsLang ?? [], CFMOD_SAFE_JSON_FLAGS); ?>;
        window.CF_CLIENT_CONFIG = <?php echo json_encode([
            'disableNsManagement' => !empty($disableNsManagement),
            'domainGiftEnabled' => !empty($domainGiftEnabled),
            'quotaRedeemEnabled' => !empty($quotaRedeemEnabled),
            'moduleSlug' => $moduleSlug,
        ], CFMOD_SAFE_JSON_FLAGS); ?>;
    </script>
    <script src="<?php echo htmlspecialchars($cfmodAssetsBase . '/js/client.js?v=1', ENT_QUOTES); ?>"></script>

    <script>
        if (window.CFClient) {
            CFClient.setLangMap(window.CF_CLIENT_LANG || {});
            CFClient.setConfig(window.CF_CLIENT_CONFIG || {});
            CFClient.bootstrap();
        }

        const ROOT_LIMIT_MAP = <?php echo json_encode($rootLimitMap, CFMOD_SAFE_JSON_FLAGS); ?>;
        const rootLimitHint = document.getElementById('register_limit_hint');
const dnsUnlockFeatureEnabled = <?php echo !empty($dnsUnlockFeatureEnabled) ? 'true' : 'false'; ?>;
const dnsUnlockRequired = dnsUnlockFeatureEnabled && <?php echo !empty($dnsUnlockRequired) ? 'true' : 'false'; ?>;

        // 注册根域名后缀实时显示
        const rootSelect = document.getElementById('register_rootdomain');
        const rootSuffix = document.getElementById('register_root_suffix');
        const updateRootLimitHint = () => {
            if (!rootLimitHint || !rootSelect) {
                return;
            }
            const selected = (rootSelect.value || '').toLowerCase();
            const limit = ROOT_LIMIT_MAP[selected] || 0;
            if (limit > 0) {
                rootLimitHint.textContent = cfLangFormat('rootLimitHint', '该根域名每个账号最多注册 %s 个', limit);
                rootLimitHint.style.display = '';
            } else {
                rootLimitHint.textContent = '';
                rootLimitHint.style.display = 'none';
            }
        };
        if (rootSelect && rootSuffix) {
            const updateSuffix = () => {
                rootSuffix.textContent = rootSelect.value || cfLang('rootSuffixPlaceholder', '根域名');
                updateRootLimitHint();
            };
            rootSelect.addEventListener('change', updateSuffix);
            updateSuffix();
        } else {
            updateRootLimitHint();
        }

        // 表单验证
        document.getElementById('registerForm').addEventListener('submit', function(e) {
            if (<?php echo ($pauseFreeRegistration ? 'true' : 'false'); ?> || <?php echo ($maintenanceMode ? 'true' : 'false'); ?>) {
                e.preventDefault();
                var msg = <?php echo json_encode($registerBlockMessage, CFMOD_SAFE_JSON_FLAGS); ?>;
                alert(msg);
                return;
            }
            const subdomain = document.querySelector('input[name="subdomain"]');
            const rootdomain = document.querySelector('select[name="rootdomain"]');
            
            if (!subdomain.value.trim()) {
                e.preventDefault();
                alert(cfLang('registerEnterPrefix', '请输入域名前缀'));
                subdomain.focus();
                return;
            }
            
            if (!rootdomain.value) {
                e.preventDefault();
                alert(cfLang('registerSelectRoot', '请选择根域名'));
                rootdomain.focus();
                return;
            }
            
            const rawPrefix = subdomain.value.trim();
            if (rawPrefix.startsWith('.') || rawPrefix.startsWith('-') || rawPrefix.endsWith('.') || rawPrefix.endsWith('-')) {
                e.preventDefault();
                alert(cfLang('registerEdgeError', '域名前缀不能以 "." 或 "-" 开头或结尾'));
                subdomain.focus();
                return;
            }
            
            // 检查前缀是否包含禁止字符
            const forbidden = <?php echo json_encode($forbidden, CFMOD_SAFE_JSON_FLAGS); ?>;
            const prefix = rawPrefix.toLowerCase();
            if (forbidden.includes(prefix)) {
                e.preventDefault();
                alert(cfLang('registerForbiddenPrefix', '该前缀被禁止使用，请选择其他前缀'));
                subdomain.focus();
                return;
            }
        });
        
        // DNS设置模态框 - VPN检测由后端处理（仅NS记录需要检测）
        function showDnsForm(subdomainId, subdomainName, isUpdate, recordId = '', recordName = '', recordType = '', recordContent = '') {
            document.getElementById('dns_subdomain_id').value = subdomainId;
            document.getElementById('dns_subdomain_name').value = subdomainName;
            document.getElementById('dns_record_suffix').textContent = subdomainName;
            document.getElementById('dns_record_name').value = recordName || '';
            document.getElementById('dns_record_id').value = recordId;
            document.getElementById('dns_action').value = isUpdate ? 'update_dns' : 'create_dns';
            const lineSel = document.querySelector('select[name="line"]');
if (lineSel) lineSel.value = 'default';
const priorityInput = document.querySelector('input[name="record_priority"]');
const weightInput = document.querySelector('input[name="record_weight"]');
const portInput = document.querySelector('input[name="record_port"]');
const targetInput = document.querySelector('input[name="record_target"]');
const contentInput = document.querySelector('input[name="record_content"]');
if (priorityInput) priorityInput.value = '10';
if (weightInput) weightInput.value = '0';
if (portInput) portInput.value = '1';
if (targetInput) targetInput.value = '';
if (contentInput) contentInput.value = '';
// 如果是更新模式，填充现有数据
if (isUpdate && recordType) {
const typeSelect = document.querySelector('select[name="record_type"]');
if (typeSelect) {
typeSelect.value = recordType;
// 触发change事件以显示/隐藏相应字段
typeSelect.dispatchEvent(new Event('change'));
}
if (recordType === 'CAA' && recordContent) {
// 解析CAA记录内容：格式为 "flag tag "value""
const caaMatch = recordContent.match(/^(\d+)\s+(\w+)\s+"([^"]*)"$/);
if (caaMatch) {
const flag = caaMatch[1];
const tag = caaMatch[2];
const value = caaMatch[3];
const flagSelect = document.querySelector('select[name="caa_flag"]');
const tagSelect = document.querySelector('select[name="caa_tag"]');
const valueInput = document.querySelector('input[name="caa_value"]');
if (flagSelect) flagSelect.value = flag;
if (tagSelect) tagSelect.value = tag;
if (valueInput) valueInput.value = value;
}
} else if (recordType === 'SRV' && recordContent) {
const parts = recordContent.trim().split(/\s+/);
if (parts.length >= 4) {
if (priorityInput) priorityInput.value = parts[0];
if (weightInput) weightInput.value = parts[1];
if (portInput) portInput.value = parts[2];
if (targetInput) targetInput.value = parts.slice(3).join(' ');
}
if (contentInput) contentInput.value = recordContent;
} else {
if (contentInput) contentInput.value = recordContent;
}
} else {
if (contentInput) contentInput.value = '';
const caaFlag = document.querySelector('select[name="caa_flag"]');
const caaTag = document.querySelector('select[name="caa_tag"]');
const caaValue = document.querySelector('input[name="caa_value"]');
if (caaFlag) caaFlag.value = '0';
if (caaTag) caaTag.value = 'issue';
if (caaValue) caaValue.value = '';
if (priorityInput) priorityInput.value = '10';
if (weightInput) weightInput.value = '0';
if (portInput) portInput.value = '1';
if (targetInput) targetInput.value = '';
}
// 显示模态框
    const modal = new bootstrap.Modal(document.getElementById('dnsModal'));
    modal.show();
}

function showDnsUnlockModal() {
    var modalEl = document.getElementById('dnsUnlockModal');
    if (!modalEl) { return; }
    var instance = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
    instance.show();
}
window.showDnsUnlockModal = showDnsUnlockModal;

function copyDnsUnlockCode() {
    var input = document.getElementById('dnsUnlockCodeText');
    if (!input) { return; }
    var value = input.value || '';
    if (!value) { return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(function(){
            alert(cfLang('dnsUnlockCopySuccess', '解锁码已复制'));
        }).catch(function(){
            alert(cfLang('dnsUnlockCopyFailed', '复制失败，请手动复制'));
        });
    } else {
        try {
            input.select();
            document.execCommand('copy');
            alert(cfLang('dnsUnlockCopySuccess', '解锁码已复制'));
        } catch (err) {
            alert(cfLang('dnsUnlockCopyFailed', '复制失败，请手动复制'));
        }
    }
}
window.copyDnsUnlockCode = copyDnsUnlockCode;

// VPN检测配置
const vpnDetectionDnsEnabled = <?php echo (!empty($vpnDetectionDnsEnabled) ? 'true' : 'false'); ?>;

// VPN检测AJAX函数
function checkVpnBeforeAction(callback) {
    if (!vpnDetectionDnsEnabled) {
        callback(false);
        return;
    }
    var moduleSlug = (window.CF_CLIENT_CONFIG && window.CF_CLIENT_CONFIG.moduleSlug) || 'domain_hub';
    var ajaxUrl = 'index.php?m=' + encodeURIComponent(moduleSlug) + '&action=ajax_check_vpn';
    fetch(ajaxUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.CF_MOD_CSRF || ''
        }
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
        if (data.blocked) {
            alert(data.message || cfLang('dnsVpnBlocked', '检测到您正在使用VPN或代理，请关闭后再进行DNS操作。'));
            callback(true);
        } else {
            callback(false);
        }
    })
    .catch(function(err) {
        // 网络错误时不阻止操作
        console.error('VPN check failed:', err);
        callback(false);
    });
}

// NS 批量替换：弹窗打开/归一化
function showNsModal(subId, name) {
    if (dnsUnlockFeatureEnabled && dnsUnlockRequired) {
        alert(cfLang('dnsUnlockRequired', '请先完成 DNS 解锁后再操作。'));
        showDnsUnlockModal();
        return;
    }
    if (<?php echo ($disableNsManagement ? 'true' : 'false'); ?>) {
        alert(cfLang('nsManagementDisabled', '已禁止设置 DNS 服务器（NS）。'));
        return;
    }

    // VPN检测
    checkVpnBeforeAction(function(blocked) {
        if (blocked) {
            return;
        }
        document.getElementById('ns_subdomain_id').value = subId;
        document.getElementById('ns_subdomain_name').value = name;
        // 预填当前NS
        const current = (window.__nsBySubId && window.__nsBySubId[subId]) ? window.__nsBySubId[subId] : [];
        document.getElementById('ns_current').textContent = current.length ? current.join(', ') : cfLang('nsNotConfigured', '（未设置）');
        document.getElementById('ns_lines').value = current.join('\n');
        const modal = new bootstrap.Modal(document.getElementById('nsModal'));
        modal.show();
    });
}

document.getElementById('nsForm')?.addEventListener('submit', function(e){
            if (dnsUnlockFeatureEnabled && dnsUnlockRequired) {
                e.preventDefault();
                alert(cfLang('dnsUnlockRequired', '请先完成 DNS 解锁后再操作。'));
                showDnsUnlockModal();
                return;
            }
            const ta = document.getElementById('ns_lines');
            if (!ta) return;
            const cleaned = ta.value.split('\n')
                .map(x => x.trim().toLowerCase())
                .filter(x => x)
                .filter((x, i, arr) => arr.indexOf(x) === i);
            if (cleaned.length === 0) {
                e.preventDefault();
                alert(cfLang('nsAtLeastOne', '请至少输入一个 NS 服务器'));
                return;
            }
            // 简单校验域名格式
            const domainRegex = /^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+\.?$/;
            for (const ns of cleaned) {
                if (!domainRegex.test(ns)) {
                    e.preventDefault();
                    alert(cfLangFormat('nsInvalidFormat', 'NS 格式不正确: %s', ns));
                    return;
                }
            }
            // 防连点：提交后禁用按钮
            try { const btn = this.querySelector('button[type="submit"]'); if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + cfLang('buttonSubmitting', '提交中...'); } } catch(err) {}
            ta.value = cleaned.join('\n');
        });

        // DNS表单验证
        document.getElementById('dnsForm').addEventListener('submit', function(e) {
const recordType = document.querySelector('select[name="record_type"]');
const recordContent = document.querySelector('input[name="record_content"]');
const recordNameInput = document.getElementById('dns_record_name');
const type = recordType.value;
if (dnsUnlockFeatureEnabled && dnsUnlockRequired && recordType && recordType.value.toUpperCase() === 'NS') {
    e.preventDefault();
    alert(cfLang('dnsUnlockRequired', '请先完成 DNS 解锁后再操作。'));
    showDnsUnlockModal();
    return;
}
if (recordNameInput) {
let recordNameValue = recordNameInput.value.trim();
if (recordNameValue === '') {
recordNameValue = '@';
}
if (recordNameValue !== '@') {
if (recordNameValue.startsWith('.') || recordNameValue.startsWith('-') || recordNameValue.endsWith('.') || recordNameValue.endsWith('-')) {
e.preventDefault();
alert(cfLang('dnsNameEdgeError', '解析名称不能以点或连字符开头或结尾'));
recordNameInput.focus();
return;
}
if (recordNameValue.includes('..')) {
e.preventDefault();
alert(cfLang('dnsNameDoubleDot', '解析名称不能包含连续的点'));
recordNameInput.focus();
return;
}
const segments = recordNameValue.split('.');
for (const segment of segments) {
if (!segment) {
e.preventDefault();
alert(cfLang('dnsNameEmptyLabel', '解析名称不能包含空的标签片段'));
recordNameInput.focus();
return;
}
if (segment.startsWith('-') || segment.endsWith('-')) {
e.preventDefault();
alert(cfLang('dnsNameLabelEdge', '解析名称中的每个标签都不能以连字符开头或结尾'));
recordNameInput.focus();
return;
}
}
}
}
if (type === 'SRV') {
const priorityInput = document.querySelector('input[name="record_priority"]');
const weightInput = document.querySelector('input[name="record_weight"]');
const portInput = document.querySelector('input[name="record_port"]');
const targetInput = document.querySelector('input[name="record_target"]');
let priority = parseInt(priorityInput ? priorityInput.value : '0', 10);
let weight = parseInt(weightInput ? weightInput.value : '0', 10);
let port = parseInt(portInput ? portInput.value : '0', 10);
let target = targetInput ? targetInput.value.trim() : '';
if (!Number.isFinite(priority) || priority < 0 || priority > 65535) {
e.preventDefault();
alert(cfLang('srvPriorityInvalid', 'SRV记录的优先级必须在0-65535之间'));
if (priorityInput) priorityInput.focus();
return;
}
if (!Number.isFinite(weight) || weight < 0 || weight > 65535) {
e.preventDefault();
alert(cfLang('srvWeightInvalid', 'SRV记录的权重必须在0-65535之间'));
if (weightInput) weightInput.focus();
return;
}
if (!Number.isFinite(port) || port < 1 || port > 65535) {
e.preventDefault();
alert(cfLang('srvPortInvalid', 'SRV记录的端口必须在1-65535之间'));
if (portInput) portInput.focus();
return;
}
if (target.endsWith('.')) {
target = target.slice(0, -1);
}
if (!target) {
e.preventDefault();
alert(cfLang('srvTargetRequired', 'SRV记录的目标地址不能为空'));
if (targetInput) targetInput.focus();
return;
}
if (!isValidDomain(target)) {
e.preventDefault();
alert(cfLang('srvTargetInvalid', '请输入有效的SRV目标主机名'));
if (targetInput) targetInput.focus();
return;
}
recordContent.value = `${priority} ${weight} ${port} ${target}`;
if (priorityInput) priorityInput.value = String(priority);
if (weightInput) weightInput.value = String(weight);
if (portInput) portInput.value = String(port);
if (targetInput) targetInput.value = target;
}
if (!recordContent.value.trim()) {
e.preventDefault();
alert(cfLang('recordContentRequired', '请输入记录内容'));
recordContent.focus();
return;
}
const content = recordContent.value.trim();
// 根据记录类型验证内容格式
// NS/MX/SRV/TXT不支持代理，自动取消勾选
if (['NS','MX','SRV','TXT'].includes(type)) {
const proxied = document.getElementById('dns_proxied');
if (proxied) proxied.checked = false;
}
if (type === 'A' && !isValidIPv4(content)) {
e.preventDefault();
alert(cfLang('ipv4Invalid', '请输入有效的IPv4地址'));
recordContent.focus();
return;
}
if (type === 'AAAA' && !isValidIPv6(content)) {
e.preventDefault();
alert(cfLang('ipv6Invalid', '请输入有效的IPv6地址'));
recordContent.focus();
return;
}
if ((type === 'CNAME' || type === 'NS') && !isValidDomain(content)) {
e.preventDefault();
alert(cfLang('domainInvalid', '请输入有效的域名'));
recordContent.focus();
return;
}
// 防连点：提交后禁用按钮
try { const btn = this.querySelector('button[type="submit"]'); if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + cfLang('buttonSaving', '保存中...'); } } catch(err) {}
});
// 动态显示/隐藏字段
        document.querySelector('select[name="record_type"]').addEventListener('change', function() {
const recordType = this.value;
const priorityField = document.getElementById('priority_field');
const proxiedCheckbox = document.getElementById('dns_proxied');
const recordContentField = document.getElementById('record_content_field');
const caaFields = document.getElementById('caa_fields');
const srvFields = document.getElementById('srv_fields');
const recordContentInput = document.querySelector('input[name="record_content"]');
// 显示/隐藏优先级字段
if (priorityField) {
priorityField.style.display = ['MX', 'SRV'].includes(recordType) ? '' : 'none';
}
// 根据不同类型切换字段显示
if (recordType === 'CAA') {
if (recordContentField) recordContentField.style.display = 'none';
if (caaFields) caaFields.style.display = '';
if (srvFields) srvFields.style.display = 'none';
if (recordContentInput) recordContentInput.removeAttribute('required');
} else if (recordType === 'SRV') {
if (recordContentField) recordContentField.style.display = 'none';
if (caaFields) caaFields.style.display = 'none';
if (srvFields) srvFields.style.display = '';
const priorityInput = document.querySelector('input[name="record_priority"]');
if (priorityInput && (priorityInput.value === '' || priorityInput.value === '10')) {
priorityInput.value = '0';
}
const weightInput = document.querySelector('input[name="record_weight"]');
const portInput = document.querySelector('input[name="record_port"]');
const targetInput = document.querySelector('input[name="record_target"]');
if (weightInput && weightInput.value === '') { weightInput.value = '0'; }
if (portInput && (portInput.value === '' || portInput.value === '0')) { portInput.value = '1'; }
if (recordContentInput) {
recordContentInput.removeAttribute('required');
recordContentInput.value = '';
}
} else {
if (recordContentField) recordContentField.style.display = '';
if (caaFields) caaFields.style.display = 'none';
if (srvFields) srvFields.style.display = 'none';
if (recordContentInput) recordContentInput.setAttribute('required', 'required');
}
// 根据记录类型控制CDN代理
if (proxiedCheckbox) {
if (['NS', 'MX', 'TXT', 'SRV', 'CAA'].includes(recordType)) {
proxiedCheckbox.checked = false;
proxiedCheckbox.disabled = true;
} else {
proxiedCheckbox.disabled = false;
}
}
});
// 验证函数
        function isValidIPv4(ip) {
            const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return ipv4Regex.test(ip);
        }
        
        function isValidIPv6(ip) {
            const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
            return ipv6Regex.test(ip);
        }
        
        function isValidDomain(domain) {
            const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
            return domainRegex.test(domain);
        }
        
        // 自动关闭提示（保留封禁横幅不消失）
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert.alert-dismissible');
            alerts.forEach(alert => {
                if (alert.id === 'banAlert') return;
                if (alert.id === 'prize-display-section') return;
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            });
        }, 8000);
        
        // 页面加载完成后初始化
        document.addEventListener('DOMContentLoaded', function() {
            // 初始化Bootstrap工具提示
            var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });

            // 若后端注册失败，保持注册弹窗并在弹窗内显示错误
            var regErr = <?php echo json_encode($registerError ?? '', CFMOD_SAFE_JSON_FLAGS); ?>;
            if (regErr) {
                var modalEl = document.getElementById('registerModal');
                if (modalEl) {
                    var alertEl = document.getElementById('registerErrorAlert');
                    if (alertEl) { alertEl.textContent = regErr; alertEl.style.display = 'block'; }
                    var m = new bootstrap.Modal(modalEl);
                    m.show();
                }
            }

            var dnsForParam = <?php echo intval($dnsPageFor); ?>;
            if (dnsForParam > 0) {
                var detailsRow = document.getElementById('details_' + dnsForParam);
                if (detailsRow) {
                    detailsRow.style.display = 'table-row';
                    setTimeout(function(){
                        try { detailsRow.scrollIntoView({behavior: 'smooth', block: 'start'}); } catch (err) {}
                    }, 150);
                }
            }
        });

        <?php if ($quotaRedeemEnabled): ?>
        (function(){
            if (!window.bootstrap) { return; }
            var modalEl = document.getElementById('quotaRedeemModal');
            if (!modalEl) { return; }
            var moduleSlug = (window.CF_CLIENT_CONFIG && window.CF_CLIENT_CONFIG.moduleSlug) || 'domain_hub';
            var ajaxBase = 'index.php?m=' + encodeURIComponent(moduleSlug);
            var bsModal = new bootstrap.Modal(modalEl);
            var form = document.getElementById('quotaRedeemForm');
            var codeInput = document.getElementById('redeemCodeInput');
            var submitBtn = document.getElementById('redeemSubmitButton');
            var submitBtnLabel = submitBtn ? submitBtn.innerHTML : '';
            var alertBox = document.getElementById('redeemAlertPlaceholder');
            var historyBody = document.getElementById('redeemHistoryBody');
            var paginationEl = document.getElementById('redeemHistoryPagination');
            var state = { historyLoaded: false, loading: false };

            function buildUrl(action) {
                return ajaxBase + (ajaxBase.indexOf('?') === -1 ? '?' : '&') + 'action=' + encodeURIComponent(action);
            }

            function sendRedeem(action, payload) {
                return fetch(buildUrl(action), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.CF_MOD_CSRF || ''
                    },
                    body: JSON.stringify(payload || {})
                }).then(function(res){ return res.json(); });
            }

            function showRedeemAlert(type, message) {
                if (!alertBox) { return; }
                alertBox.innerHTML = '<div class="alert alert-' + type + ' alert-dismissible fade show" role="alert">' +
                    message +
                    '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>' +
                    '</div>';
            }

            window.openQuotaRedeemModal = function(){
                bsModal.show();
                if (!state.historyLoaded) {
                    loadHistory(1);
                }
            };

            if (form) {
                form.addEventListener('submit', function(e){
                    e.preventDefault();
                    if (state.loading) { return; }
                    var code = codeInput ? codeInput.value.trim() : '';
                    if (!code) {
                        showRedeemAlert('warning', cfLang('redeemEnterCode', '请输入兑换码'));
                        if (codeInput) { codeInput.focus(); }
                        return;
                    }
                    state.loading = true;
                    if (submitBtn) {
                        submitBtn.disabled = true;
                        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + cfLang('buttonSubmitting', '提交中...');
                    }
                    sendRedeem('ajax_redeem_quota_code', { code: code }).then(function(res){
                        if (res && res.success) {
                            showRedeemAlert('success', cfLang('redeemSuccess', '兑换成功，正在刷新页面'));
                            setTimeout(function(){ window.location.reload(); }, 1200);
                        } else {
                            var errMsg = (res && res.error) ? res.error : '';
                            var template = cfLang('redeemFailed', '兑换失败：%s');
                            showRedeemAlert('danger', template.replace('%s', errMsg));
                        }
                    }).catch(function(){
                        showRedeemAlert('danger', cfLang('networkError', '网络异常，请稍后再试'));
                    }).finally(function(){
                        state.loading = false;
                        if (submitBtn) {
                            submitBtn.disabled = false;
                            submitBtn.innerHTML = submitBtnLabel || '<i class="fas fa-check-circle"></i>';
                        }
                    });
                });
            }

            function renderHistory(rows) {
                if (!historyBody) { return; }
                if (!rows || !rows.length) {
                    historyBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-3">' + cfLang('redeemHistoryEmpty', '暂无兑换记录') + '</td></tr>';
                    return;
                }
                var statusMap = {
                    success: { label: cfLang('cfclient.redeem.status.success', '成功'), className: 'success' },
                    failed: { label: cfLang('cfclient.redeem.status.failed', '失败'), className: 'danger' }
                };
                historyBody.innerHTML = rows.map(function(item){
                    var info = statusMap[item.status] || { label: item.status || '-', className: 'secondary' };
                    var amount = typeof item.grant_amount !== 'undefined' ? ('+' + item.grant_amount) : '-';
                    var timeText = item.created_at || '-';
                    return '<tr>' +
                        '<td><code>' + (item.code || '') + '</code></td>' +
                        '<td>' + amount + '</td>' +
                        '<td>' + timeText + '</td>' +
                        '<td><span class="badge bg-' + info.className + '">' + info.label + '</span></td>' +
                        '</tr>';
                }).join('');
            }

            function renderPagination(meta) {
                if (!paginationEl) { return; }
                var page = meta.page || 1;
                var total = meta.total_pages || 1;
                if (total <= 1) {
                    paginationEl.innerHTML = '';
                    return;
                }
                var html = '';
                html += '<li class="page-item ' + (page === 1 ? 'disabled' : '') + '"><a class="page-link" data-redeem-page="' + Math.max(1, page - 1) + '" href="#">&laquo;</a></li>';
                for (var i = 1; i <= total; i++) {
                    html += '<li class="page-item ' + (i === page ? 'active' : '') + '"><a class="page-link" data-redeem-page="' + i + '" href="#">' + i + '</a></li>';
                }
                html += '<li class="page-item ' + (page === total ? 'disabled' : '') + '"><a class="page-link" data-redeem-page="' + Math.min(total, page + 1) + '" href="#">&raquo;</a></li>';
                paginationEl.innerHTML = html;
                paginationEl.querySelectorAll('[data-redeem-page]').forEach(function(link){
                    link.addEventListener('click', function(evt){
                        evt.preventDefault();
                        var target = parseInt(link.getAttribute('data-redeem-page'), 10);
                        if (!isNaN(target)) {
                            loadHistory(target);
                        }
                    });
                });
            }

            function loadHistory(page) {
                sendRedeem('ajax_list_quota_redeems', { page: page }).then(function(res){
                    if (res && res.success) {
                        renderHistory(res.data || []);
                        renderPagination(res.pagination || {});
                        state.historyLoaded = true;
                    } else {
                        showRedeemAlert('danger', (res && res.error) ? res.error : cfLang('redeemHistoryLoadFailed', '加载兑换记录失败'));
                    }
                }).catch(function(){
                    showRedeemAlert('danger', cfLang('redeemHistoryLoadFailed', '加载兑换记录失败'));
                });
            }
        })();
        <?php endif; ?>

        <?php if ($domainGiftEnabled): ?>
        (function(){
            if (!window.bootstrap) { return; }
            const modalEl = document.getElementById('domainGiftModal');
            if (!modalEl) { return; }
            const ajaxBase = <?php echo json_encode('index.php?m=' . $moduleSlug, CFMOD_SAFE_JSON_FLAGS); ?>;
            const state = {
                subdomains: <?php echo json_encode($domainGiftSubdomains, CFMOD_SAFE_JSON_FLAGS); ?>,
                historyLoaded: false
            };
            const bsModal = new bootstrap.Modal(modalEl);
            const domainSelect = document.getElementById('giftDomainSelect');
            function renderDomainOptions() {
                if (!domainSelect) { return; }
                domainSelect.innerHTML = '<option value="">' + cfLang('giftSelectDomain', '请选择域名') + '</option>';
                if (!state.subdomains.length) {
                    const opt = document.createElement('option');
                    opt.value = '';
                    opt.disabled = true;
                    opt.textContent = cfLang('giftNoDomains', '暂无可用域名');
                    domainSelect.appendChild(opt);
                    return;
                }
                state.subdomains.forEach(function(item){
                    const opt = document.createElement('option');
                    opt.value = item.id || '';
                    opt.textContent = item.fullDomain || '';
                    if (item.locked) {
                        opt.disabled = true;
                        opt.textContent += cfLang('giftInTransfer', '（转赠中）');
                    }
                    domainSelect.appendChild(opt);
                });
            }
            renderDomainOptions();
            function buildUrl(action) {
                return ajaxBase + (ajaxBase.indexOf('?') === -1 ? '?' : '&') + 'action=' + encodeURIComponent(action);
            }
            function giftFetch(action, payload){
                return fetch(buildUrl(action), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': window.CF_MOD_CSRF || ''
                    },
                    body: JSON.stringify(payload || {})
                }).then(function(res){ return res.json(); });
            }
            function giftAlert(type, message) {
                const placeholder = document.getElementById('giftAlertPlaceholder');
                if (!placeholder) { return; }
                placeholder.innerHTML = '<div class="alert alert-' + type + ' alert-dismissible fade show" role="alert">' +
                    message +
                    '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>' +
                    '</div>';
            }
            window.openDomainGiftModal = function(tab){
                renderDomainOptions();
                if (tab) {
                    var trigger = document.querySelector('[data-bs-target="#gift-' + tab + '-pane"]');
                    if (trigger) {
                        new bootstrap.Tab(trigger).show();
                    }
                }
                bsModal.show();
            };
            const generateBtn = document.getElementById('generateGiftButton');
            if (generateBtn) {
                generateBtn.addEventListener('click', function(){
                    if (!domainSelect) { return; }
                    const subId = parseInt(domainSelect.value, 10);
                    if (!subId) {
                        giftAlert('warning', cfLang('giftSelectRequired', '请选择要转赠的域名'));
                        return;
                    }
                    generateBtn.disabled = true;
                    giftFetch('ajax_initiate_domain_gift', { subdomain_id: subId }).then(function(res){
                        if (res && res.success) {
                            giftAlert('success', cfLang('giftGenerateSuccess', '接收码已生成，请尽快分享给受赠人。'));
                            const box = document.getElementById('giftCodeResult');
                            if (box) {
                                box.classList.remove('d-none');
                                document.getElementById('giftCodeValue').textContent = res.data?.code || '';
                                document.getElementById('giftCodeExpire').textContent = res.data?.expires_at || '';
                                document.getElementById('giftCodeDomain').textContent = res.data?.full_domain || '';
                            }
                            state.subdomains = state.subdomains.map(function(item){
                                if (parseInt(item.id, 10) === subId) {
                                    item.locked = true;
                                }
                                return item;
                            });
                            renderDomainOptions();
                        } else {
                            giftAlert('danger', (res && res.error) ? res.error : cfLang('giftGenerateFailed', '生成接收码失败，请稍后再试'));
                        }
                    }).catch(function(){
                        giftAlert('danger', cfLang('networkError', '网络异常，请稍后再试'));
                    }).finally(function(){
                        generateBtn.disabled = false;
                    });
                });
            }
            const copyBtn = document.getElementById('giftCopyButton');
            if (copyBtn) {
                copyBtn.addEventListener('click', function(){
                    const code = document.getElementById('giftCodeValue')?.textContent || '';
                    if (!code) {
                        giftAlert('warning', cfLang('giftCopyEmpty', '暂无可复制的接收码'));
                        return;
                    }
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(code).then(function(){
                            giftAlert('success', cfLang('giftCopySuccess', '接收码已复制'));
                        }).catch(function(){
                            giftAlert('warning', cfLang('giftCopyFailed', '复制失败，请手动复制'));
                        });
                    } else {
                        copyText(code);
                        giftAlert('success', cfLang('giftCopySuccess', '接收码已复制'));
                    }
                });
            }
            const acceptBtn = document.getElementById('acceptGiftButton');
            if (acceptBtn) {
                acceptBtn.addEventListener('click', function(){
                    const input = document.getElementById('giftAcceptCode');
                    const code = (input ? input.value : '').trim();
                    if (!code) {
                        giftAlert('warning', cfLang('giftEnterCode', '请输入接收码'));
                        return;
                    }
                    acceptBtn.disabled = true;
                    giftFetch('ajax_accept_domain_gift', { code: code }).then(function(res){
                        if (res && res.success) {
                            giftAlert('success', cfLang('giftAcceptSuccess', '领取成功，即将刷新页面'));
                            setTimeout(function(){ window.location.reload(); }, 1500);
                        } else {
                            giftAlert('danger', (res && res.error) ? res.error : cfLang('giftAcceptFailed', '领取失败，请稍后再试'));
                        }
                    }).catch(function(){
                        giftAlert('danger', cfLang('networkError', '网络异常，请稍后再试'));
                    }).finally(function(){ acceptBtn.disabled = false; });
                });
            }
            const historyBody = document.getElementById('giftHistoryTableBody');
            const paginationEl = document.getElementById('giftHistoryPagination');
            const historyTab = document.getElementById('gift-history-tab');
            if (historyTab) {
                historyTab.addEventListener('shown.bs.tab', function(){
                    if (!state.historyLoaded) {
                        loadHistory(1);
                    }
                });
            }
            function renderHistory(rows) {
                if (!historyBody) { return; }
                if (!rows || !rows.length) {
                    historyBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">' + cfLang('giftHistoryEmpty', '暂无转赠记录') + '</td></tr>';
                    return;
                }
                const statusMap = {
                    pending: {label: cfLang('giftStatusPending', '进行中'), className: 'warning'},
                    accepted: {label: cfLang('giftStatusAccepted', '已完成'), className: 'success'},
                    cancelled: {label: cfLang('giftStatusCancelled', '已取消'), className: 'secondary'},
                    expired: {label: cfLang('giftStatusExpired', '已过期'), className: 'danger'}
                };
                historyBody.innerHTML = rows.map(function(item){
                    const info = statusMap[item.status] || {label: item.status, className: 'secondary'};
                    const timeline = [];
                    if (item.created_at) timeline.push(cfLang('giftTimelineStart', '发起：') + item.created_at);
                    if (item.completed_at) timeline.push(cfLang('giftTimelineCompleted', '完成：') + item.completed_at);
                    else if (item.cancelled_at) timeline.push(cfLang('giftTimelineEnded', '结束：') + item.cancelled_at);
                    const codeCell = item.status === 'pending'
                        ? '<span class="badge bg-light text-dark">' + (item.code || '') + '</span>'
                        : '<span class="text-muted">' + (item.code || '') + '</span>';
                    const roleLabel = item.role === 'received' ? cfLang('giftRoleReceived', '（接收）') : cfLang('giftRoleSent', '（转赠）');
                    const canCancel = item.role === 'sent' && item.status === 'pending';
                    const actionCell = canCancel
                        ? '<button class="btn btn-sm btn-outline-danger" data-gift-cancel="' + item.id + '"><i class="fas fa-ban"></i> ' + cfLang('giftActionCancel', '取消') + '</button>'
                        : '-';
                    return '<tr>' +
                        '<td>' + roleLabel + (item.full_domain || '-') + '</td>' +
                        '<td>' + codeCell + '</td>' +
                        '<td><span class="badge bg-' + info.className + '">' + info.label + '</span></td>' +
                        '<td class="small text-muted">' + (timeline.join('<br>') || '-') + '</td>' +
                        '<td class="text-end">' + actionCell + '</td>' +
                        '</tr>';
                }).join('');
                historyBody.querySelectorAll('[data-gift-cancel]').forEach(function(btn){
                    btn.addEventListener('click', function(){
                        const giftId = parseInt(btn.getAttribute('data-gift-cancel'), 10);
                        if (!giftId) { return; }
                        btn.disabled = true;
                        giftFetch('ajax_cancel_domain_gift', { gift_id: giftId }).then(function(res){
                            if (res && res.success) {
                                giftAlert('success', cfLang('giftCancelSuccess', '已取消转赠，即将刷新页面'));
                                setTimeout(function(){ window.location.reload(); }, 1200);
                            } else {
                                giftAlert('danger', (res && res.error) ? res.error : cfLang('giftCancelFailed', '取消失败，请稍后再试'));
                            }
                        }).catch(function(){
                            giftAlert('danger', cfLang('networkError', '网络异常，请稍后再试'));
                        }).finally(function(){ btn.disabled = false; });
                    });
                });
            }
            function renderPagination(meta) {
                if (!paginationEl) { return; }
                const page = meta.page || 1;
                const total = meta.total_pages || 1;
                if (total <= 1) {
                    paginationEl.innerHTML = '';
                    return;
                }
                let html = '';
                html += '<li class="page-item ' + (page === 1 ? 'disabled' : '') + '"><a class="page-link" data-gift-page="' + Math.max(1, page - 1) + '" href="#">&laquo;</a></li>';
                for (let i = 1; i <= total; i++) {
                    html += '<li class="page-item ' + (i === page ? 'active' : '') + '"><a class="page-link" data-gift-page="' + i + '" href="#">' + i + '</a></li>';
                }
                html += '<li class="page-item ' + (page === total ? 'disabled' : '') + '"><a class="page-link" data-gift-page="' + Math.min(total, page + 1) + '" href="#">&raquo;</a></li>';
                paginationEl.innerHTML = html;
                paginationEl.querySelectorAll('[data-gift-page]').forEach(function(link){
                    link.addEventListener('click', function(e){
                        e.preventDefault();
                        const target = parseInt(link.getAttribute('data-gift-page'), 10);
                        if (!isNaN(target)) {
                            loadHistory(target);
                        }
                    });
                });
            }
            function loadHistory(page){
                giftFetch('ajax_list_domain_gifts', { page: page }).then(function(res){
                    if (res && res.success) {
                        renderHistory(res.data || []);
                        renderPagination(res.pagination || {});
                        state.historyLoaded = true;
                    } else {
                        giftAlert('danger', (res && res.error) ? res.error : cfLang('giftHistoryLoadFailed', '加载历史记录失败'));
                    }
                }).catch(function(){
                    giftAlert('danger', cfLang('networkError', '网络异常，请稍后再试'));
                });
            }
        })();
        <?php endif; ?>

        // 复制

        // 展开/收起域名详情
        function toggleSubdomainDetails(subdomainId) {
            const detailsRow = document.getElementById('details_' + subdomainId);
            if (detailsRow) {
                if (detailsRow.style.display === 'none') {
                    detailsRow.style.display = 'table-row';
                } else {
                    detailsRow.style.display = 'none';
                }
            }
        }
        
        // 控制消息提示的显示
        function dismissMessage() {
            const messageAlert = document.getElementById('messageAlert');
            if (messageAlert) {
                messageAlert.style.display = 'none';
            }
        }
        
        // 页面加载完成后，确保消息提示不会自动消失
        document.addEventListener('DOMContentLoaded', function() {
            const messageAlert = document.getElementById('messageAlert');
            if (messageAlert) {
                // 移除Bootstrap的自动消失功能
                messageAlert.classList.remove('fade');
                messageAlert.classList.remove('show');
                // 添加自定义样式
                messageAlert.style.opacity = '1';
                messageAlert.style.display = 'block';
            }
        });
        
        // 确保注册模态框中的重要说明始终可见
        document.addEventListener('DOMContentLoaded', function() {
            const registerModal = document.getElementById('registerModal');
            if (registerModal) {
                registerModal.addEventListener('shown.bs.modal', function() {
                    const importantInfo = document.getElementById('registerImportantInfo');
                    if (importantInfo) {
                        importantInfo.style.display = 'block';
                        importantInfo.style.opacity = '1';
                        importantInfo.style.visibility = 'visible';
                    }
                });
            }
        });
        
        // 确保DNS设置模态框中的提示始终可见
        document.addEventListener('DOMContentLoaded', function() {
            const dnsModal = document.getElementById('dnsModal');
            if (dnsModal) {
                dnsModal.addEventListener('shown.bs.modal', function() {
                    const importantInfo = document.getElementById('dnsImportantInfo');
                    const usageTips = document.getElementById('dnsUsageTips');
                    
                    if (importantInfo) {
                        importantInfo.style.display = 'block';
                        importantInfo.style.opacity = '1';
                        importantInfo.style.visibility = 'visible';
                    }
                    
                    if (usageTips) {
                        usageTips.style.display = 'block';
                        usageTips.style.opacity = '1';
                        usageTips.style.visibility = 'visible';
                    }
                });
            }
        });
        


        // 过滤应用/重置
        const fType=document.getElementById('flt_type');
        const fName=document.getElementById('flt_name');
        const fApply=document.getElementById('flt_apply');
        const fReset=document.getElementById('flt_reset');
        if(fApply){
          fApply.addEventListener('click',()=>{
            const url=new URL(location.href);
            if(fType&&fType.value) url.searchParams.set('filter_type',fType.value); else url.searchParams.delete('filter_type');
            if(fName&&fName.value) url.searchParams.set('filter_name',fName.value); else url.searchParams.delete('filter_name');
            url.searchParams.delete('dns_page');
            url.searchParams.delete('dns_for');
            url.searchParams.delete('page');
            location.href=url.toString();
          });
        }
        if(fReset){ fReset.addEventListener('click',()=>{ const url=new URL(location.href); url.searchParams.delete('filter_type'); url.searchParams.delete('filter_name'); url.searchParams.delete('dns_page'); url.searchParams.delete('dns_for'); url.searchParams.delete('page'); location.href=url.toString(); }); }

        // 冲突校验（A/AAAA 与 CNAME 互斥）
        document.getElementById('dnsForm').addEventListener('submit', function(e) {
          const type = document.querySelector('select[name="record_type"]').value.toUpperCase();
          const nameBase = document.getElementById('dns_subdomain_name').value;
          const recName = (document.getElementById('dns_record_name').value || '@');
          const fullName = recName==='@' ? nameBase : (recName + '.' + nameBase);
          // 构建当前名称的已有类型集合
          const typesHere = [];
        });

        // 解析预览：提交前生成摘要
        function showPreviewAndSubmit(form){
const type = form.record_type.value;
let content = form.record_content.value;
const ttl = form.record_ttl.value;
const line = form.line?.value || 'default';
const nameBase = document.getElementById('dns_subdomain_name').value;
const recName = form.record_name.value || '@';
const fullName = recName==='@' ? nameBase : (recName + '.' + nameBase);
const action = document.getElementById('dns_action').value;
// 如果是CAA记录，显示组合后的内容
if (type === 'CAA') {
const caaFlag = form.caa_flag?.value || '0';
const caaTag = form.caa_tag?.value || 'issue';
const caaValue = form.caa_value?.value || '';
if (!caaValue) {
alert(cfLang('caaValueRequired', 'CAA记录的Value不能为空'));
return;
}
content = `${caaFlag} ${caaTag} "${caaValue}"`;
form.record_content.value = content;
}
if (type === 'SRV') {
const priority = parseInt(form.record_priority.value || '0', 10);
const weight = parseInt(form.record_weight?.value || '0', 10);
const port = parseInt(form.record_port?.value || '0', 10);
let target = form.record_target?.value.trim() || '';
if (!Number.isFinite(priority) || priority < 0 || priority > 65535) {
alert(cfLang('srvPriorityInvalid', 'SRV记录的优先级必须在0-65535之间'));
return;
}
if (!Number.isFinite(weight) || weight < 0 || weight > 65535) {
alert(cfLang('srvWeightInvalid', 'SRV记录的权重必须在0-65535之间'));
return;
}
if (!Number.isFinite(port) || port < 1 || port > 65535) {
alert(cfLang('srvPortInvalid', 'SRV记录的端口必须在1-65535之间'));
return;
}
if (target.endsWith('.')) {
target = target.slice(0, -1);
}
if (!target) {
alert(cfLang('srvTargetRequired', 'SRV记录的目标地址不能为空'));
return;
}
if (!isValidDomain(target)) {
alert(cfLang('srvTargetInvalid', '请输入有效的SRV目标主机名'));
return;
}
content = `${priority} ${weight} ${port} ${target}`;
form.record_content.value = content;
}
const actionLabel = action==='create_dns' ? cfLang('dnsActionCreate', '创建') : cfLang('dnsActionUpdate', '更新');
const summary = cfLangFormat('dnsConfirmSummary', '将要%1$s记录\n名称: %2$s\n类型: %3$s\n内容: %4$s\nTTL: %5$s\n线路: %6$s', actionLabel, fullName, type, content, ttl, line);
if(confirm(summary + "\n\n" + cfLang('dnsConfirmPrompt', '确认提交吗？'))){
form.submit();
}
}
</script>
