<?php
$footerConfig = $cfAdminFooterConfig ?? [];
$footerLang = $footerConfig['lang'] ?? [];
$csrfToken = (string)($footerConfig['csrfToken'] ?? '');
$announcementEnabled = !empty($footerConfig['announcement']['enabled']);
$quotaEndpoint = $footerConfig['api']['quotaEndpoint'] ?? '?module=domain_hub&action=get_user_quota&userid=';
?>
<script>
(function(){
  var token = <?php echo json_encode($csrfToken, CFMOD_SAFE_JSON_FLAGS); ?> || '';
  window.CF_MOD_ADMIN_CSRF = token;
  function inject(scope){
    if (!scope || !token) { return; }
    scope.querySelectorAll('form').forEach(function(form){
      if (form.dataset.cfmodSkipCsrf === '1') { return; }
      if (form.querySelector("input[name='cfmod_admin_csrf']")) { return; }
      var el = document.createElement('input');
      el.type = 'hidden';
      el.name = 'cfmod_admin_csrf';
      el.value = token;
      form.appendChild(el);
    });
  }
  if (document.readyState !== 'loading') {
    inject(document);
  } else {
    document.addEventListener('DOMContentLoaded', function(){ inject(document); });
  }
})();
</script>
<script>
(function(){
  var lang = <?php echo json_encode($footerLang, CFMOD_SAFE_JSON_FLAGS); ?> || {};
  var quotaEndpoint = <?php echo json_encode($quotaEndpoint, CFMOD_SAFE_JSON_FLAGS); ?>;
  function format(template, value){
    if (!template) { return ''; }
    return template.replace('%d', value);
  }

  function alertMessage(prefixKey, detail){
    var prefix = lang[prefixKey] || '';
    alert(prefix + detail);
  }

  window.toggleExpiryForm = function(id){
    var row = document.getElementById('expiry_form_' + id);
    if (!row) { return; }
    if (row.style.display === 'none' || row.style.display === '') {
      row.style.display = 'table-row';
    } else {
      row.style.display = 'none';
    }
  };

  window.confirmBatchDelete = function(){
    var checkedBoxes = document.querySelectorAll('.record-checkbox:checked');
    if (checkedBoxes.length === 0) {
      alert(lang.batchDeleteEmpty || '请选择要删除的记录');
      return;
    }
    var message = format(lang.batchDeleteConfirm || '确定要删除选中的 %d 条记录吗？此操作不可恢复！', checkedBoxes.length);
    if (confirm(message)) {
      var batchForm = document.getElementById('batchForm');
      if (batchForm) {
        batchForm.submit();
      }
    }
  };

  function initSelectAll(){
    var selectAll = document.getElementById('selectAll');
    if (!selectAll) { return; }
    selectAll.addEventListener('change', function(){
      document.querySelectorAll('.record-checkbox').forEach(function(box){
        box.checked = selectAll.checked;
      });
    });
  }

  function initPurgeHelper(){
    var select = document.getElementById('cf-purge-root-select');
    var input = document.getElementById('cf-purge-root-input');
    if (!select || !input) { return; }
    select.addEventListener('change', function(){
      if (select.value) {
        input.value = select.value;
      }
    });
  }

  function initAnnouncementModal(){
    if (!<?php echo $announcementEnabled ? 'true' : 'false'; ?>) { return; }
    var key = 'cfmod_admin_announce_dismissed';
    if (document.cookie.indexOf(key + '=1') !== -1) { return; }
    var show = function(){
      var el = document.getElementById('adminAnnounceModal');
      if (!el) { return; }
      if (window.jQuery && typeof jQuery(el).modal === 'function') {
        jQuery(el).modal('show');
      } else {
        el.style.display = 'block';
        el.classList.add('in');
      }
    };
    document.addEventListener('DOMContentLoaded', show);
    var dismiss = document.getElementById('adminAnnounceDismiss');
    if (dismiss) {
      dismiss.addEventListener('click', function(){
        var expires = new Date();
        expires.setFullYear(expires.getFullYear() + 1);
        document.cookie = key + '=1; path=/; expires=' + expires.toUTCString();
      });
    }
  }

  document.addEventListener('DOMContentLoaded', function(){
    initSelectAll();
    initPurgeHelper();
    initAnnouncementModal();
    initModalPolyfill();
    document.addEventListener('keydown', function(e){
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        var searchInput = document.getElementById('api_search');
        if (searchInput) {
          e.preventDefault();
          searchInput.focus();
          searchInput.select();
          searchInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }
    });
  });

  function initModalPolyfill(){
    var hasBootstrapModal = window.jQuery && typeof jQuery.fn === 'object' && typeof jQuery.fn.modal === 'function';
    if (hasBootstrapModal) {
      return;
    }
    var activeBackdropClass = 'cfmod-modal-backdrop';

    function matchesSelector(el, selector){
      if (!el || el.nodeType !== 1) { return false; }
      var proto = Element.prototype;
      var fn = proto.matches || proto.msMatchesSelector || proto.webkitMatchesSelector;
      if (!fn) {
        var nodes = el.parentNode ? el.parentNode.querySelectorAll(selector) : [];
        for (var i = 0; nodes && i < nodes.length; i++) {
          if (nodes[i] === el) { return true; }
        }
        return false;
      }
      return fn.call(el, selector);
    }

    function closestElement(el, selector){
      while (el && el.nodeType === 1) {
        if (matchesSelector(el, selector)) {
          return el;
        }
        el = el.parentElement;
      }
      return null;
    }

    function showBackdrop(modal){

      if (existing) { return existing; }
      var backdrop = document.createElement('div');
      backdrop.className = 'modal-backdrop fade in ' + activeBackdropClass;
      if (modal.id) {
        backdrop.setAttribute('data-target', modal.id);
      }
      document.body.appendChild(backdrop);
      return backdrop;
    }

    function hideBackdrop(modal){
      if (!modal.id) { return; }
      var backdrop = document.querySelector('.' + activeBackdropClass + '[data-target="' + modal.id + '"]');
      if (backdrop && backdrop.parentNode) {
        backdrop.parentNode.removeChild(backdrop);
      }
    }

    function openModal(modal){
      if (!modal) { return; }
      modal.style.display = 'block';
      modal.classList.add('in');
      modal.setAttribute('aria-hidden', 'false');
      document.body.classList.add('modal-open');
      if (modal.id) {
        modal.setAttribute('data-modal-id', modal.id);
      }
      showBackdrop(modal);
      var focusable = modal.querySelector('input, button, select, textarea, [tabindex]');
      if (focusable && typeof focusable.focus === 'function') {
        focusable.focus();
      }
    }

    function closeModal(modal){
      if (!modal) { return; }
      modal.classList.remove('in');
      modal.style.display = 'none';
      modal.setAttribute('aria-hidden', 'true');
      hideBackdrop(modal);
      if (!document.querySelector('.modal.in')) {
        document.body.classList.remove('modal-open');
      }
    }

    document.addEventListener('click', function(event){
      var trigger = closestElement(event.target, '[data-toggle="modal"]');
      if (!trigger) { return; }
      var selector = trigger.getAttribute('data-target') || trigger.getAttribute('href');
      if (!selector || selector === '#') { return; }
      var modal = document.querySelector(selector);
      if (!modal) { return; }
      event.preventDefault();
      openModal(modal);
    });

    document.addEventListener('click', function(event){
      var dismiss = closestElement(event.target, '[data-dismiss="modal"]');
      if (!dismiss) { return; }
      var modal = closestElement(event.target, '.modal');
      if (!modal) { return; }
      event.preventDefault();
      closeModal(modal);
    });

    document.addEventListener('keydown', function(event){
      if (event.key !== 'Escape') { return; }
      var modal = document.querySelector('.modal.in');
      if (modal) {
        closeModal(modal);
      }
    });
  }

  function validateBigNumber(value, min, max){

    if (value === '') {
      return { valid: false, error: lang.numberRequired || '请输入数字！' };
    }
    if (!/^\d+$/.test(value)) {
      return { valid: false, error: lang.numberInvalid || '请输入有效的数字（只能包含0-9）！' };
    }
    if (value.length > 1 && value[0] === '0') {
      return { valid: false, error: lang.numberLeadingZero || '数字不能以0开头！' };
    }
    var minStr = String(min);
    var maxStr = String(max);
    if (value.length < minStr.length || (value.length === minStr.length && value < minStr)) {
      return { valid: false, error: format(lang.numberMin || '数值不能小于 %d！', min) };
    }
    if (value.length > maxStr.length || (value.length === maxStr.length && value > maxStr)) {
      return { valid: false, error: format(lang.numberMax || '数值不能超过 %d！', max) };
    }
    return { valid: true };
  }

  window.editRateLimit = function(keyId, currentLimit){
    var modal = document.getElementById('editRateLimitModal');
    if (!modal) { return; }
    document.getElementById('edit_rate_key_id').value = keyId;
    document.getElementById('edit_rate_limit').value = currentLimit;
    modal.style.display = 'block';
  };

  window.manageUserQuota = function(userId, userName){
    var modal = document.getElementById('manageQuotaModal');
    if (!modal) { return; }
    document.getElementById('quota_user_id').value = userId;
    document.getElementById('quota_user_name').textContent = userName + ' (ID: ' + userId + ')';
    fetch(quotaEndpoint + encodeURIComponent(userId))
      .then(function(response){ return response.json(); })
      .then(function(data){
        if (data.success) {
          document.getElementById('max_count').value = data.quota.max_count || 0;
          document.getElementById('invite_bonus_limit').value = data.quota.invite_bonus_limit || 0;
        } else {
          document.getElementById('max_count').value = 5;
          document.getElementById('invite_bonus_limit').value = 5;
        }
        modal.style.display = 'block';
      })
      .catch(function(){
        document.getElementById('max_count').value = 5;
        document.getElementById('invite_bonus_limit').value = 5;
        modal.style.display = 'block';
      });
  };

  window.validateQuotaForm = function(){
    var maxCount = document.getElementById('max_count').value;
    var inviteLimit = document.getElementById('invite_bonus_limit').value;
    var result1 = validateBigNumber(maxCount, 0, 99999999999);
    if (!result1.valid) {
      alertMessage('quotaErrorPrefix', result1.error);
      return false;
    }
    var result2 = validateBigNumber(inviteLimit, 0, 99999999999);
    if (!result2.valid) {
      alertMessage('inviteErrorPrefix', result2.error);
      return false;
    }
    return true;
  };

  window.validateInviteLimit = function(form){
    var inviteLimit = form.new_invite_limit.value;
    var result = validateBigNumber(inviteLimit, 0, 99999999999);
    if (!result.valid) {
      alertMessage('inviteErrorPrefix', result.error);
      return false;
    }
    return true;
  };

  window.validateQuotaUpdate = function(form){
    var newQuota = form.new_quota.value;
    var result = validateBigNumber(newQuota, 0, 99999999999);
    if (!result.valid) {
      alertMessage('quotaUpdateErrorPrefix', result.error);
      return false;
    }
    return true;
  };

  window.validateRootDomain = function(form){
    var maxSubdomains = form.max_subdomains.value;
    var result = validateBigNumber(maxSubdomains, 1, 99999999999);
    if (!result.valid) {
      alertMessage('rootErrorPrefix', result.error);
      return false;
    }
    return true;
  };

  window.onclick = function(event){
    if (event.target.classList && event.target.classList.contains('modal')) {
      event.target.style.display = 'none';
    }
  };
})();
</script>
