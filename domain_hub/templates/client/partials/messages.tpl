<?php if($isUserBannedOrInactive): ?>
    <div class="alert alert-danger d-flex align-items-start" role="alert">
        <i class="fas fa-ban me-2 mt-1"></i>
        <div>
            <strong><?php echo cfclient_lang('cfclient.alerts.ban.title', '账户受限：', [], true); ?></strong>
            <?php echo cfclient_lang('cfclient.alerts.ban.body', '您当前被封禁或处于停用状态，暂不能进行任何操作。', [], true); ?>
            <?php if(!empty($banReasonText)): ?>
                <div class="mt-1 small text-muted"><?php echo $banReasonText; ?></div>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<!-- 消息提示 -->
<?php if($msg && empty($registerError)): ?>
    <div class="alert alert-<?php echo $msg_type; ?> alert-dismissible fade show" role="alert" id="messageAlert">
        <i class="fas fa-<?php echo $msg_type == 'success' ? 'check-circle' : ($msg_type == 'warning' ? 'exclamation-triangle' : 'times-circle'); ?>"></i>
        <?php echo htmlspecialchars($msg); ?>
        <button type="button" class="btn btn-close" data-bs-dismiss="alert" onclick="dismissMessage()"></button>
    </div>
<?php endif; ?>
