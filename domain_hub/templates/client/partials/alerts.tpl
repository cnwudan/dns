<?php if ($maintenanceMode): ?>
    <div class="container mt-3">
        <div class="alert alert-warning d-flex align-items-start" role="alert" id="maintenanceAlert">
            <i class="fas fa-tools me-2 mt-1"></i>
            <div>
                <strong><?php echo cfclient_lang('cfclient.alerts.maintenance.title', '维护通知：', [], true); ?></strong>
                <?php echo cfclient_lang('cfclient.alerts.maintenance.body', '系统维护中，部分功能暂不可用。', [], true); ?>
                <?php if(!empty($maintenanceMessage)): ?>
                    <div class="mt-1 small text-muted"><?php echo nl2br(htmlspecialchars($maintenanceMessage)); ?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
<?php endif; ?>

<?php if (!empty($isUserBannedOrInactive) && $isUserBannedOrInactive): ?>
    <div class="container mt-3">
        <div class="alert alert-danger d-flex align-items-start" role="alert" id="banAlert">
            <i class="fas fa-ban me-2 mt-1"></i>
            <div>
                <strong><?php echo cfclient_lang('cfclient.alerts.ban.title', '账户受限：', [], true); ?></strong>
                <?php echo cfclient_lang('cfclient.alerts.ban.body', '您当前被封禁或处于停用状态，暂不能进行任何操作。', [], true); ?>
                <?php if(!empty($banReasonText)): ?>
                    <div class="mt-1 small text-muted"><?php echo $banReasonText; ?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
<?php endif; ?>
