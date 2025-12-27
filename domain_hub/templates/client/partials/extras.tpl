<?php
$clientLanguageCode = isset($currentClientLanguage) ? strtolower((string) $currentClientLanguage) : 'english';
$isClientLanguageChinese = $clientLanguageCode === 'chinese';
$extrasTexts = [
    'tipsTitle' => cfclient_lang('cfclient.extras.tips.title', $isClientLanguageChinese ? '域名知识小贴士' : 'Domain Tips', [], true),
    'domainTitle' => cfclient_lang('cfclient.extras.tips.domain.title', $isClientLanguageChinese ? '📚 域名概念' : '📚 Domain Basics', [], true),
    'dnsTitle' => cfclient_lang('cfclient.extras.tips.dns.title', $isClientLanguageChinese ? '🔧 DNS记录说明' : '🔧 DNS Records', [], true),
    'warning' => cfclient_lang('cfclient.extras.warning', $isClientLanguageChinese ? '重要提示：DNS记录修改可能需要几分钟时间生效，请耐心等待。' : 'Important: DNS changes can take a few minutes to propagate. Please wait patiently.', [], true),
    'supportTitle' => cfclient_lang('cfclient.extras.support.title', $isClientLanguageChinese ? '需要帮助？' : 'Need help?', [], true),
    'supportBody' => cfclient_lang('cfclient.extras.support.body', $isClientLanguageChinese ? '如果您在使用过程中遇到问题，或者需要技术支持，请点击下方按钮提交工单' : 'If you run into issues or need support, click the buttons below to open a ticket.', [], true),
    'supportTicket' => cfclient_lang('cfclient.extras.support.ticket', $isClientLanguageChinese ? '提交工单' : 'Open Ticket', [], true),
    'supportAppeal' => cfclient_lang('cfclient.extras.support.appeal', $isClientLanguageChinese ? '提交封禁申诉工单' : 'Submit Ban Appeal', [], true),
    'supportKb' => cfclient_lang('cfclient.extras.support.kb', $isClientLanguageChinese ? '知识库' : 'Knowledgebase', [], true),
    'supportContact' => cfclient_lang('cfclient.extras.support.contact', $isClientLanguageChinese ? '联系我们' : 'Contact Us', [], true),
    'backToPortal' => cfclient_lang('cfclient.extras.back_to_portal', $isClientLanguageChinese ? '返回客户中心' : 'Back to Client Area', [], true),
];
$deleteTipKey = !empty($clientDeleteEnabled) ? 'cfclient.extras.tips.domain.delete_enabled' : 'cfclient.extras.tips.domain.delete';
$deleteTipDefault = !empty($clientDeleteEnabled)
    ? ($isClientLanguageChinese ? '域名删除：可在“查看详情”中提交自助删除申请。' : 'Deletion: submit a self-service request under “View details”.')
    : ($isClientLanguageChinese ? '域名删除：域名成功注册后不支持删除！' : 'Deletion: once registered, domains cannot be removed.');
$extrasList = [
    'domain' => [
        cfclient_lang('cfclient.extras.tips.domain.transfer', '域名转赠：域名转赠成功后无法撤回操作，请在分享前确认。', [], true),
        cfclient_lang('cfclient.extras.tips.domain.content', '禁止内容：域名禁止用于任何违法违规行为,一经发现立即封禁!', [], true),
        cfclient_lang($deleteTipKey, $deleteTipDefault, [], true),
    ],
    'dns' => [
        cfclient_lang('cfclient.extras.tips.dns.root', '@ 记录：表示域名本身（如 blog.example.com）', [], true),
        cfclient_lang('cfclient.extras.tips.dns.propagation', 'DNS解析：DNS记录修改可能需要几分钟时间生效，请耐心等待。', [], true),
        cfclient_lang('cfclient.extras.tips.dns.error', '解析错误：如遇解析错误,无法解析的情况可以提交工单联系客服获取帮助！', [], true),
    ],
];
$banAppealSubject = $isClientLanguageChinese ? '封禁申诉' : 'Ban Appeal';
$banAppealMessageBase = $isClientLanguageChinese
    ? '我的账号被封禁/停用。'
    : 'My account has been banned or disabled.';
$banAppealMessageTail = $isClientLanguageChinese ? '请协助核查并解除限制。' : 'Please review and lift the restriction.';
$banAppealReason = '';
if (!empty($banReasonText)) {
    $banAppealReason = '\n' . strip_tags($banReasonText);
}
$banAppealMessage = $banAppealMessageBase . $banAppealReason . '\n' . $banAppealMessageTail;
?>
<div class="row mt-4">
    <div class="col-12">
        <div class="card border-0 shadow-sm">
            <div class="card-header bg-info text-white">
                <h6 class="card-title mb-0">
                    <i class="fas fa-lightbulb"></i> <?php echo $extrasTexts['tipsTitle']; ?>
                </h6>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-primary"><?php echo $extrasTexts['domainTitle']; ?></h6>
                        <ul class="list-unstyled">
                            <?php foreach ($extrasList['domain'] as $item): ?>
                                <li><?php echo $item; ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-success"><?php echo $extrasTexts['dnsTitle']; ?></h6>
                        <ul class="list-unstyled">
                            <?php foreach ($extrasList['dns'] as $item): ?>
                                <li><?php echo $item; ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
                <div class="alert alert-warning mt-3 mb-0" id="dnsTimeoutWarning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong><?php echo $extrasTexts['warning']; ?></strong>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- 工单入口导航 -->
<div class="row mt-5 mb-4">
    <div class="col-12">
        <div class="card border-0 shadow-sm">
            <div class="card-body text-center">
                <h6 class="card-title text-primary mb-3">
                    <i class="fas fa-life-ring"></i> <?php echo $extrasTexts['supportTitle']; ?>
                </h6>
                <p class="text-muted mb-3"><?php echo $extrasTexts['supportBody']; ?></p>
                <div class="d-flex justify-content-center gap-3">
                    <?php if (!empty($isUserBannedOrInactive) && $isUserBannedOrInactive): ?>
                        <a href="submitticket.php?step=2&deptid=1&subject=<?php echo urlencode($banAppealSubject); ?>&message=<?php echo urlencode($banAppealMessage); ?>" class="btn btn-danger btn-custom">
                            <i class="fas fa-gavel"></i> <?php echo $extrasTexts['supportAppeal']; ?>
                        </a>
                    <?php else: ?>
                        <a href="submitticket.php" class="btn btn-primary btn-custom">
                            <i class="fas fa-ticket-alt"></i> <?php echo $extrasTexts['supportTicket']; ?>
                        </a>
                    <?php endif; ?>
                    <a href="knowledgebase.php" class="btn btn-outline-primary btn-custom">
                        <i class="fas fa-book"></i> <?php echo $extrasTexts['supportKb']; ?>
                   <a href="https://t.me/+l9I5TNRDLP5lZDBh" 
   class="btn btn-outline-secondary btn-custom"
   target="_blank" 
   rel="noopener noreferrer">
    <i class="fa-brands fa-telegram"></i> <?php echo $extrasTexts['supportContact']; ?>
</a>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- 底部导航 -->
<div class="row mt-4">
    <div class="col-12">
        <div class="text-center">
            <a href="index.php" class="btn btn-outline-secondary btn-custom">
                <i class="fas fa-arrow-left"></i> <?php echo $extrasTexts['backToPortal']; ?>
            </a>
        </div>
    </div>
</div>
