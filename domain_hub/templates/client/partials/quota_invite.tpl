            <?php
use WHMCS\Database\Capsule;

$cfInviteText = static function (string $key, string $default, array $params = [], bool $escape = true): string {
    return cfclient_lang($key, $default, $params, $escape);
};

$inviteTableHeaders = [
    'user' => $cfInviteText('cfclient.invite.table.user', '用户ID', [], true),
    'email' => $cfInviteText('cfclient.invite.table.email', 'Email', [], true),
    'code' => $cfInviteText('cfclient.invite.table.code', '邀请码', [], true),
    'usage' => $cfInviteText('cfclient.invite.table.usage', '使用次数', [], true),
];
$inviteTableHeadHtml = '<thead><tr><th>#</th><th>' . $inviteTableHeaders['user'] . '</th><th>' . $inviteTableHeaders['email'] . '</th><th>' . $inviteTableHeaders['code'] . '</th><th>' . $inviteTableHeaders['usage'] . '</th></tr></thead>';
$inviteHiddenLabel = $cfInviteText('cfclient.invite.table.hidden', '已隐藏', [], true);
$inviteEmptyLabel = $cfInviteText('cfclient.invite.table.empty', '暂无数据', [], true);
$inviteLoadingLabel = $cfInviteText('cfclient.invite.table.loading', '加载中...', [], true);
?>
<!-- 配额信息 -->
            <div class="card mb-4 border-0 shadow-sm">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col-md-8">
                            <div class="d-flex flex-wrap align-items-center gap-3 mb-3">
                                <h5 class="card-title mb-0">
                                    <i class="fas fa-chart-pie text-primary"></i> <?php echo cfclient_lang('cfclient.quota.title', '注册额度', [], true); ?>
                                </h5>
                                <?php if ($quotaRedeemEnabled): ?>
                                <button class="btn btn-sm btn-outline-success" type="button" onclick="openQuotaRedeemModal()">
                                    <i class="fas fa-gift"></i> <?php echo cfclient_lang('cfclient.quota.button.redeem', '兑换额度', [], true); ?>
                                </button>
                                <?php endif; ?>
                            </div>
                            <div class="progress quota-progress mb-2">
                                <?php $percentage = ($quota->used_count / $quota->max_count) * 100; ?>
                                <div class="progress-bar <?php echo $percentage > 80 ? 'bg-danger' : ($percentage > 60 ? 'bg-warning' : 'bg-success'); ?>" 
                                     role="progressbar" 
                                     style="width: <?php echo $percentage; ?>%">
                                    <?php echo $quota->used_count; ?>/<?php echo $quota->max_count; ?>
                                </div>
                            </div>
                            <small class="text-muted">
                                <?php echo cfclient_lang('cfclient.quota.summary', '已注册 %1$s 个，剩余 %2$s 个', [number_format($quota->used_count), number_format($quota->max_count - $quota->used_count)], true); ?>
                                <?php if(!$hideInviteFeature): ?>
                                <span class="ms-2">
                                    <i class="fas fa-gift"></i> <?php echo cfclient_lang('cfclient.quota.invite_bonus', '邀请解锁已增加 %1$s/%2$s', [intval($quota->invite_bonus_count ?? 0), intval($quota->invite_bonus_limit ?? 5)], true); ?>
                                </span>
                                <?php endif; ?>
                            </small>
                        </div>
                        <div class="col-md-4 text-end">
                            <?php if($isUserBannedOrInactive): ?>
                                <button class="btn btn-secondary btn-custom" disabled>
                                    <i class="fas fa-lock"></i> <?php echo cfclient_lang('cfclient.quota.button.locked', '账号受限', [], true); ?>
                                </button>
                            <?php elseif($quota->used_count < $quota->max_count): ?>
                                <button class="btn btn-primary btn-custom" data-bs-toggle="modal" data-bs-target="#registerModal">
                                    <i class="fas fa-plus"></i> <?php echo cfclient_lang('cfclient.quota.button.register', '注册新域名', [], true); ?>
                                </button>
                                <?php if(!$hideInviteFeature): ?>
                                <button class="btn btn-outline-primary btn-custom ms-2" data-bs-toggle="modal" data-bs-target="#inviteModal">
                                    <i class="fas fa-user-friends"></i> <?php echo cfclient_lang('cfclient.quota.button.invite', '邀请好友解锁额度', [], true); ?>
                                </button>
                                <?php endif; ?>
                            <?php else: ?>
                                <button class="btn btn-secondary btn-custom" disabled>
                                    <i class="fas fa-ban"></i> <?php echo cfclient_lang('cfclient.quota.button.limit', '已达上限', [], true); ?>
                                </button>
                                <?php if(!$hideInviteFeature): ?>
                                <button class="btn btn-outline-primary btn-custom ms-2" data-bs-toggle="modal" data-bs-target="#inviteModal">
                                    <i class="fas fa-user-friends"></i> <?php echo cfclient_lang('cfclient.quota.button.invite', '邀请好友解锁额度', [], true); ?>
                                </button>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>

            <?php if(!$hideInviteFeature): ?>
            <!-- 邀请好友解锁额度 Modal -->
            <div class="modal fade" id="inviteModal" tabindex="-1" aria-labelledby="inviteModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-dialog-centered">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="inviteModalLabel"><i class="fas fa-user-friends text-primary"></i> <?php echo cfclient_lang('cfclient.invite.modal.title', '邀请好友解锁额度', [], true); ?></h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <ul class="nav nav-tabs" id="inviteTabs" role="tablist">
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link active" id="mycode-tab" data-bs-toggle="tab" data-bs-target="#mycode" type="button" role="tab" aria-controls="mycode" aria-selected="true"><?php echo cfclient_lang('cfclient.invite.tabs.my_code', '我的邀请码', [], true); ?></button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="usecode-tab" data-bs-toggle="tab" data-bs-target="#usecode" type="button" role="tab" aria-controls="usecode" aria-selected="false"><?php echo cfclient_lang('cfclient.invite.tabs.use_code', '使用他人邀请码', [], true); ?></button>
                                </li>
                                <?php if ($enableInviteLeaderboard): ?>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="leaderboard-tab" data-bs-toggle="tab" data-bs-target="#leaderboard" type="button" role="tab" aria-controls="leaderboard" aria-selected="false"><?php echo cfclient_lang('cfclient.invite.tabs.leaderboard', '邀请排行榜', [], true); ?></button>
                                </li>
                                <!-- 移除单独的实时榜单 Tab，改在排行榜内展示 Top10 实时数据 -->
                                <?php endif; ?>
                            </ul>
                            <div class="tab-content pt-3" id="inviteTabsContent">
                                <div class="tab-pane fade show active" id="mycode" role="tabpanel" aria-labelledby="mycode-tab">
                                    <div class="mb-3">
                                        <label class="form-label"><?php echo cfclient_lang('cfclient.invite.my_code.label', '您唯一的邀请码', [], true); ?></label>
                                        <div class="input-group">
                                            <input type="text" class="form-control" id="myInviteCodeInput" value="<?php echo htmlspecialchars($myInviteCode ?: cfclient_lang('cfclient.invite.my_code.generating', '生成中', [], true)); ?>" readonly>
                                            <button class="btn btn-outline-secondary" type="button" onclick="copyInviteCode()"><i class="fas fa-copy"></i> <?php echo cfclient_lang('cfclient.common.copy', '复制', [], true); ?></button>
                                        </div>
                                        <div class="form-text"><?php echo cfclient_lang('cfclient.invite.my_code.help', '将该邀请码分享给好友。好友在此页面输入后，您与好友各增加 1 个注册额度。', [], true); ?></div>
                                    </div>
                                    <?php if(!$hideInviteFeature): ?>
                                    <div class="alert alert-info mb-0">
                                        <i class="fas fa-info-circle"></i>
                                        <?php echo cfclient_lang('cfclient.invite.my_code.progress', '已增加 %1$s/%2$s（通过邀请解锁的额度）', [intval($quota->invite_bonus_count ?? 0), intval($quota->invite_bonus_limit ?? 5)], true); ?>
                                    </div>
                                    <?php endif; ?>
                                </div>
                                <div class="tab-pane fade" id="usecode" role="tabpanel" aria-labelledby="usecode-tab">
                                    <form method="post">
                                        <input type="hidden" name="action" value="claim_invite">
                                        <div class="mb-3">
                                            <label for="inviteCodeInput" class="form-label"><?php echo cfclient_lang('cfclient.invite.use_code.label', '输入好友的邀请码', [], true); ?></label>
                                            <input type="text" name="invite_code" id="inviteCodeInput" class="form-control" placeholder="<?php echo cfclient_lang('cfclient.invite.my_code.placeholder', '例如：AB1A2B3C4', [], true); ?>" required <?php echo (intval($quota->invite_bonus_count ?? 0) >= intval($quota->invite_bonus_limit ?? 5)) ? 'disabled' : ''; ?> oninput="this.value=this.value.toUpperCase()">
                                            <div class="form-text"><?php echo cfclient_lang('cfclient.invite.use_code.limit_hint', '每位用户最多可通过邀请累计增加 %1$s 个注册额度。', [intval($quota->invite_bonus_limit ?? 5)], true); ?></div>
                                        </div>
                                        <?php if (intval($quota->invite_bonus_count ?? 0) >= intval($quota->invite_bonus_limit ?? 5)): ?>
                                            <div class="alert alert-warning">
                                                <i class="fas fa-exclamation-triangle"></i> <?php echo cfclient_lang('cfclient.invite.use_code.limit_reached', '达到额度上限，无法再增加', [], true); ?>
                                            </div>
                                            <button type="button" class="btn btn-secondary" disabled><?php echo cfclient_lang('cfclient.quota.button.limit', '已达上限', [], true); ?></button>
                                        <?php else: ?>
                                            <button type="submit" class="btn btn-primary"><i class="fas fa-unlock"></i> <?php echo cfclient_lang('cfclient.invite.use_code.unlock_button', '立即解锁', [], true); ?></button>
                                        <?php endif; ?>
                                    </form>
                                </div>
                                <?php if ($enableInviteLeaderboard): ?>
                                <div class="tab-pane fade" id="leaderboard" role="tabpanel" aria-labelledby="leaderboard-tab">
                                    <div class="mb-3">
                                        <div class="d-flex justify-content-between align-items-center">
                                            <div>
                                                <strong><?php echo $cfInviteText('cfclient.invite.leaderboard.period_summary', '周期排行榜单：%s 天榜', [number_format($inviteLeaderboardDays)], true); ?></strong>
                                                <?php if ($hideCurrentWeekLeaderboard): ?>
                                                    <span class="badge bg-warning ms-2"><?php echo $cfInviteText('cfclient.invite.leaderboard.hidden_badge', '本周排行榜已隐藏', [], true); ?></span>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                    <?php
                                        $invitePrizeDefaults = [];
                                        for ($i = 1; $i <= 5; $i++) {
                                            $invitePrizeDefaults[$i] = trim($module_settings['invite_reward_prize_' . $i] ?? '');
                                        }
                                        $invitePrizeMapText = trim($module_settings['invite_reward_prizes'] ?? '');
                                        $invitePrizeRules = [];
                                        $invitePrizeDisplayRows = [];
                                        if ($invitePrizeMapText !== '') {
                                            $lines = preg_split('/\r?\n/', $invitePrizeMapText);
                                            foreach ($lines as $line) {
                                                $line = trim($line);
                                                if ($line === '') { continue; }
                                                if (function_exists('mb_convert_kana')) { $line = mb_convert_kana($line, 'as'); }
                                                $line = str_replace(['：','＝'], ['=','='], $line);
                                                $line = str_replace(['－','—','–','―','~','～'], ['-','-','-','-','-','-'], $line);
                                                $line = preg_replace('/\s+/', ' ', $line);
                                                if (strpos($line, '=') === false) { continue; }
                                                list($k, $v) = explode('=', $line, 2);
                                                $k = trim($k);
                                                $v = trim($v);
                                                if ($k === '' || $v === '') { continue; }
                                                if (function_exists('mb_convert_kana')) { $k = mb_convert_kana($k, 'as'); }
                                                $k = str_replace(['－','—','–','―','~','～'], ['-','-','-','-','-','-'], $k);
                                                $k = preg_replace('/\s+/', '', $k);
                                                if (preg_match('/^(\d+)-(\d+)$/', $k, $m)) {
                                                    $min = (int) min($m[1], $m[2]);
                                                    $max = (int) max($m[1], $m[2]);
                                                    if ($min <= 0) { continue; }
                                                    $invitePrizeRules[] = ['min' => $min, 'max' => $max, 'label' => $v];
                                                    $rangeLabel = $cfInviteText('cfclient.invite.prize.table.range_multi', '第 %1$s-%2$s 名', [$min, $max], false);
                                                    $invitePrizeDisplayRows[] = [
                                                        'range' => trim($rangeLabel),
                                                        'reward' => $v,
                                                    ];
                                                } elseif (ctype_digit($k)) {
                                                    $rankVal = (int) $k;
                                                    if ($rankVal <= 0) { continue; }
                                                    $invitePrizeRules[] = ['min' => $rankVal, 'max' => $rankVal, 'label' => $v];
                                                    $rangeLabel = $cfInviteText('cfclient.invite.prize.table.range_single', '第 %s 名', [$rankVal], false);
                                                    $invitePrizeDisplayRows[] = [
                                                        'range' => trim($rangeLabel),
                                                        'reward' => $v,
                                                    ];
                                                }
                                            }
                                        }
                                        if (empty($invitePrizeDisplayRows)) {
                                            foreach ($invitePrizeDefaults as $rank => $label) {
                                                if ($label === '') { continue; }
                                                $rangeLabel = $cfInviteText('cfclient.invite.prize.table.range_single', '第 %s 名', [$rank], false);
                                                $invitePrizeDisplayRows[] = [
                                                    'range' => trim($rangeLabel),
                                                    'reward' => $label,
                                                ];
                                            }
                                        }
                                        $prizeSectionSubtitleKey = $invitePrizeMapText !== '' ? 'cfclient.invite.prize.advanced_title' : 'cfclient.invite.prize.basic_title';
                                        $prizeSectionSubtitle = rtrim($cfInviteText($prizeSectionSubtitleKey, $invitePrizeMapText !== '' ? '高级奖品配置：' : '基础奖品：', [], true), '：:');
                                        $cfInviteResolvePrize = static function (int $rank) use ($invitePrizeRules, $invitePrizeDefaults): string {
                                            foreach ($invitePrizeRules as $rule) {
                                                if ($rank >= $rule['min'] && $rank <= $rule['max']) {
                                                    return $rule['label'];
                                                }
                                            }
                                            return $invitePrizeDefaults[$rank] ?? '';
                                        };
                                    ?>
                                    
                                    <?php if ($hideCurrentWeekLeaderboard): ?>
                                        <!-- 隐藏本周排行榜，只显示历史快照 -->
                                        <div class="alert alert-info">
                                            <i class="fas fa-info-circle"></i> <?php echo $cfInviteText('cfclient.invite.leaderboard.hidden_notice', '本周排行榜已隐藏，请查看历史期数快照。', [], true); ?>
                                        </div>
                                        <?php
                                        // 隐藏本周排行榜时也显示实时榜单（一直显示，不检查周期结束）
                                            try {
                                                $todayYmd = date('Y-m-d');
                                                if ($inviteCycleStart !== '' && preg_match('/^\\d{4}-\\d{2}-\\d{2}$/', $inviteCycleStart)) {
                                                    $startTs = strtotime($inviteCycleStart);
                                                    $todayTs = strtotime($todayYmd);
                                                    if ($todayTs >= $startTs) {
                                                        $k = (int) floor((($todayTs - $startTs) / 86400) / $inviteLeaderboardDays);
                                                        $rtStartH = date('Y-m-d', strtotime('+' . ($k * $inviteLeaderboardDays) . ' days', $startTs));
                                                    } else { $rtStartH = $todayYmd; }
                                                    $rtEndH = $todayYmd;
                                                } else {
                                                    $rtEndH = $todayYmd;
                                                    $rtStartH = date('Y-m-d', strtotime($rtEndH . ' -' . ($inviteLeaderboardDays - 1) . ' days'));
                                                }
                                                $rtTopH = Capsule::table('mod_cloudflare_invitation_claims as ic')
                                                    ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                                                    ->whereBetween('ic.created_at', [$rtStartH.' 00:00:00', $rtEndH.' 23:59:59'])
                                                    ->groupBy('ic.inviter_userid')
                                                    ->orderBy('cnt','desc')->limit(10)->get();
                                            } catch (Exception $e) { $rtTopH = []; }
                                            if (!empty($rtTopH)) {
                                                $rtTopHUserIds = [];
                                                foreach ($rtTopH as $rw) {
                                                    $uid = intval($rw->inviter_userid ?? 0);
                                                    if ($uid > 0) {
                                                        $rtTopHUserIds[] = $uid;
                                                    }
                                                }
                                                list($rtTopHEmailMap, $rtTopHCodeMap) = cfmod_client_fetch_invite_user_meta($rtTopHUserIds);
                                                echo '<div class="mt-2">';
                                                echo '<span class="badge bg-info">' . $cfInviteText('cfclient.invite.leaderboard.realtime_badge', '实时Top10', [], true) . '</span>';
                                                echo '<div class="table-responsive mt-2">';
                                                echo '<table class="table table-sm table-striped">';
                                                echo '<?php echo $inviteTableHeadHtml; ?><tbody>';
                                                $i=1; foreach($rtTopH as $rw){
                                                    $uid = intval($rw->inviter_userid ?? 0);
                                                    $email = $rtTopHEmailMap[$uid] ?? '';
                                                    $emailMasked = cfmod_client_mask_leaderboard_email($email);
                                                    $codeVal = $rtTopHCodeMap[$uid] ?? '';
                                                    $codeMasked = cfmod_mask_invite_code($codeVal);
                                                    echo '<tr'.($uid===intval($userid)?' class="table-warning"':''). '>';
                                                    echo '<td>'.$i.'</td><td><?php echo $inviteHiddenLabel; ?></td><td>'.htmlspecialchars($emailMasked).'</td><td><code>'.htmlspecialchars($codeMasked).'</code></td><td>'.intval($rw->cnt ?? 0).'</td>';
                                                    echo '</tr>';
                                                    $i++; }
                                                echo '</tbody></table></div></div>';
                                            }
                                        ?>
                                        <?php
                                        // 显示最近的历史快照
                                        try {
                                            $recentSnapshots = Capsule::table('mod_cloudflare_invite_leaderboard')
                                                ->orderBy('period_start', 'desc')
                                                ->limit(3)
                                                ->get();
                                        } catch (Exception $e) { $recentSnapshots = []; }
                                        ?>
                                        <?php if (!empty($recentSnapshots)): ?>
                                            <h6 class="mt-3"><?php echo $cfInviteText('cfclient.invite.leaderboard.snapshots.title', '最近期数快照：', [], true); ?></h6>
                                            <div class="table-responsive">
                                                <table class="table table-sm table-striped">
                                                    <thead><tr><th><?php echo $cfInviteText('cfclient.invite.leaderboard.snapshots.period', '周期', [], true); ?></th><th><?php echo $cfInviteText('cfclient.invite.leaderboard.snapshots.start', '开始时间', [], true); ?></th><th><?php echo $cfInviteText('cfclient.invite.leaderboard.snapshots.end', '结束时间', [], true); ?></th><th><?php echo $cfInviteText('cfclient.invite.leaderboard.snapshots.actions', '操作', [], true); ?></th></tr></thead>
                                                    <tbody>
                                                        <?php foreach($recentSnapshots as $snapshot): ?>
                                                        <tr>
                                                            <td><?php echo htmlspecialchars($cfInviteText('cfclient.invite.leaderboard.snapshots.range', '%1$s 至 %2$s', [$snapshot->period_start, $snapshot->period_end], false)); ?></td>
                                                            <td><small><?php echo htmlspecialchars($snapshot->period_start); ?></small></td>
                                                            <td><small><?php echo htmlspecialchars($snapshot->period_end); ?></small></td>
                                                            <td>
                                                                <button type="button" class="btn btn-sm btn-outline-primary" onclick="viewSnapshot('<?php echo htmlspecialchars($snapshot->period_start); ?>', '<?php echo htmlspecialchars($snapshot->period_end); ?>')">
                                                                    <?php echo $cfInviteText('cfclient.invite.leaderboard.snapshots.view', '查看详情', [], true); ?>
                                                                </button>
                                                            </td>
                                                        </tr>
                                                        <?php endforeach; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                        <?php else: ?>
                                            <div class="text-muted"><?php echo $cfInviteText('cfclient.invite.leaderboard.snapshots.empty', '暂无历史快照数据', [], true); ?></div>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <!-- 正常显示本周排行榜 -->
                                        <?php
                                        // 计算上期结算的周期：支持自定义周期开始
                                        if ($inviteCycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $inviteCycleStart)) {
                                            $startTs = strtotime($inviteCycleStart);
                                            $todayTs = strtotime(date('Y-m-d'));
                                            if ($todayTs >= $startTs) {
                                                $k = (int) floor((($todayTs - $startTs) / 86400) / $inviteLeaderboardDays);
                                                // 计算上期的开始和结束日期
                                                $periodStart = date('Y-m-d', strtotime('+' . (($k - 1) * $inviteLeaderboardDays) . ' days', $startTs));
                                                $periodEnd = date('Y-m-d', strtotime('+' . (($k * $inviteLeaderboardDays) - 1) . ' days', $startTs));
                                            } else {
                                                // 如果当前日期在周期开始日期之前，则显示空数据
                                                $periodStart = date('Y-m-d', strtotime('yesterday'));
                                                $periodEnd = date('Y-m-d', strtotime('yesterday'));
                                            }
                                        } else {
                                            // 默认按周计算，上期结束日为昨天
                                            $periodEnd = date('Y-m-d', strtotime('yesterday'));
                                            $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($inviteLeaderboardDays - 1) . ' days'));
                                        }
                                        

                                        try {
                                            // 只显示已生成的奖励表（历史快照数据），不显示实时统计
                                            $winners = Capsule::table('mod_cloudflare_invite_rewards as r')
                                                ->select('r.inviter_userid', 'r.rank', 'r.count', 'r.code')
                                                ->where('r.period_start', $periodStart)
                                                ->where('r.period_end', $periodEnd)
                                                ->orderBy('r.rank', 'asc')
                                                ->limit(5)
                                                ->get();
                                            // 如果没有历史快照数据，则显示空数组，不回退到实时统计
                                        } catch (Exception $e) { $winners = []; }
                                        ?>
                                        <div class="table-responsive">
                                            <table class="table table-sm table-striped">
                                                <?php echo $inviteTableHeadHtml; ?>
                                                <tbody>
                                                <?php if (!empty($winners)):
                                                    $winnerUserIds = [];
                                                    foreach ($winners as $winnerRow) {
                                                        $uid = intval($winnerRow->inviter_userid ?? 0);
                                                        if ($uid > 0) {
                                                            $winnerUserIds[] = $uid;
                                                        }
                                                    }
                                                    list($winnerEmailMap, $winnerCodeMap) = cfmod_client_fetch_invite_user_meta($winnerUserIds);
                                                    $ranked=1; foreach($winners as $w):
                                                        $uid = intval($w->inviter_userid ?? 0);
                                                        $email = $winnerEmailMap[$uid] ?? '';
                                                        $emailMasked = cfmod_client_mask_leaderboard_email($email);
                                                        $codeFromRewards = isset($w->code) ? ($w->code ?? '') : '';
                                                        $codeVal = $codeFromRewards !== '' ? $codeFromRewards : ($winnerCodeMap[$uid] ?? '');
                                                        $codeMasked = cfmod_mask_invite_code($codeVal);
                                                ?>
                                                    <?php $rankValue = isset($w->rank) ? intval($w->rank) : $ranked; ?>
                                                    <tr <?php echo ($uid===intval($userid))?'class="table-warning"':''; ?>>
                                                        <td><?php echo $rankValue; ?></td>
                                                        <td><?php echo $inviteHiddenLabel; ?></td>
                                                        <td><?php echo htmlspecialchars($emailMasked); ?></td>
                                                        <td><code><?php echo htmlspecialchars($codeMasked); ?></code></td>
                                                        <td><?php echo intval(isset($w->count) ? $w->count : ($w->cnt ?? 0)); ?></td>
                                                    </tr>
                                                <?php $ranked++; endforeach; else: ?>
                                                    <tr><td colspan="5" class="text-center text-muted"><?php echo $inviteEmptyLabel; ?></td></tr>
                                                <?php endif; ?>
                                                </tbody>
                                            </table>
                                        </div>
                                        
                                        <?php
                                        // 判断本人是否上榜
                                        $myRank = null; $myCount = 0;
                                        if (!empty($winners)) {
                                            $idx=1; foreach($winners as $w){
                                                $rankValue = isset($w->rank) ? intval($w->rank) : $idx;
                                                if (intval($w->inviter_userid)===intval($userid)) { $myRank=$rankValue; $myCount=intval(isset($w->count)?$w->count:($w->cnt ?? 0)); break; }
                                                $idx++;
                                            }
                                        }
                                        
                                        ?>
                                        <?php if ($myRank !== null): ?>
                                            <div class="alert alert-success mt-3" id="prize-display-section">
                                                <?php echo $cfInviteText('cfclient.invite.prize.congrats', '恭喜！您上期排名第 %1$s，使用次数 %2$s。', [number_format($myRank), number_format($myCount)], true); ?>
                                                <?php
                                                $resolvedPrize = '';
                                                if (isset($cfInviteResolvePrize) && is_callable($cfInviteResolvePrize)) {
                                                    $resolvedPrize = trim((string) call_user_func($cfInviteResolvePrize, intval($myRank)));
                                                }
                                                if ($resolvedPrize === '') {
                                                    $rankIdx = intval($myRank);
                                                    if (!empty($invitePrizeDefaults[$rankIdx])) {
                                                        $resolvedPrize = trim((string) $invitePrizeDefaults[$rankIdx]);
                                                    }
                                                }
                                                if ($resolvedPrize !== '') {
                                                    echo '<div class="mt-1" id="prize-info"><strong>' . $cfInviteText('cfclient.invite.prize.previous_title', '上期奖品：', [], true) . '</strong>' . htmlspecialchars($resolvedPrize) . '</div>';
                                                }
                                                ?>
                                            </div>
                                            <?php
                                            // 根据当前周期的奖励状态，控制兑换按钮显示
                                            $existingReward = null;
                                            try {
                                                $existingReward = Capsule::table('mod_cloudflare_invite_rewards')
                                                    ->where('period_start', $periodStart)
                                                    ->where('period_end', $periodEnd)
                                                    ->where('inviter_userid', $userid)
                                                    ->first();
                                            } catch (Exception $e) { $existingReward = null; }
                                            ?>
                                            <?php if ($existingReward && ($existingReward->status === 'claimed')): ?>
                                                <div class="alert alert-success mt-2 mb-0">
                                                    <?php
                                                        $claimedAtText = $existingReward->claimed_at ? ('（' . htmlspecialchars($existingReward->claimed_at) . '）') : '';
                                                        echo $cfInviteText('cfclient.invite.prize.claimed_notice', '上期奖励已领取%1$s。', [$claimedAtText], false);
                                                    ?>
                                                </div>
                                                <div class="small text-muted mt-1"><?php echo $cfInviteText('cfclient.invite.prize.waiting', '本期未结束，等待周期结束排名。', [], true); ?></div>
                                            <?php elseif ($existingReward && ($existingReward->status === 'pending')): ?>
                                                <button type="button" class="btn btn-outline-secondary mt-2" disabled>
                                                    <i class="fas fa-hourglass-half"></i> <?php echo $cfInviteText('cfclient.invite.prize.pending', '已申请，等待处理', [], true); ?>
                                                </button>
                                            <?php else: ?>
                                                <?php
                                                // 周期结束后允许兑换（统一规则：今日日期 > 上期结束日）
                                                $canRedeem = (date('Y-m-d') > $periodEnd);
                                                ?>
                                                <form method="post" class="mt-2">
                                                    <input type="hidden" name="action" value="request_invite_reward">
                                                    <button type="submit" class="btn btn-outline-success" <?php echo $canRedeem ? '' : 'disabled'; ?>><i class="fas fa-gift"></i> <?php echo $cfInviteText('cfclient.invite.prize.redeem_button', '兑换礼品', [], true); ?></button>
                                                </form>
                                                <?php if (!$canRedeem): ?>
                                                    <div class="small text-muted mt-1"><?php echo $cfInviteText('cfclient.invite.prize.wait_until', '上期尚未结束，请在 %s 之后再申请兑换。', [htmlspecialchars($periodEnd)], false); ?></div>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <div class="alert alert-info mt-3"><?php echo $cfInviteText('cfclient.invite.prize.encourage', '再接再厉，邀请更多好友，就有机会进入排行榜并兑换礼品。', [], true); ?></div>
                                        <?php endif; ?>

                                        <?php if (!empty($invitePrizeDisplayRows) || !empty($inviteRewardInstructions)): ?>
                                            <div class="card border-0 shadow-sm mt-3" id="invitePrizeTableCard">
                                                <div class="card-body">
                                                    <div class="d-flex align-items-center mb-3">
                                                      <i class="fas fa-gift text-primary me-2"></i>
                                                      <div>
                                                        <div class="fw-bold"><?php echo $cfInviteText('cfclient.invite.prize.section_title', '本期奖品配置', [], true); ?></div>
                                                        <?php if (!empty($prizeSectionSubtitle)): ?>
                                                            <small class="text-muted"><?php echo htmlspecialchars($prizeSectionSubtitle); ?></small>
                                                        <?php endif; ?>
                                                      </div>
                                                    </div>
                                                    <?php if (!empty($invitePrizeDisplayRows)): ?>
                                                    <div class="table-responsive">
                                                        <table class="table table-sm table-bordered mb-0">
                                                            <thead><tr><th><?php echo $cfInviteText('cfclient.invite.prize.table.rank', '名次', [], true); ?></th><th><?php echo $cfInviteText('cfclient.invite.prize.table.reward', '奖品', [], true); ?></th></tr></thead>
                                                            <tbody>
                                                            <?php foreach ($invitePrizeDisplayRows as $row): ?>
                                                                <tr>
                                                                    <td><?php echo htmlspecialchars($row['range']); ?></td>
                                                                    <td><?php echo htmlspecialchars($row['reward']); ?></td>
                                                                </tr>
                                                            <?php endforeach; ?>
                                                            </tbody>
                                                        </table>
                                                    </div>
                                                    <?php endif; ?>
                                                    <?php if (!empty($inviteRewardInstructions)): ?>
                                                        <div class="small text-muted mt-2" id="prize-instructions"><?php echo nl2br(htmlspecialchars($inviteRewardInstructions)); ?></div>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        <?php endif; ?>

                                        <?php
                                        // 倒计时：本期剩余时间（基于当前周期计算）
                                        $now = time();
                                        // 计算当前周期的结束时间
                                        if ($inviteCycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $inviteCycleStart)) {
                                            $startTs = strtotime($inviteCycleStart);
                                            $todayTs = strtotime(date('Y-m-d'));
                                            if ($todayTs >= $startTs) {
                                                $k = (int) floor((($todayTs - $startTs) / 86400) / $inviteLeaderboardDays);
                                                // 计算当前周期的结束时间
                                                $currentPeriodEnd = date('Y-m-d', strtotime('+' . (($k * $inviteLeaderboardDays) + $inviteLeaderboardDays - 1) . ' days', $startTs));
                                            } else {
                                                // 如果当前日期在周期开始日期之前，则使用周期开始日期+周期天数-1
                                                $currentPeriodEnd = date('Y-m-d', strtotime($inviteCycleStart . ' +' . ($inviteLeaderboardDays - 1) . ' days'));
                                            }
                                        } else {
                                            // 默认按周计算，当前周期结束日为本周日
                                            $currentPeriodEnd = date('Y-m-d', strtotime('next sunday'));
                                        }
                                        $currentPeriodEndTs = strtotime($currentPeriodEnd . ' 23:59:59');
                                        $remain = max(0, $currentPeriodEndTs - $now);
                                        $countdownLabel = $cfInviteText('cfclient.invite.countdown.label', '本期剩余时间', [], true);
$inviteCountdownDayUnit = $cfInviteText('cfclient.invite.countdown.day_unit', '天 ', [], true);
                                        ?>
                                        <div class="mt-3">
                                            <span class="badge bg-secondary"><?php echo $countdownLabel; ?></span>
                                            <span id="leaderboardCountdown" class="ms-2 fw-bold"></span>
                                        </div>
                                        <script>
                                        (function(){
                                            var remain = <?php echo $remain; ?>;
            var inviteCountdownDayUnit = <?php echo json_encode($inviteCountdownDayUnit); ?>;
                                            function fmt(s){ s=Math.max(0,s); var d=Math.floor(s/86400); s%=86400; var h=Math.floor(s/3600); s%=3600; var m=Math.floor(s/60); var sec=s%60; return (d>0?d+inviteCountdownDayUnit:'')+String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0'); }
                                            function tick(){
                                                var el=document.getElementById('leaderboardCountdown'); if(!el) return; el.textContent=fmt(remain); if(remain>0){ remain--; setTimeout(tick,1000);} }
                                            tick();
                                        })();
                                        </script>
                                        <?php
                                        // 倒计时下方展示实时 Top10（一直显示，不检查周期结束）
                                        try {
                                            // 计算"当前周期"的实时窗口：
                                            // 有自定义起始 -> 找到包含今天的周期起始；否则用最近 N 天（含今天）
                                            if ($inviteCycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $inviteCycleStart)) {
                                                $startTs = strtotime($inviteCycleStart);
                                                $todayYmd = date('Y-m-d');
                                                $todayTs = strtotime($todayYmd);
                                                if ($todayTs >= $startTs) {
                                                    $k = (int) floor((($todayTs - $startTs) / 86400) / $inviteLeaderboardDays);
                                                    $rtStart2 = date('Y-m-d', strtotime('+' . ($k * $inviteLeaderboardDays) . ' days', $startTs));
                                                } else {
                                                    $rtStart2 = $todayYmd;
                                                }
                                                $rtEnd2 = date('Y-m-d');
                                            } else {
                                                $rtEnd2 = date('Y-m-d');
                                                $rtStart2 = date('Y-m-d', strtotime($rtEnd2 . ' -' . ($inviteLeaderboardDays - 1) . ' days'));
                                            }
                                            $rtTop5 = Capsule::table('mod_cloudflare_invitation_claims as ic')
                                                ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                                                ->whereBetween('ic.created_at', [$rtStart2.' 00:00:00', $rtEnd2.' 23:59:59'])
                                                ->groupBy('ic.inviter_userid')
                                                ->orderBy('cnt', 'desc')
                                                ->limit(10)
                                                ->get();
                                        } catch (Exception $e) { $rtTop5 = []; }
                                        echo '<div class="mt-2">';
                                        echo '<span class="badge bg-info">' . $cfInviteText('cfclient.invite.leaderboard.realtime_badge', '实时邀请Top10', [], true) . '</span>';
                                        echo '<div class="table-responsive mt-2">';
                                        echo '<table class="table table-sm table-striped" id="realtimeTopTable">';
                                        echo '<?php echo $inviteTableHeadHtml; ?><tbody id="realtimeTopBody">';
                                        echo '<tr><td colspan="5" class="text-center text-muted"><?php echo $inviteLoadingLabel; ?></td></tr>';
                                        echo '</tbody></table></div></div>';
                                        ?>
                                        <script>
                                        (function(){
                                            function render(rows){
                                                var tbody=document.getElementById('realtimeTopBody');
                                                if(!tbody) return;
                                                if(!rows || rows.length===0){ tbody.innerHTML='<tr><td colspan="5" class="text-center text-muted"><?php echo $inviteEmptyLabel; ?></td></tr>'; return; }
                                                var html='';
                                                rows.forEach(function(r){
                                                    html += '<tr>'+
                                                        '<td>'+r.rank+'</td>'+
                                                        '<td><?php echo $inviteHiddenLabel; ?></td>'+
                                                        '<td>'+r.emailMasked+'</td>'+
                                                        '<td><code>'+r.codeMasked+'</code></td>'+
                                                        '<td>'+r.count+'</td>'+
                                                    '</tr>';
                                                });
                                                tbody.innerHTML=html;
                                            }
                                            function load(){
                                                fetch('index.php?m=<?php echo htmlspecialchars($moduleSlug, ENT_QUOTES); ?>&action=realtime_top&limit=10', {
                                                    method: 'POST',
                                                    credentials: 'same-origin',
                                                    headers: {
                                                        'Content-Type': 'application/json',
                                                        'X-CSRF-Token': window.CF_MOD_CSRF || ''
                                                    },
                                                    body: '{}'
                                                })
                                                    .then(function(r){return r.json();})
                                                    .then(function(j){ if(j&&j.ok){ render(j.rows||[]);} else { render([]);} })
                                                    .catch(function(){ render([]); });
                                            }
                                            load();
                                            setInterval(load, 30000); // 每30秒刷新
                                        })();
                                        </script>
                                    <?php endif; ?>
                                </div>
                                <div class="tab-pane fade" id="realtime" role="tabpanel" aria-labelledby="realtime-tab">
                                    <?php
                                    // 计算当前周期起止（确保是新周期的开始）
                                    if ($inviteCycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $inviteCycleStart)) {
                                        $startTs = strtotime($inviteCycleStart);
                                        $todayTs = strtotime(date('Y-m-d'));
                                        if ($todayTs >= $startTs) {
                                            $k = (int) floor((($todayTs - $startTs) / 86400) / $inviteLeaderboardDays);
                                            $rtStart = date('Y-m-d', strtotime('+' . ($k * $inviteLeaderboardDays) . ' days', $startTs));
                                        } else {
                                            $rtStart = date('Y-m-d');
                                        }
                                        $rtEnd = date('Y-m-d');
                                    } else {
                                        $rtEnd = date('Y-m-d');
                                        $rtStart = date('Y-m-d', strtotime($rtEnd . ' -' . ($inviteLeaderboardDays - 1) . ' days'));
                                    }
                                    try {
                                        $rtTop = Capsule::table('mod_cloudflare_invitation_claims as ic')
                                            ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as cnt'))
                                            ->whereBetween('ic.created_at', [$rtStart.' 00:00:00', $rtEnd.' 23:59:59'])
                                            ->groupBy('ic.inviter_userid')
                                            ->orderBy('cnt', 'desc')
                                            ->limit(20)
                                            ->get();
                                    } catch (Exception $e) { $rtTop = []; }
                                    ?>
                                    <div class="table-responsive">
                                        <table class="table table-sm table-striped">
                                            <?php echo $inviteTableHeadHtml; ?>
                                            <tbody>
                                            <?php if (!empty($rtTop)):
                                                $rtTopUserIds = [];
                                                foreach ($rtTop as $row) {
                                                    $uid = intval($row->inviter_userid ?? 0);
                                                    if ($uid > 0) {
                                                        $rtTopUserIds[] = $uid;
                                                    }
                                                }
                                                list($rtTopEmailMap, $rtTopCodeMap) = cfmod_client_fetch_invite_user_meta($rtTopUserIds);
                                                $i=1; foreach($rtTop as $w):
                                                    $uid = intval($w->inviter_userid ?? 0);
                                                    $email = $rtTopEmailMap[$uid] ?? '';
                                                    $emailMasked = cfmod_client_mask_leaderboard_email($email);
                                                    $codeVal = $rtTopCodeMap[$uid] ?? '';
                                                    $codeMasked = cfmod_mask_invite_code($codeVal);
                                            ?>
                                                <tr <?php echo ($uid===intval($userid))?'class="table-warning"':''; ?>>
                                                    <td><?php echo $i; ?></td>
                                                    <td><?php echo $inviteHiddenLabel; ?></td>
                                                    <td><?php echo htmlspecialchars($emailMasked); ?></td>
                                                    <td><code><?php echo htmlspecialchars($codeMasked); ?></code></td>
                                                    <td><?php echo intval($w->cnt ?? 0); ?></td>
                                                </tr>
                                            <?php $i++; endforeach; else: ?>
                                                <tr><td colspan="5" class="text-center text-muted"><?php echo $inviteEmptyLabel; ?></td></tr>
                                            <?php endif; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            <script>
            function copyInviteCode(){
                var el = document.getElementById('myInviteCodeInput');
                var code = el ? el.value : '';
                if (!code) return;
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(code).then(function(){
                        try { alert(cfLang('invite.copySuccess', '邀请码已复制')); } catch (e) {}
                    }).catch(function(){
                        try { alert(cfLang('invite.copyFailed', '复制失败，请手动复制')); } catch (e) {}
                    });
                } else {
                    el.select();
                    try {
                        document.execCommand('copy');
                        alert(cfLang('invite.copySuccess', '邀请码已复制'));
                    } catch (e) {
                        alert(cfLang('invite.copyFailed', '复制失败，请手动复制'));
                    }
                }
            }
            
            // 保护奖品信息不被意外隐藏或删除
            (function() {
                var prizeSection = document.getElementById('prize-display-section');
                var prizeInfo = document.getElementById('prize-info');
                var prizeInstructions = document.getElementById('prize-instructions');
                
                if (prizeSection) {
                    // 监控奖品区域是否被意外修改
                    var observer = new MutationObserver(function(mutations) {
                        mutations.forEach(function(mutation) {
                            if (mutation.type === 'childList' && mutation.removedNodes.length > 0) {
                                // 如果奖品信息被删除，尝试恢复
                                if (!document.getElementById('prize-info') && prizeInfo) {
                                    console.log('检测到奖品信息被删除，尝试恢复...');
                                    setTimeout(function() {
                                        if (prizeSection && !document.getElementById('prize-info')) {
                                            prizeSection.appendChild(prizeInfo.cloneNode(true));
                                        }
                                    }, 100);
                                }
                            }
                        });
                    });
                    
                    observer.observe(prizeSection, {
                        childList: true,
                        subtree: true
                    });
                    
                    // 定期检查奖品信息是否存在
                    setInterval(function() {
                        if (prizeSection && !document.getElementById('prize-info') && prizeInfo) {
                            console.log('奖品信息丢失，正在恢复...');
                            prizeSection.appendChild(prizeInfo.cloneNode(true));
                        }
                    }, 5000);
                }
                
                // 调试信息：记录页面加载状态
                console.log('邀请排行榜页面已加载');
                if (prizeSection) console.log('奖品区域已找到');
                if (prizeInfo) console.log('奖品信息已找到');
                if (prizeInstructions) console.log('奖品说明已找到');
            })();
            
            // 查看快照详情
            function viewSnapshot(periodStart, periodEnd) {
                // 这里可以添加查看快照详情的逻辑
                // 比如弹窗显示或跳转到详情页面
                alert(cfLangFormat('invite.snapshotPreview', '查看期数：%1$s 至 %2$s 的快照详情\n\n功能开发中...', periodStart, periodEnd));
            }
            
            // 增强的奖品信息保护
            (function() {
                // 防止页面刷新或重新加载时奖品信息丢失
                window.addEventListener('beforeunload', function() {
                    // 保存奖品信息到 sessionStorage
                    var prizeInfo = document.getElementById('prize-info');
                    if (prizeInfo) {
                        sessionStorage.setItem('prizeInfo', prizeInfo.outerHTML);
                    }
                });
                
                // 页面加载完成后恢复奖品信息
                window.addEventListener('load', function() {
                    var savedPrizeInfo = sessionStorage.getItem('prizeInfo');
                    if (savedPrizeInfo) {
                        var prizeSection = document.getElementById('prize-display-section');
                        if (prizeSection && !document.getElementById('prize-info')) {
                            // 创建临时容器来解析HTML
                            var temp = document.createElement('div');
                            temp.innerHTML = savedPrizeInfo;
                            var restoredPrizeInfo = temp.firstChild;
                            if (restoredPrizeInfo) {
                                prizeSection.appendChild(restoredPrizeInfo);
                                console.log('从sessionStorage恢复奖品信息');
                            }
                        }
                        // 清理存储
                        sessionStorage.removeItem('prizeInfo');
                    }
                });
                
                // 额外的保护：监听DOM变化
                var bodyObserver = new MutationObserver(function(mutations) {
                    mutations.forEach(function(mutation) {
                        if (mutation.type === 'childList') {
                            // 检查是否有奖品信息被意外删除
                            var prizeSection = document.getElementById('prize-display-section');
                            if (prizeSection && !document.getElementById('prize-info')) {
                                console.log('检测到奖品信息丢失，尝试从备份恢复...');
                                // 这里可以添加更多的恢复逻辑
                            }
                        }
                    });
                });
                
                bodyObserver.observe(document.body, {
                    childList: true,
                    subtree: true
                });
            })();
            </script>

