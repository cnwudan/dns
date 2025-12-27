<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$__ = static function (string $key, string $fallback = '') use ($lang): string {
    return htmlspecialchars($lang[$key] ?? $fallback, ENT_QUOTES, 'UTF-8');
};
$__raw = static function (string $key, string $fallback = '') use ($lang): string {
    return $lang[$key] ?? $fallback;
};
$inviteView = $cfAdminViewModel['invite'] ?? [];
$rewardSection = $inviteView['rewards'] ?? [];
$periodStart = $rewardSection['periodStart'] ?? '';
$periodEnd = $rewardSection['periodEnd'] ?? '';
$reward_list = $rewardSection['items'] ?? [];
$inviteStatsView = $inviteView['stats'] ?? [];
$invite_stats = $inviteStatsView['items'] ?? [];
$invPage = $inviteStatsView['page'] ?? 1;
$invPerPage = $inviteStatsView['perPage'] ?? 20;
$invTotal = $inviteStatsView['total'] ?? (is_countable($invite_stats) ? count($invite_stats) : 0);
$invTotalPages = $inviteStatsView['totalPages'] ?? 1;
$top20 = $inviteView['top'] ?? [];
$snapshotsView = $inviteView['history'] ?? [];
$leaderboard_history = $snapshotsView['items'] ?? [];
$snapPage = $snapshotsView['page'] ?? 1;
$snapPerPage = $snapshotsView['perPage'] ?? 20;
$snapTotal = $snapshotsView['total'] ?? (is_countable($leaderboard_history) ? count($leaderboard_history) : 0);
$snapTotalPages = $snapshotsView['totalPages'] ?? 1;
?>

<div class="card mb-4">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-chart-line"></i> <?php echo $__('invite_stats_title', '邀请统计'); ?></h5>
    <div class="table-responsive">
      <table class="table table-sm table-striped">
        <thead>
          <tr>
            <th><?php echo $__('invite_stats_header_inviter_id', '邀请方用户ID'); ?></th>
            <th><?php echo $__('invite_stats_header_email', '邀请方 Email'); ?></th>
            <th><?php echo $__('invite_stats_header_total', '累计成功邀请数'); ?></th>
            <th><?php echo $__('invite_stats_header_last', '最近一次时间'); ?></th>
          </tr>
        </thead>
        <tbody>
          <?php if (!empty($invite_stats)): ?>
            <?php foreach ($invite_stats as $st): ?>
              <tr>
                <td><?php echo intval($st->inviter_userid); ?></td>
                <td><?php echo htmlspecialchars($st->inviter_email ?? ''); ?></td>
                <td><?php echo intval($st->claims); ?></td>
                <td><small class="text-muted"><?php echo htmlspecialchars($st->last_claim ?? ''); ?></small></td>
              </tr>
            <?php endforeach; ?>
          <?php else: ?>
            <tr><td colspan="4" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
    <?php if ($invTotalPages > 1): ?>
      <nav aria-label="<?php echo $__('invite_stats_pagination_aria', '邀请统计分页'); ?>" class="mt-2">
        <ul class="pagination pagination-sm justify-content-center">
          <?php if ($invPage > 1): ?><li class="page-item"><a class="page-link" href="?module=domain_hub&inv_page=<?php echo $invPage-1; ?>#invite_stats"><?php echo $__('common_prev', '上一页'); ?></a></li><?php endif; ?>
          <?php for ($i = 1; $i <= $invTotalPages; $i++): ?>
            <?php if ($i == $invPage): ?>
              <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
            <?php elseif ($i==1 || $i==$invTotalPages || abs($i-$invPage)<=2): ?>
              <li class="page-item"><a class="page-link" href="?module=domain_hub&inv_page=<?php echo $i; ?>#invite_stats"><?php echo $i; ?></a></li>
            <?php elseif (abs($i-$invPage)==3): ?>
              <li class="page-item disabled"><span class="page-link">...</span></li>
            <?php endif; ?>
          <?php endfor; ?>
          <?php if ($invPage < $invTotalPages): ?><li class="page-item"><a class="page-link" href="?module=domain_hub&inv_page=<?php echo $invPage+1; ?>#invite_stats"><?php echo $__('common_next', '下一页'); ?></a></li><?php endif; ?>
        </ul>
        <div class="text-center text-muted small"><?php echo sprintf($__('pagination_summary', '第 %1$d / %2$d 页（共 %3$d 条）'), $invPage, $invTotalPages, $invTotal); ?></div>
      </nav>
    <?php endif; ?>
  </div>
</div>

<div class="card mb-4">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-trophy"></i> <?php echo $__('invite_top_title', '邀请排行榜（前20名）'); ?></h5>
    <div class="table-responsive">
      <table class="table table-sm table-striped align-middle">
        <thead><tr><th>#</th><th><?php echo $__('common_user_id', '用户ID'); ?></th><th><?php echo $__('common_email', 'Email'); ?></th><th><?php echo $__('invite_top_header_count', '邀请次数'); ?></th><th><?php echo $__('invite_top_header_last', '最近一次'); ?></th></tr></thead>
        <tbody>
          <?php if (!empty($top20)): $rank=1; foreach($top20 as $row): ?>
            <tr>
              <td><?php echo $rank++; ?></td>
              <td><?php echo intval($row->inviter_userid); ?></td>
              <td><?php echo htmlspecialchars($row->email ?? ''); ?></td>
              <td><span class="badge bg-primary"><?php echo intval($row->claims); ?></span></td>
              <td><small class="text-muted"><?php echo htmlspecialchars($row->last_claim ?? ''); ?></small></td>
            </tr>
          <?php endforeach; else: ?>
            <tr><td colspan="5" class="text-center text-muted"><?php echo $__('common_no_data', '暂无数据'); ?></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="card mb-4">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-history"></i> <?php echo $__('invite_snapshots_title', '历史期数快照'); ?></h5>
    <div class="table-responsive">
      <table class="table table-sm table-striped align-middle">
        <thead><tr><th><?php echo $__('invite_snapshots_header_start', '周期开始'); ?></th><th><?php echo $__('invite_snapshots_header_end', '周期结束'); ?></th><th><?php echo $__('invite_snapshots_header_payload', 'Top JSON'); ?></th></tr></thead>
        <tbody>
          <?php if (!empty($leaderboard_history)): foreach($leaderboard_history as $row): ?>
            <tr>
              <td><code><?php echo htmlspecialchars($row->period_start); ?></code></td>
              <td><code><?php echo htmlspecialchars($row->period_end); ?></code></td>
              <td><small class="text-muted" style="word-break:break-all;display:inline-block;max-width:640px;"><?php echo htmlspecialchars($row->top_json); ?></small></td>
            </tr>
          <?php endforeach; else: ?>
            <tr><td colspan="3" class="text-center text-muted"><?php echo $__('invite_snapshots_empty', '暂无快照'); ?></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
    <?php if ($snapTotalPages > 1): ?>
      <nav aria-label="<?php echo $__('invite_snapshots_pagination_aria', '历史期数分页'); ?>" class="mt-2">
        <ul class="pagination pagination-sm justify-content-center">
          <?php if ($snapPage > 1): ?><li class="page-item"><a class="page-link" href="?module=domain_hub&snap_page=<?php echo $snapPage-1; ?>#snapshots"><?php echo $__('common_prev', '上一页'); ?></a></li><?php endif; ?>
          <?php for($i=1;$i<=$snapTotalPages;$i++): ?>
            <?php if ($i == $snapPage): ?>
              <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
            <?php elseif ($i==1 || $i==$snapTotalPages || abs($i-$snapPage)<=2): ?>
              <li class="page-item"><a class="page-link" href="?module=domain_hub&snap_page=<?php echo $i; ?>#snapshots"><?php echo $i; ?></a></li>
            <?php elseif (abs($i-$snapPage)==3): ?>
              <li class="page-item disabled"><span class="page-link">...</span></li>
            <?php endif; ?>
          <?php endfor; ?>
          <?php if ($snapPage < $snapTotalPages): ?><li class="page-item"><a class="page-link" href="?module=domain_hub&snap_page=<?php echo $snapPage+1; ?>#snapshots"><?php echo $__('common_next', '下一页'); ?></a></li><?php endif; ?>
        </ul>
        <div class="text-center text-muted small"><?php echo sprintf($__('pagination_summary', '第 %1$d / %2$d 页（共 %3$d 条）'), $snapPage, $snapTotalPages, $snapTotal); ?></div>
      </nav>
    <?php endif; ?>
  </div>
</div>

<div class="card mb-4">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-gift"></i> <?php echo $__('invite_rewards_title', '礼品兑换申请（本期）'); ?></h5>
    <form method="post" class="row g-2 mb-3 align-items-end">
      <div class="col-auto">
        <label class="form-label"><?php echo $__('invite_rewards_form_user', '用户邮箱或ID'); ?></label>
        <input type="text" name="user_identifier" class="form-control" placeholder="email@example.com" >
      </div>
      <div class="col-auto">
        <label class="form-label"><?php echo $__('invite_rewards_form_rank', '名次'); ?></label>
        <input type="number" name="rank" class="form-control" min="1" value="1">
      </div>
      <div class="col-auto">
        <label class="form-label"><?php echo $__('invite_rewards_form_count', '次数'); ?></label>
        <input type="number" name="count" class="form-control" min="0" value="0">
      </div>
      <div class="col-auto">
        <label class="form-label"><?php echo $__('invite_rewards_form_code', '邀请码（可选）'); ?></label>
        <input type="text" name="code" class="form-control" placeholder="<?php echo $__('invite_rewards_form_code_placeholder', '留空自动取值'); ?>">
      </div>
      <div class="col-auto">
        <label class="form-label"><?php echo $__('invite_rewards_form_status', '状态'); ?></label>
        <select name="status" class="form-select">
          <option value="eligible">eligible</option>
          <option value="pending">pending</option>
          <option value="claimed">claimed</option>
        </select>
      </div>
      <div class="col-auto">
        <input type="hidden" name="action" value="admin_upsert_invite_reward">
        <button class="btn btn-outline-primary"><?php echo $__('invite_rewards_save_entry', '保存榜单条目'); ?></button>
      </div>
    </form>

    <form method="post" class="row g-2 mb-3 align-items-end">
      <div class="col-auto">
        <label class="form-label"><?php echo $__('invite_rewards_rebuild_label', '重建当前周期快照'); ?></label>
        <div class="input-group">
          <div class="input-group-text"><input type="checkbox" name="overwrite" value="1"> <?php echo $__('invite_rewards_rebuild_overwrite', '覆盖已有'); ?></div>
          <input type="hidden" name="action" value="admin_rebuild_invite_rewards">
          <button class="btn btn-outline-secondary"><?php echo $__('invite_rewards_rebuild_button', '一键重建'); ?></button>
        </div>
      </div>
    </form>

    <form method="post" class="row g-2 mb-3 align-items-end">
      <div class="col-auto">
        <label class="form-label"><?php echo $__('invite_rewards_settle_label', '手动结算上一期'); ?></label>
        <div class="input-group">
          <input type="hidden" name="action" value="admin_settle_last_period">
          <button class="btn btn-outline-danger" onclick="return confirm('<?php echo addslashes($__('invite_rewards_settle_confirm', '确认手动结算上一期？将写入快照与奖励。')); ?>');"><?php echo $__('invite_rewards_settle_button', '立即结算'); ?></button>
        </div>
      </div>
    </form>

    <div class="table-responsive">
      <table class="table table-sm table-striped align-middle">
        <thead><tr><th>#</th><th><?php echo $__('common_user_id', '用户ID'); ?></th><th><?php echo $__('common_email', 'Email'); ?></th><th><?php echo $__('invite_rewards_header_code', '邀请码'); ?></th><th><?php echo $__('invite_rewards_header_count', '次数'); ?></th><th><?php echo $__('invite_rewards_header_prize', '奖品'); ?></th><th><?php echo $__('invite_rewards_header_status', '状态'); ?></th><th><?php echo $__('invite_rewards_header_time', '申请时间'); ?></th><th><?php echo $__('common_actions', '操作'); ?></th></tr></thead>
        <tbody>
          <?php if (!empty($reward_list)): foreach($reward_list as $r): ?>
            <tr>
              <td><?php echo intval($r->rank); ?></td>
              <td><?php echo intval($r->inviter_userid); ?></td>
              <td><?php echo htmlspecialchars($r->email ?? ''); ?></td>
              <td><code><?php echo htmlspecialchars($r->code ?? ''); ?></code></td>
              <td><?php echo intval($r->count); ?></td>
              <td>
                <?php
                  $p1=$module_settings['invite_reward_prize_1']??'';
                  $p2=$module_settings['invite_reward_prize_2']??'';
                  $p3=$module_settings['invite_reward_prize_3']??'';
                  $p4=$module_settings['invite_reward_prize_4']??'';
                  $p5=$module_settings['invite_reward_prize_5']??'';
                  $prizeDefaults=[
                      1=>$p1,
                      2=>$p2,
                      3=>$p3,
                      4=>$p4,
                      5=>$p5,
                  ];
                  $map=$module_settings['invite_reward_prizes']??'';
                  $pr='';
                  if ($map){
                      $lines=preg_split('/\r?\n/',$map);
                      foreach($lines as $line){
                          $line=trim($line);
                          if($line==='') continue;
                          if (strpos($line,'=')!==false){
                              list($k,$v)=explode('=',$line,2);
                              $k=trim($k);
                              $v=trim($v);
                              if (preg_match('/^(\d+)-(\d+)$/',$k,$m)){
                                  $a=intval($m[1]);
                                  $b=intval($m[2]);
                                  if (intval($r->rank)>=$a && intval($r->rank)<=$b){ $pr=$v; break; }
                              } elseif (ctype_digit($k)){
                                  if (intval($k)===intval($r->rank)){ $pr=$v; break; }
                              }
                          }
                      }
                  }
                  if ($pr===''){
                      $rankIdx = intval($r->rank);
                      if (!empty($prizeDefaults[$rankIdx])) {
                          $pr = $prizeDefaults[$rankIdx];
                      }
                  }
                  echo htmlspecialchars($pr);
                ?>
              </td>
              <td>
                <span class="badge bg-<?php echo $r->status==='claimed'?'success':($r->status==='pending'?'warning':'secondary'); ?>">
                  <?php echo htmlspecialchars($r->status); ?>
                </span>
              </td>
              <td><small class="text-muted"><?php echo htmlspecialchars($r->requested_at ?? ''); ?></small></td>
              <td>
                <?php if ($r->status !== 'claimed'): ?>
                  <form method="post" class="d-inline" onsubmit="return confirm('<?php echo addslashes($__('invite_rewards_mark_confirm', '确认标记为已发放？')); ?>');">
                    <input type="hidden" name="action" value="mark_reward_claimed">
                    <input type="hidden" name="reward_id" value="<?php echo intval($r->id); ?>">
                    <button class="btn btn-sm btn-outline-success"><?php echo $__('invite_rewards_mark_button', '标记已发放'); ?></button>
                  </form>
                  <button class="btn btn-sm btn-outline-primary ms-1" data-toggle="collapse" data-target="#edit_<?php echo $r->id; ?>"><?php echo $__('invite_rewards_edit_button', '修改'); ?></button>
                  <form method="post" class="d-inline ms-1" onsubmit="return confirm('<?php echo addslashes($__('invite_rewards_remove_confirm', '确认移除该上榜用户？')); ?>');">
                    <input type="hidden" name="action" value="remove_leaderboard_user">
                    <input type="hidden" name="period_start" value="<?php echo htmlspecialchars($r->period_start); ?>">
                    <input type="hidden" name="period_end" value="<?php echo htmlspecialchars($r->period_end); ?>">
                    <input type="hidden" name="userid" value="<?php echo intval($r->inviter_userid); ?>">
                    <button class="btn btn-sm btn-outline-danger"><?php echo $__('invite_rewards_remove_button', '移除上榜'); ?></button>
                  </form>
                <?php else: ?>
                  <span class="text-muted"><?php echo sprintf($__('invite_rewards_claimed_text', '已发放于 %s'), htmlspecialchars($r->claimed_at ?? '')); ?></span>
                <?php endif; ?>
              </td>
            </tr>
            <tr class="collapse" id="edit_<?php echo $r->id; ?>">
              <td colspan="9">
                <form method="post" class="row g-2 align-items-end">
                  <input type="hidden" name="action" value="admin_edit_leaderboard_user">
                  <input type="hidden" name="reward_id" value="<?php echo intval($r->id); ?>">
                  <div class="col-auto">
                    <label class="form-label"><?php echo $__('invite_rewards_form_rank', '名次'); ?></label>
                    <input type="number" name="rank" class="form-control" min="1" value="<?php echo intval($r->rank); ?>">
                  </div>
                  <div class="col-auto">
                    <label class="form-label"><?php echo $__('invite_rewards_form_count', '次数'); ?></label>
                    <input type="number" name="count" class="form-control" min="0" value="<?php echo intval($r->count); ?>">
                  </div>
                  <div class="col-auto">
                    <label class="form-label"><?php echo $__('invite_rewards_header_code', '邀请码'); ?></label>
                    <input type="text" name="code" class="form-control" value="<?php echo htmlspecialchars($r->code ?? ''); ?>">
                  </div>
                  <div class="col-auto">
                    <button class="btn btn-primary"><?php echo $__('invite_rewards_edit_save', '保存修改'); ?></button>
                  </div>
                </form>
              </td>
            </tr>
          <?php endforeach; else: ?>
            <tr><td colspan="9" class="text-center text-muted"><?php echo $__('invite_rewards_empty', '暂无申请'); ?></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
