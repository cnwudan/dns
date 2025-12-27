<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$LANG = $LANG ?? [];
$lang = $LANG['domainHub'] ?? [];
$announcementView = $announcementView ?? ($cfAdminViewModel['announcements'] ?? []);
$admin_announce_enabled = (string) ($announcementView['enabled'] ?? '0');
$admin_announce_title = (string) ($announcementView['title'] ?? '公告');
$admin_announce_html = (string) ($announcementView['html'] ?? '');

$titleText = $lang['announcement_card_title'] ?? '后台公告';
$enableLabel = $lang['announcement_enable_label'] ?? '启用公告';
$titleLabel = $lang['announcement_title_label'] ?? '标题';
$contentLabel = $lang['announcement_content_label'] ?? '内容（支持HTML）';
$saveLabel = $lang['announcement_save_button'] ?? '保存公告';
$modalButton = $lang['announcement_modal_ack'] ?? '我知道了';
?>

<div class="card mb-4" id="admin-announcements">
  <div class="card-body">
    <h5 class="card-title mb-3"><i class="fas fa-bullhorn"></i> <?php echo htmlspecialchars($titleText); ?></h5>
    <form method="post" class="row g-3">
      <input type="hidden" name="action" value="save_admin_announce">
      <div class="col-12 col-md-2">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" name="admin_announce_enabled" value="1" id="admin_announce_enabled" <?php echo $admin_announce_enabled === '1' ? 'checked' : ''; ?>>
          <label class="form-check-label" for="admin_announce_enabled"><?php echo htmlspecialchars($enableLabel); ?></label>
        </div>
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label" for="admin_announce_title_input"><?php echo htmlspecialchars($titleLabel); ?></label>
        <input type="text" id="admin_announce_title_input" class="form-control" name="admin_announce_title" value="<?php echo htmlspecialchars($admin_announce_title); ?>" placeholder="<?php echo htmlspecialchars($titleLabel); ?>">
      </div>
      <div class="col-12">
        <label class="form-label" for="admin_announce_html_input"><?php echo htmlspecialchars($contentLabel); ?></label>
        <textarea class="form-control" id="admin_announce_html_input" name="admin_announce_html" rows="4" placeholder="<?php echo htmlspecialchars($contentLabel); ?>"><?php echo str_replace('</textarea>', '&lt;/textarea>', $admin_announce_html); ?></textarea>
      </div>
      <div class="col-12">
        <button class="btn btn-primary"><?php echo htmlspecialchars($saveLabel); ?></button>
      </div>
    </form>
  </div>
</div>

<?php if ($admin_announce_enabled === '1'): ?>
<div class="modal fade" id="adminAnnounceModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="fas fa-bullhorn me-2"></i><?php echo htmlspecialchars($admin_announce_title); ?></h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
      </div>
      <div class="modal-body">
        <div><?php echo $admin_announce_html; ?></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-primary" data-dismiss="modal" id="adminAnnounceDismiss"><?php echo htmlspecialchars($modalButton); ?></button>
      </div>
    </div>
  </div>
</div>

<?php endif; ?>
