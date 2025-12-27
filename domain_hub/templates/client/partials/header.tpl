<?php
$headerTitle = htmlspecialchars(cfmod_trans('cfclient.header_title', 'DNSHE免费域名管理平台'), ENT_QUOTES);
$headerSubtitle = htmlspecialchars(cfmod_trans('cfclient.header_subtitle', '管理您的免费域名，设置DNS解析。'), ENT_QUOTES);
$announceFallbackTitle = htmlspecialchars(cfmod_trans('cfclient.announcement_title', '公告'), ENT_QUOTES);
$announceButtonText = htmlspecialchars(cfmod_trans('cfclient.announcement_confirm', '我知道了'), ENT_QUOTES);
$clientAnnounceTitleSafe = (isset($clientAnnounceTitle) && $clientAnnounceTitle !== '')
    ? htmlspecialchars($clientAnnounceTitle, ENT_QUOTES)
    : $announceFallbackTitle;
?>
<?php echo $cfmodClientNoscriptNotice ?? ''; ?>
<div class="main-container">
    <?php
        $languageOptions = isset($availableLanguages) && is_array($availableLanguages) ? $availableLanguages : [];
        $languageSwitchLabel = cfclient_lang('cfclient.language.switch_label', '选择语言', [], true);
        $activeLanguageLabel = $languageSwitchLabel;
        foreach ($languageOptions as $langOption) {
            if (!empty($langOption['active'])) {
                $activeLanguageLabel = htmlspecialchars($langOption['label'], ENT_QUOTES);
                break;
            }
        }
    ?>
    <!-- 头部区域 -->
    <div class="header-section text-center position-relative">
        <div class="position-absolute top-0 end-0 d-flex gap-2 align-items-start">
            <?php if (!empty($languageOptions)): ?>
                <div class="header-language-switcher dropdown">
                    <button class="btn btn-light btn-sm dropdown-toggle" type="button" id="cfmodLanguageDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="fas fa-language me-1"></i> <?php echo $activeLanguageLabel; ?>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="cfmodLanguageDropdown">
                        <li class="dropdown-header text-muted small"><?php echo $languageSwitchLabel; ?></li>
                        <?php foreach ($languageOptions as $langOption): ?>
                            <li>
                                <a class="dropdown-item <?php echo !empty($langOption['active']) ? 'active fw-bold' : ''; ?>" href="<?php echo htmlspecialchars($langOption['url'], ENT_QUOTES); ?>">
                                    <?php echo htmlspecialchars($langOption['label'], ENT_QUOTES); ?>
                                </a>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
        </div>
        <h1><i class="fas fa-globe"></i> <?php echo $headerTitle; ?></h1>
        <p class="mb-0"><?php echo $headerSubtitle; ?></p>
    </div>
    <?php if ($clientAnnounceEnabled): ?>
        <div class="modal fade" id="clientAnnounceModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-lg modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-bullhorn me-2"></i><?php echo $clientAnnounceTitleSafe; ?></h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div><?php echo $clientAnnounceHtml; ?></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-primary" data-bs-dismiss="modal" id="clientAnnounceDismiss"><?php echo $announceButtonText; ?></button>
                    </div>
                </div>
            </div>
        </div>
        <script>
            (function(){
                try{
                    var key=<?php echo json_encode($clientAnnounceCookieKey, CFMOD_SAFE_JSON_FLAGS); ?>;
                    if (document.cookie.indexOf(key+'=1')!==-1) return;
                    var show=function(){ var el=document.getElementById('clientAnnounceModal'); if(!el) return; var m=new bootstrap.Modal(el); m.show(); };
                    if (document.readyState==='complete') { setTimeout(show, 0); } else { window.addEventListener('load', function(){ setTimeout(show, 0); }); }
                    var btn=document.getElementById('clientAnnounceDismiss');
                    if (btn) btn.addEventListener('click', function(){
                        var d=new Date(); d.setFullYear(d.getFullYear()+1);
                        document.cookie = key+'=1; path=/; expires='+d.toUTCString();
                    });
                }catch(e){}
            })();
        </script>
    <?php endif; ?>
