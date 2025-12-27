<?php
// phpcs:ignoreFile

declare(strict_types=1);

use WHMCS\Database\Capsule;

require_once __DIR__ . '/../AtomicOperations.php';
require_once __DIR__ . '/../ErrorFormatter.php';
require_once __DIR__ . '/../TtlHelper.php';
require_once __DIR__ . '/../RootDomainLimitHelper.php';
require_once __DIR__ . '/../ProviderResolver.php';
require_once __DIR__ . '/DnsUnlockService.php';

class CfClientActionService
{
    public static function process(array $globals): array
    {
        if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return [];
        }

        if (!array_key_exists('action', $_POST)) {
            return [];
        }

        $action = (string) $_POST['action'];
        if ($action === '' || in_array($action, ['__csrf_failed__', '__maintenance__', '__banned__'], true)) {
            return [];
        }

        $isAsyncReplay = !empty($_POST['__cf_async_dns']);
        if ($isAsyncReplay) {
            unset($_POST['__cf_async_dns']);
        }

        extract($globals, EXTR_SKIP);

        $module_settings = $module_settings ?? [];
        $enableDnsUnlockFeature = cfmod_setting_enabled($module_settings['enable_dns_unlock'] ?? '0');
        $dnsUnlockPurchaseEnabled = cfmod_setting_enabled($module_settings['dns_unlock_purchase_enabled'] ?? '0');
        $dnsUnlockShareEnabled = cfmod_setting_enabled($module_settings['dns_unlock_share_enabled'] ?? '1');
        $dnsUnlockPurchasePrice = round(max(0, (float)($module_settings['dns_unlock_purchase_price'] ?? 0)), 2);
        $msg = $globals['msg'] ?? '';
        $msg_type = $globals['msg_type'] ?? '';
        $registerError = $globals['registerError'] ?? '';

        try {
            self::enforceClientRateLimit($action, $module_settings, intval($userid ?? 0));
        } catch (CfRateLimitExceededException $e) {
            $minutes = CfRateLimiter::formatRetryMinutes($e->getRetryAfterSeconds());
            $rateMessage = self::actionText('rate_limit.hit', '操作频率过高，请 %s 分钟后再试。', [$minutes]);
            if ($action === 'register') {
                $registerError = $rateMessage;
            } else {
                $msg = $rateMessage;
                $msg_type = 'danger';
            }
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }

        if ($_POST['action'] === 'purchase_dns_unlock') {
            if (!$enableDnsUnlockFeature) {
                $msg = self::actionText('dns.unlock.disabled', '当前未启用 DNS 解锁功能。');
                $msg_type = 'warning';
            } elseif (!$dnsUnlockPurchaseEnabled) {
                $msg = self::actionText('dns.unlock.purchase_disabled', 'Paid unlock is disabled.');
                $msg_type = 'warning';
            } elseif ($dnsUnlockPurchasePrice <= 0) {
                $msg = self::actionText('dns.unlock.purchase_invalid_price', 'Unlock price is not configured.');
                $msg_type = 'warning';
            } elseif ($userid <= 0) {
                $msg = self::actionText('dns.unlock.invalid', '未找到登录信息，请刷新页面后重试。');
                $msg_type = 'danger';
            } elseif (CfDnsUnlockService::userHasUnlocked($userid ?? 0)) {
                $msg = self::actionText('dns.unlock.already', '您已完成 DNS 解锁，无需再次操作。');
                $msg_type = 'info';
            } else {
                try {
                    $email = self::resolveClientEmail($userid);
                    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                    Capsule::transaction(function () use ($userid, $dnsUnlockPurchasePrice, $email, $ip) {
                        $clientRow = Capsule::table('tblclients')->where('id', $userid)->lockForUpdate()->first();
                        if (!$clientRow) {
                            throw new \RuntimeException('client_missing');
                        }
                        $currentCredit = (float) ($clientRow->credit ?? 0);
                        if (($currentCredit + 1e-6) < $dnsUnlockPurchasePrice) {
                            throw new \RuntimeException('insufficient_credit');
                        }
                        $newCredit = $currentCredit - $dnsUnlockPurchasePrice;
                        Capsule::table('tblclients')
                            ->where('id', $userid)
                            ->update(['credit' => number_format($newCredit, 2, '.', '')]);
                        static $creditSchemaInfoPurchase = null;
                        if ($creditSchemaInfoPurchase === null) {
                            $creditSchemaInfoPurchase = [
                                'has_table' => false,
                                'has_relid' => false,
                                'has_refundid' => false,
                            ];
                            try {
                                $creditSchemaInfoPurchase['has_table'] = Capsule::schema()->hasTable('tblcredit');
                                if ($creditSchemaInfoPurchase['has_table']) {
                                    $creditSchemaInfoPurchase['has_relid'] = Capsule::schema()->hasColumn('tblcredit', 'relid');
                                    $creditSchemaInfoPurchase['has_refundid'] = Capsule::schema()->hasColumn('tblcredit', 'refundid');
                                }
                            } catch (\Throwable $ignored) {
                                $creditSchemaInfoPurchase = [
                                    'has_table' => false,
                                    'has_relid' => false,
                                    'has_refundid' => false,
                                ];
                            }
                        }
                        if ($creditSchemaInfoPurchase['has_table']) {
                            $creditRow = [
                                'clientid' => $userid,
                                'date' => date('Y-m-d H:i:s'),
                                'description' => self::actionText('dns.unlock.purchase_credit_desc', 'DNS unlock purchase'),
                                'amount' => 0 - $dnsUnlockPurchasePrice,
                            ];
                            if ($creditSchemaInfoPurchase['has_relid']) {
                                $creditRow['relid'] = 0;
                            }
                            if ($creditSchemaInfoPurchase['has_refundid']) {
                                $creditRow['refundid'] = 0;
                            }
                            Capsule::table('tblcredit')->insert($creditRow);
                        }
                        CfDnsUnlockService::unlockByPurchase($userid, $email, $ip);
                    });
                    $msg = self::actionText('dns.unlock.purchase_success', 'DNS unlock completed via account balance.');
                    $msg_type = 'success';
                } catch (\RuntimeException $e) {
                    if ($e->getMessage() === 'insufficient_credit') {
                        $msg = self::actionText('dns.unlock.purchase_insufficient', 'Insufficient balance for unlock.');
                        $msg_type = 'danger';
                    } else {
                        $msg = self::actionText('dns.unlock.error', '解锁失败：%s', [$e->getMessage()]);
                        $msg_type = 'danger';
                    }
                } catch (\InvalidArgumentException $e) {
                    $reason = $e->getMessage();
                    if ($reason === 'owner_banned') {
                        $msg = self::actionText('dns.unlock.owner_banned', '该解锁码已失效，请联系管理员。');
                        $msg_type = 'danger';
                    } else {
                        $msg = self::actionText('dns.unlock.already', '您已完成 DNS 解锁，无需再次操作。');
                        $msg_type = 'info';
                    }
                } catch (\Throwable $e) {
                    $msg = self::actionText('dns.unlock.error', '解锁失败：%s', [$e->getMessage()]);
                    $msg_type = 'danger';
                }
            }
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }

        if ($_POST['action'] === 'dns_unlock') {
            if (!$enableDnsUnlockFeature) {
                $msg = self::actionText('dns.unlock.disabled', '当前未启用 DNS 解锁功能。');
                $msg_type = 'warning';
            } elseif ($userid <= 0) {
                $msg = self::actionText('dns.unlock.invalid', '未找到登录信息，请刷新页面后重试。');
                $msg_type = 'danger';
            } elseif (!$dnsUnlockShareEnabled) {
                $msg = self::actionText('dns.unlock.share_disabled', '管理员已关闭解锁码分享，请使用余额解锁。');
                $msg_type = 'warning';
            } else {
                $inputCode = strtoupper(trim($_POST['unlock_code'] ?? ''));
                if ($inputCode === '') {
                    $msg = self::actionText('dns.unlock.code_required', '请输入解锁码后再提交。');
                    $msg_type = 'warning';
                } else {
                    try {
                        $email = self::resolveClientEmail($userid);
                        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                        CfDnsUnlockService::unlockForUser($userid, $inputCode, $userid, $email, $ip);
                        $msg = self::actionText('dns.unlock.success', 'DNS 解锁成功，现在可以设置 NS 服务器。');
                        $msg_type = 'success';
                    } catch (\InvalidArgumentException $e) {
                        $reason = $e->getMessage();
                        if ($reason === 'self_code') {
                            $msg = self::actionText('dns.unlock.self', '不能使用自己的解锁码。');
                        } elseif ($reason === 'invalid_code') {
                            $msg = self::actionText('dns.unlock.invalid', '解锁码不正确，请核对后重试。');
                        } elseif ($reason === 'owner_banned') {
                            $msg = self::actionText('dns.unlock.owner_banned', '该解锁码已失效，请联系管理员。');
                        } elseif ($reason === 'already_unlocked') {
                            $msg = self::actionText('dns.unlock.already', '您已完成 DNS 解锁，无需再次操作。');
                        } else {
                            $msg = self::actionText('dns.unlock.error', '解锁失败：%s', [$reason]);
                        }
                        $msg_type = 'danger';
                    } catch (\Throwable $e) {
                        $msg = self::actionText('dns.unlock.error', '解锁失败：%s', [$e->getMessage()]);
                        $msg_type = 'danger';
                    }
                }
            }
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }

// 处理填写他人邀请码以解锁额度
if($_POST['action'] == 'claim_invite') {
    if ($hideInviteFeature) { $msg = self::actionText('invite.closed', '当前邀请功能已关闭'); $msg_type = 'warning'; }
    else {
    $inputCode = strtoupper(trim($_POST['invite_code'] ?? ''));
    // 动态刷新最新的全局邀请上限，并在每次填码前若用户配额未自定义上限，则对其 invite_bonus_limit 进行同步
    try {
        $inviteLimitGlobalSetting = Capsule::table('tbladdonmodules')
            ->where('module', defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub')
            ->where('setting','invite_bonus_limit_global')
            ->value('value');
        if ($inviteLimitGlobalSetting === null) {
            $inviteLimitGlobalSetting = Capsule::table('tbladdonmodules')
                ->where('module', defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : 'cloudflare_subdomain')
                ->where('setting','invite_bonus_limit_global')
                ->value('value');
        }
        $inviteLimitGlobal = intval($inviteLimitGlobalSetting ?? 5);
        $q = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userid)->first();
        if ($q) {
            $currentLimit = intval($q->invite_bonus_limit ?? 0);
            // 仅在用户当前上限等于默认值（或为0）时，同步为最新全局值，避免覆盖管理员为个别用户单独设置的上限
            if ($currentLimit <= 0 || $currentLimit === 5 || $currentLimit === intval($module_settings['invite_bonus_limit_global'] ?? 5)) {
                Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userid)->update([
                    'invite_bonus_limit' => $inviteLimitGlobal,
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                $quota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userid)->first();
            }
        }
    } catch (Exception $e) { /* 忽略 */ }
    if ($isUserBannedOrInactive) { $msg = self::actionText('invite.banned', '您的账号已被封禁或停用，无法解锁额度。') . ($banReasonText ? (' ' . $banReasonText) : ''); $msg_type = 'danger'; }
    elseif ($inputCode === '') { $msg = self::actionText('invite.input_empty', '请输入邀请码'); $msg_type = 'danger'; }
    else {
        try {
            $result = Capsule::connection()->transaction(function() use ($userid, $inputCode, $max, $inviteLimitGlobal) {
                $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->where('code', $inputCode)->first();
                if (!$codeRow) { throw new Exception(self::actionText('invite.invalid_code', '邀请码无效')); }
                if (intval($codeRow->userid) === intval($userid)) { throw new Exception(self::actionText('invite.self', '不能使用自己的邀请码')); }

                // 受邀者不可重复使用同一个邀请码
                $claimedSameCode = Capsule::table('mod_cloudflare_invitation_claims')
                    ->where('invitee_userid', $userid)
                    ->where('code', $inputCode)
                    ->first();
                if ($claimedSameCode) { throw new Exception(self::actionText('invite.used', '您已使用过该邀请码')); }

                // 确保双方配额记录存在
                $inviterQuota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $codeRow->userid)->first();
                if (!$inviterQuota) {
                    Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                        'userid' => $codeRow->userid,
                        'used_count' => 0,
                        'max_count' => $max,
                        'invite_bonus_count' => 0,
                        'invite_bonus_limit' => $inviteLimitGlobal > 0 ? $inviteLimitGlobal : 5,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ]);
                    $inviterQuota = (object)['userid'=>$codeRow->userid,'used_count'=>0,'max_count'=>$max,'invite_bonus_count'=>0,'invite_bonus_limit'=>($inviteLimitGlobal > 0 ? $inviteLimitGlobal : 5)];
                }
                $inviteeQuota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userid)->first();
                if (!$inviteeQuota) {
                    Capsule::table('mod_cloudflare_subdomain_quotas')->insert([
                        'userid' => $userid,
                        'used_count' => 0,
                        'max_count' => $max,
                        'invite_bonus_count' => 0,
                        'invite_bonus_limit' => $inviteLimitGlobal > 0 ? $inviteLimitGlobal : 5,
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ]);
                    $inviteeQuota = (object)['userid'=>$userid,'used_count'=>0,'max_count'=>$max,'invite_bonus_count'=>0,'invite_bonus_limit'=>($inviteLimitGlobal > 0 ? $inviteLimitGlobal : 5)];
                }

                $inviterLimit = intval($inviterQuota->invite_bonus_limit ?? 5);
                $inviteeLimit = intval($inviteeQuota->invite_bonus_limit ?? 5);
                $inviterBonus = intval($inviterQuota->invite_bonus_count ?? 0);
                $inviteeBonus = intval($inviteeQuota->invite_bonus_count ?? 0);

                // 若受邀者已达上限，则双方均不可获得加成
                if ($inviteeBonus >= $inviteeLimit) {
                    throw new Exception(self::actionText('invite.limit_reached', '达到额度上限，无法再增加'));
                }

                $inviterAdded = 0;
                $inviteeAdded = 0;

                // 邀请方加成（不超过上限）
                if ($inviterBonus < $inviterLimit) {
                    Capsule::table('mod_cloudflare_subdomain_quotas')
                        ->where('userid', $codeRow->userid)
                        ->update([
                            'invite_bonus_count' => $inviterBonus + 1,
                            'max_count' => intval($inviterQuota->max_count) + 1,
                            'updated_at' => date('Y-m-d H:i:s')
                        ]);
                    $inviterAdded = 1;
                }

                // 受邀方加成（不超过上限）
                if ($inviteeBonus < $inviteeLimit) {
                    Capsule::table('mod_cloudflare_subdomain_quotas')
                        ->where('userid', $userid)
                        ->update([
                            'invite_bonus_count' => $inviteeBonus + 1,
                            'max_count' => intval($inviteeQuota->max_count) + 1,
                            'updated_at' => date('Y-m-d H:i:s')
                        ]);
                    $inviteeAdded = 1;
                }

                // 记录本次使用
                Capsule::table('mod_cloudflare_invitation_claims')->insert([
                    'inviter_userid' => $codeRow->userid,
                    'invitee_userid' => $userid,
                    'code' => $inputCode,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);

                return ['inviterAdded' => $inviterAdded, 'inviteeAdded' => $inviteeAdded];
            });

            // 刷新本地配额信息
            try {
                $quota = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userid)->first();
            } catch (Exception $e) {}

            if ($result['inviteeAdded'] && $result['inviterAdded']) {
                $msg = self::actionText('invite.success_both', '解锁成功，您与邀请方各增加 1 个注册额度');
                $msg_type = 'success';
            } elseif ($result['inviteeAdded'] && !$result['inviterAdded']) {
                $msg = self::actionText('invite.success_self', '解锁成功，您增加 1 个注册额度（邀请方已达上限）');
                $msg_type = 'success';
            } else {
                $msg = self::actionText('invite.success_none', '未增加注册额度');
                $msg_type = 'warning';
            }
        } catch (Exception $e) {
            $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('errors.try_again', '操作失败，请稍后重试。'));
            $msg = $errorText;
            $msg_type = 'danger';
        }
    }}
}

// 兑换礼品申请
if($_POST['action'] == 'request_invite_reward') {
    try {
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
                // 如果当前日期在周期开始日期之前，则无法申请
                $periodStart = date('Y-m-d', strtotime('yesterday'));
                $periodEnd = date('Y-m-d', strtotime('yesterday'));
            }
        } else {
            // 默认按周计算，上期结束日为昨天
            $periodEnd = date('Y-m-d', strtotime('yesterday'));
            $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($inviteLeaderboardDays - 1) . ' days'));
        }
        // 只查奖励表（历史快照数据），不查实时统计
        $winners = Capsule::table('mod_cloudflare_invite_rewards as r')
            ->select('r.inviter_userid','r.rank','r.count','r.code')
            ->where('r.period_start', $periodStart)
            ->where('r.period_end', $periodEnd)
            ->orderBy('r.rank','asc')
            ->limit(5)
            ->get();
        // 如果没有历史快照数据，则无法申请兑换
        $rank = null; $count = 0; $codeVal = '';
        $i = 1; foreach ($winners as $w) {
            $thisRank = isset($w->rank) ? intval($w->rank) : $i;
            $thisCount = isset($w->count) ? intval($w->count) : intval($w->cnt ?? 0);
            if (intval($w->inviter_userid) === intval($userid)) { $rank = $thisRank; $count = $thisCount; break; }
            $i++;
        }
        if ($rank === null) { $msg = self::actionText('invite.reward.not_ranked', '上期未上榜，无法申请兑换'); $msg_type = 'warning'; }
        else {
            $codeRow = Capsule::table('mod_cloudflare_invitation_codes')->select('code')->where('userid', $userid)->first();
            $codeVal = $codeRow ? ($codeRow->code ?? '') : '';
            $existing = Capsule::table('mod_cloudflare_invite_rewards')
                ->where('period_start', $periodStart)
                ->where('period_end', $periodEnd)
                ->where('inviter_userid', $userid)
                ->first();
            if ($existing) {
                if ($existing->status === 'claimed') { $msg = self::actionText('invite.reward.already_claimed', '本期奖励已领取'); $msg_type = 'success'; }
                else {
                    Capsule::table('mod_cloudflare_invite_rewards')
                        ->where('id', $existing->id)
                        ->update(['status' => 'pending', 'requested_at' => date('Y-m-d H:i:s'), 'updated_at' => date('Y-m-d H:i:s')]);
                    $msg = self::actionText('invite.reward.submitted', '兑换申请已提交，请等待处理'); $msg_type = 'success';
                }
            } else {
                Capsule::table('mod_cloudflare_invite_rewards')->insert([
                    'period_start' => $periodStart,
                    'period_end' => $periodEnd,
                    'inviter_userid' => $userid,
                    'code' => $codeVal,
                    'rank' => $rank,
                    'count' => $count,
                    'status' => 'pending',
                    'requested_at' => date('Y-m-d H:i:s'),
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ]);
                $msg = self::actionText('invite.reward.submitted', '兑换申请已提交，请等待处理'); $msg_type = 'success';
            }
        }
    } catch (Exception $e) {
        $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('invite.reward.retry', '申请失败，请稍后重试。'));
        $msg = self::actionText('invite.reward.failed', '申请失败：%s', [$errorText]);
        $msg_type = 'danger';
    }
}

// 处理注册请求 - 不创建解析，仅记录保存
if($_POST['action'] == "register") {
    if ($pauseFreeRegistration) {
        $msg = self::actionText('register.paused', '当前已暂停免费域名注册，请稍后再试。');
        $msg_type = 'warning';
        $registerError = $msg;
    } else {
        if ($isUserBannedOrInactive) {
            $msg = self::actionText('register.banned', '您的账号已被封禁或停用，禁止注册新域名。') . ($banReasonText ? (' ' . $banReasonText) : '');
            $msg_type = 'danger';
            $registerError = $msg;
        } else {
            // VPN/代理检测
            $vpnCheckPassed = true;
            $vpnCheckResult = null;
            if (class_exists('CfVpnDetectionService') && CfVpnDetectionService::isEnabled($module_settings)) {
                $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
                $vpnCheckResult = CfVpnDetectionService::shouldBlockRegistration($clientIp, $module_settings);
                if (!empty($vpnCheckResult['blocked'])) {
                    $vpnCheckPassed = false;
                    $msg = self::actionText('register.vpn_blocked', '检测到您正在使用VPN或代理，请关闭后再尝试注册域名。');
                    $msg_type = 'warning';
                    $registerError = $msg;
                    // 记录日志
                    if (function_exists('cloudflare_subdomain_log')) {
                        cloudflare_subdomain_log('vpn_detection_blocked', [
                            'ip' => $clientIp,
                            'reason' => $vpnCheckResult['reason'] ?? 'unknown',
                            'is_vpn' => $vpnCheckResult['is_vpn'] ?? false,
                            'is_proxy' => $vpnCheckResult['is_proxy'] ?? false,
                            'is_hosting' => $vpnCheckResult['is_hosting'] ?? false,
                        ], $userid ?? 0, null);
                    }
                }
            }

            if ($vpnCheckPassed) {
            $subprefix = trim($_POST['subdomain']);
            $rootdomain = trim($_POST['rootdomain']);
            $subprefixLen = strlen($subprefix);

            if ($subprefix === '' || $rootdomain === '') {
                $msg = self::actionText('register.missing_fields', '请填写完整信息');
                $msg_type = 'danger';
                $registerError = $msg;
            } elseif (is_object($quota) && intval($quota->max_count ?? 0) > 0 && intval($quota->used_count ?? 0) >= intval($quota->max_count ?? 0)) {
                $msg = self::actionText('register.limit_reached', '已达到最大注册数量限制 (%s)', [intval($quota->max_count ?? 0)]);
                $msg_type = 'warning';
                $registerError = $msg;
            } elseif (in_array(strtolower($subprefix), array_map('strtolower', $forbidden))) {
                $msg = self::actionText('register.forbidden_prefix', "该前缀 '%s' 禁止使用", [$subprefix]);
                $msg_type = 'danger';
                $registerError = $msg;
            } elseif (!preg_match('/^[a-zA-Z0-9\-]+$/', $subprefix)) {
                $msg = self::actionText('register.invalid_chars', '子域名前缀只能包含字母、数字和连字符');
                $msg_type = 'danger';
                $registerError = $msg;
            } elseif (cfmod_has_invalid_edge_character($subprefix)) {
                $msg = self::actionText('register.edge_error', "子域名前缀不能以 '.' 或 '-' 开头或结尾");
                $msg_type = 'danger';
                $registerError = $msg;
            } elseif ($subprefixLen < $subPrefixMinLength || $subprefixLen > $subPrefixMaxLength) {
                $msg = self::actionText('register.length_error', '子域名前缀长度必须在%1$s-%2$s个字符之间', [$subPrefixMinLength, $subPrefixMaxLength]);
                $msg_type = 'danger';
                $registerError = $msg;
            } else {
                $fullsub = strtolower($subprefix) . '.' . strtolower($rootdomain);

                $isForbidden = Capsule::table('mod_cloudflare_forbidden_domains')->where('domain', $fullsub)->count() > 0;
                if ($isForbidden) {
                    $msg = self::actionText('register.forbidden_domain', '该域名已被禁止注册');
                    $msg_type = 'danger';
                    $registerError = $msg;
                } elseif (Capsule::table('mod_cloudflare_subdomain')->where('subdomain', $fullsub)->count() > 0) {
                    $msg = self::actionText('register.duplicate', "域名 '%s' 已被注册,请更换后重试.", [$fullsub]);
                    $msg_type = 'danger';
                    $registerError = $msg;
                } else {
                    try {
                        $rootAllowed = in_array($rootdomain, $roots);
                        if (!$rootAllowed) {
                            $msg = self::actionText('register.root_not_allowed', '根域名未被允许注册');
                            $msg_type = 'danger';
                            $registerError = $msg;
                        } else {
                            try {
                                $dbHasRoots = Capsule::table('mod_cloudflare_rootdomains')->count() > 0;
                                if ($dbHasRoots) {
                                    $st = Capsule::table('mod_cloudflare_rootdomains')
                                        ->select('status')
                                        ->whereRaw('LOWER(domain)=?', [strtolower($rootdomain)])
                                        ->first();
                                    if ($st && ($st->status ?? '') !== 'active') {
                                        $msg = self::actionText('register.root_suspended', '该根域名已停止新注册');
                                        $msg_type = 'danger';
                                        $registerError = $msg;
                                        throw new Exception('suspended rootdomain');
                                    }
                                }
                            } catch (Exception $e) {}

                            $limitCheck = function_exists('cfmod_check_rootdomain_user_limit')
                                ? cfmod_check_rootdomain_user_limit($userid, $rootdomain, 1)
                                : ['allowed' => true, 'limit' => 0];

                            if (!$limitCheck['allowed']) {
                                $limitMessage = cfmod_format_rootdomain_limit_message($rootdomain, $limitCheck['limit']);
                                if ($limitMessage === '') {
                                    $limitValueText = max(1, intval($limitCheck['limit'] ?? 0));
                                    $limitMessage = self::actionText('register.root_user_limit', '%1$s 每个账号最多注册 %2$s 个，您已达到上限', [$rootdomain, $limitValueText]);
                                }
                                $msg = $limitMessage;
                                $msg_type = 'warning';
                                $registerError = $msg;
                            } else {
                                $providerContext = cfmod_make_provider_client(null, $rootdomain, null, $module_settings);
                                if (!$providerContext || empty($providerContext['client'])) {
                                    $msg = self::actionText('register.provider_missing', '当前根域未配置有效的 DNS 供应商，请联系管理员');
                                    $msg_type = 'danger';
                                    $registerError = $msg;
                                } else {
                                    $cf = $providerContext['client'];
                                    $selectedProviderId = intval($providerContext['provider_account_id'] ?? 0);
                                    $zone_id = $cf->getZoneId($rootdomain);

                                    if ($zone_id) {
                                        $existsOnCF = $cf->checkDomainExists($zone_id, $fullsub);
                                        if ($existsOnCF) {
                                            $msg = self::actionText('register.provider_exists', '该域名在阿里云DNS上已存在解析记录，无法注册');
                                            $msg_type = 'danger';
                                            $registerError = $msg;
                                        } else {
                                            $created = null;
                                            try {
                                                $created = cf_atomic_register_subdomain(
                                                    $userid,
                                                    $fullsub,
                                                    $rootdomain,
                                                    $zone_id,
                                                    $module_settings,
                                                    [
                                                        'dns_record_id' => null,
                                                        'notes' => '已注册，等待解析设置',
                                                        'provider_account_id' => $selectedProviderId
                                                    ]
                                                );
                                            } catch (CfAtomicQuotaExceededException $e) {
                                                $totalLimit = null;
                                                if (is_object($quota) && isset($quota->max_count)) {
                                                    $totalLimit = $quota->max_count;
                                                } elseif (isset($module_settings['max_subdomain_per_user'])) {
                                                    $totalLimit = $module_settings['max_subdomain_per_user'];
                                                }
                                                $limitText = $totalLimit !== null ? intval($totalLimit) : self::actionText('common.configured_limit', '已配置的上限');
                                                $msg = self::actionText('register.limit_reached', '已达到最大注册数量限制 (%s)', [$limitText]);
                                                $msg_type = 'warning';
                                                $registerError = $msg;
                                            } catch (CfAtomicAlreadyRegisteredException $e) {
                                                $msg = self::actionText('register.duplicate', "域名 '%s' 已被注册,请更换后重试.", [$fullsub]);
                                                $msg_type = 'danger';
                                                $registerError = $msg;
                                            } catch (CfAtomicInvalidPrefixLengthException $e) {
                                                $msg = self::actionText('register.length_error', '子域名前缀长度必须在%1$s-%2$s个字符之间', [$subPrefixMinLength, $subPrefixMaxLength]);
                                                $msg_type = 'danger';
                                                $registerError = $msg;
                                            }

                                            if ($created) {
                                                if (is_object($quota)) {
                                                    $quota->used_count = $created['used_count'];
                                                    $quota->max_count = $created['max_count'];
                                                } else {
                                                    $quota = (object) [
                                                        'used_count' => $created['used_count'],
                                                        'max_count' => $created['max_count'],
                                                        'invite_bonus_count' => 0,
                                                        'invite_bonus_limit' => intval($module_settings['invite_bonus_limit_global'] ?? 5)
                                                    ];
                                                }

                                                if (function_exists('cloudflare_subdomain_log')) {
                                                    cloudflare_subdomain_log('client_register_subdomain', ['subdomain' => $fullsub, 'root' => $rootdomain], $userid, $created['id']);
                                                }

                                                $msg = self::actionText('register.success_detail', "注册成功！域名 '%s' 已创建，现在您可以设置解析了", [$fullsub]);
                                                $msg_type = 'success';
                                                $registerError = '';

                                                list($existing, $existing_total, $domainTotalPages, $domainPage) = cfmod_client_load_subdomains_paginated(
                                                    $userid,
                                                    1,
                                                    $domainPageSize,
                                                    $domainSearchTerm
                                                );
                                            }
                                        }
                                    } else {
                                        $msg = self::actionText('register.error_generic', '错误：错误代码#1001,请稍后重试。');
                                        $msg_type = 'danger';
                                        $registerError = $msg;
                                    }
                                }
                            }
                        }
                    } catch (Exception $e) {}
                }
            }
            } // end if ($vpnCheckPassed)
        }
    }
}
// 处理续期请求
if($_POST['action'] == "renew" && isset($_POST['subdomain_id'])) {
    $subdomainId = intval($_POST['subdomain_id']);
    $nowTs = time();
    try {
        if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
    } catch (Exception $e) {}

    $renewSig = 'renew|' . $subdomainId;
    if (!empty($_SESSION['cfmod_last_renew_sig']) && $_SESSION['cfmod_last_renew_sig'] === $renewSig && isset($_SESSION['cfmod_last_renew_time']) && ($nowTs - intval($_SESSION['cfmod_last_renew_time'])) < 5) {
        $msg = self::actionText('common.duplicate_submit', '操作已提交，请勿重复点击');
        $msg_type = 'warning';
    } else {
        $_SESSION['cfmod_last_renew_sig'] = $renewSig;
        $_SESSION['cfmod_last_renew_time'] = $nowTs;

        $termYearsRaw = $module_settings['domain_registration_term_years'] ?? 1;
        $termYears = is_numeric($termYearsRaw) ? (int)$termYearsRaw : 1;
        if ($termYears <= 0) {
            $msg = self::actionText('renew.term_missing', '当前未配置有效的续期年限，请联系管理员');
            $msg_type = 'danger';
            unset($_SESSION['cfmod_last_renew_sig'], $_SESSION['cfmod_last_renew_time']);
        } else {
            $freeWindowDays = max(0, intval($module_settings['domain_free_renew_window_days'] ?? 30));
            $graceDaysRaw = $module_settings['domain_grace_period_days'] ?? ($module_settings['domain_auto_delete_grace_days'] ?? 45);
            $graceDays = is_numeric($graceDaysRaw) ? (int)$graceDaysRaw : 45;
            if ($graceDays < 0) { $graceDays = 0; }
            $redemptionDaysRaw = $module_settings['domain_redemption_days'] ?? 0;
            $redemptionDays = is_numeric($redemptionDaysRaw) ? (int)$redemptionDaysRaw : 0;
            if ($redemptionDays < 0) { $redemptionDays = 0; }
            $freeWindowSeconds = $freeWindowDays * 86400;
            $graceSeconds = $graceDays * 86400;
            $redemptionSeconds = $redemptionDays * 86400;

            try {
                $renewResult = Capsule::transaction(function () use ($subdomainId, $userid, $termYears, $freeWindowSeconds, $graceSeconds, $redemptionSeconds, $nowTs, $redemptionModeSetting, $redemptionFeeSetting) {
                    $nowStr = date('Y-m-d H:i:s');
                    $subdomain = Capsule::table('mod_cloudflare_subdomain')
                        ->where('id', $subdomainId)
                        ->where('userid', $userid)
                        ->lockForUpdate()
                        ->first();

                    if (!$subdomain) {
                        throw new \RuntimeException(self::actionText('renew.not_found', '未找到该域名或无权操作'));
                    }

                    if (intval($subdomain->never_expires ?? 0) === 1) {
                        throw new \RuntimeException(self::actionText('renew.never_expires', '此域名为永久有效，无需续期'));
                    }

                    $statusLower = strtolower($subdomain->status ?? '');
                    if (!in_array($statusLower, ['active', 'pending'], true)) {
                        throw new \RuntimeException(self::actionText('renew.status_invalid', '当前状态不允许续期'));
                    }

                    $expiresRaw = $subdomain->expires_at ?? null;
                    if (!$expiresRaw) {
                        throw new \RuntimeException(self::actionText('renew.no_expiry', '尚未设置到期时间，请联系管理员'));
                    }

                    $expiresTs = strtotime($expiresRaw);
                    if ($expiresTs === false) {
                        throw new \RuntimeException(self::actionText('renew.parse_failed', '无法解析当前到期时间'));
                    }

                    if ($freeWindowSeconds > 0 && $nowTs < ($expiresTs - $freeWindowSeconds)) {
                        throw new \RuntimeException(self::actionText('renew.not_in_window', '尚未进入续期窗口'));
                    }

                    $graceDeadlineTs = $expiresTs + $graceSeconds;
                    $chargeAmount = 0.0;
                    if ($nowTs > $graceDeadlineTs) {
                        $redemptionDeadlineTs = $graceDeadlineTs + $redemptionSeconds;
                        if ($redemptionSeconds > 0 && $nowTs <= $redemptionDeadlineTs) {
                            if ($redemptionModeSetting === 'auto_charge') {
                                if ($redemptionFeeSetting > 0) {
                                    $clientRow = Capsule::table('tblclients')
                                        ->where('id', $userid)
                                        ->lockForUpdate()
                                        ->first();
                                    if (!$clientRow) {
                                        throw new \RuntimeException(self::actionText('renew.balance_unavailable', '无法读取账户余额信息，请稍后重试'));
                                    }
                                    $currentCredit = (float) ($clientRow->credit ?? 0.0);
                                    if ($currentCredit + 1e-8 < $redemptionFeeSetting) {
                                        throw new \RuntimeException(self::actionText('renew.redemption_insufficient_balance', '赎回期续费需要 ￥%s，账户余额不足，请先充值后再试。', [number_format($redemptionFeeSetting, 2)]));
                                    }
                                    $newCredit = round($currentCredit - $redemptionFeeSetting, 2);
                                    Capsule::table('tblclients')
                                        ->where('id', $userid)
                                        ->update([
                                            'credit' => number_format($newCredit, 2, '.', ''),
                                        ]);

                                    static $creditSchemaInfoLocal = null;
                                    if ($creditSchemaInfoLocal === null) {
                                        $creditSchemaInfoLocal = [
                                            'has_table' => false,
                                            'has_relid' => false,
                                            'has_refundid' => false,
                                        ];
                                        try {
                                            $creditSchemaInfoLocal['has_table'] = Capsule::schema()->hasTable('tblcredit');
                                            if ($creditSchemaInfoLocal['has_table']) {
                                                $creditSchemaInfoLocal['has_relid'] = Capsule::schema()->hasColumn('tblcredit', 'relid');
                                                $creditSchemaInfoLocal['has_refundid'] = Capsule::schema()->hasColumn('tblcredit', 'refundid');
                                            }
                                        } catch (\Throwable $ignored) {
                                            $creditSchemaInfoLocal = [
                                                'has_table' => false,
                                                'has_relid' => false,
                                                'has_refundid' => false,
                                            ];
                                        }
                                    }
                                    if ($creditSchemaInfoLocal['has_table']) {
                                        $creditInsert = [
                                            'clientid' => $userid,
                                            'date' => date('Y-m-d H:i:s', $nowTs),
                                            'description' => '赎回期续费自动扣费',
                                            'amount' => 0 - $redemptionFeeSetting,
                                        ];
                                        if ($creditSchemaInfoLocal['has_relid']) {
                                            $creditInsert['relid'] = 0;
                                        }
                                        if ($creditSchemaInfoLocal['has_refundid']) {
                                            $creditInsert['refundid'] = 0;
                                        }
                                        Capsule::table('tblcredit')->insert($creditInsert);
                                    }
                                    $chargeAmount = $redemptionFeeSetting;
                                }
                            } else {
                                throw new \RuntimeException(self::actionText('renew.redemption_contact_admin', '域名处于赎回期，需要联系管理员续期'));
                            }
                        } else {
                            throw new \RuntimeException($redemptionSeconds > 0 ? self::actionText('renew.redemption_expired', '域名已超过赎回期，无法续期') : self::actionText('renew.grace_expired', '已超过续期宽限期，无法续期'));
                        }
                    }

                    $baseTs = max($expiresTs, $nowTs);
                    $newExpiryTs = strtotime('+' . $termYears . ' years', $baseTs);
                    if ($newExpiryTs === false) {
                        throw new \RuntimeException(self::actionText('renew.calculation_failed', '续期计算失败，请稍后重试'));
                    }

                    $newExpiry = date('Y-m-d H:i:s', $newExpiryTs);

                    Capsule::table('mod_cloudflare_subdomain')
                        ->where('id', $subdomainId)
                        ->update([
                            'expires_at' => $newExpiry,
                            'renewed_at' => $nowStr,
                            'never_expires' => 0,
                            'updated_at' => $nowStr
                        ]);

                    return [
                        'new_expires_at' => $newExpiry,
                        'previous_expires_at' => $expiresRaw,
                        'subdomain' => $subdomain->subdomain,
                        'charged_amount' => $chargeAmount,
                    ];
                });

                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('client_renew_subdomain', [
                        'subdomain' => $renewResult['subdomain'],
                        'previous_expires_at' => $renewResult['previous_expires_at'],
                        'new_expires_at' => $renewResult['new_expires_at'],
                        'charged_amount' => $renewResult['charged_amount'] ?? 0,
                    ], $userid, $subdomainId);
                }

                $chargedAmount = isset($renewResult['charged_amount']) ? (float)$renewResult['charged_amount'] : 0.0;
                $msg = self::actionText('renew.success', '续期成功，新到期时间：%s', [date('Y-m-d H:i', strtotime($renewResult['new_expires_at']))]);
                if ($chargedAmount > 0) {
                    $msg .= self::actionText('renew.success_charge_suffix', '（已扣除 ￥%s）', [number_format($chargedAmount, 2)]);
                }
                $msg_type = 'success';

                $existing = Capsule::table('mod_cloudflare_subdomain')
                    ->where('userid', $userid)
                    ->where('status', 'active')
                    ->orderBy('created_at', 'desc')
                    ->get();
                if (!is_array($existing)) {
                    $existing = [];
                }
            } catch (\Throwable $e) {
                unset($_SESSION['cfmod_last_renew_sig'], $_SESSION['cfmod_last_renew_time']);
                $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('renew.failed_default', '续期失败，请稍后再试。'));
                $msg = self::actionText('renew.failed_detail', '续期失败：%s', [$errorText]);
                $msg_type = 'danger';
            }
        }
    }
}

// 处理删除请求（禁用：用户不能删除自己的域名）
if($_POST['action'] == "delete" && isset($_POST['subdomain_id'])) {
    $subdomain_id = intval($_POST['subdomain_id']);
    $msg = self::actionText('delete.not_supported', '成功注册的免费域名暂不支持删除。如需处理，请提交工单获取支持。');
    $msg_type = "warning";
    if (function_exists('cloudflare_subdomain_log')) {
        cloudflare_subdomain_log('client_attempt_delete_subdomain', ['subdomain_id' => $subdomain_id], $userid, $subdomain_id);
    }
}

// 处理DNS记录创建请求（支持记录表持久化）
if($_POST['action'] == "create_dns" && isset($_POST['subdomain_id'])) {
    if ($disableDnsWrite) {
        $msg = self::actionText('dns.operations_disabled', '当前已禁止新增/修改 DNS 记录');
        $msg_type = 'warning';
    } else {
        $record_type = trim($_POST['record_type'] ?? '');
        if ($record_type === '') {
            $record_type = 'A';
        }
        $record_type_upper = strtoupper($record_type);
        if ($enableDnsUnlockFeature && $record_type_upper === 'NS' && !CfDnsUnlockService::userHasUnlocked($userid ?? 0)) {
            $msg = self::actionText('dns.unlock.required', '请先完成 DNS 解锁后再设置 NS 记录。');
            $msg_type = 'warning';
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }
        // VPN/代理检测（仅NS记录）
        if ($record_type_upper === 'NS' && class_exists('CfVpnDetectionService') && CfVpnDetectionService::isDnsCheckEnabled($module_settings)) {
            $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
            $vpnCheckResult = CfVpnDetectionService::shouldBlockDnsOperation($clientIp, $module_settings);
            if (!empty($vpnCheckResult['blocked'])) {
                $msg = self::actionText('dns.vpn_blocked', '检测到您正在使用VPN或代理，请关闭后再进行DNS操作。');
                $msg_type = 'warning';
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('vpn_detection_blocked_dns', [
                        'action' => 'create_dns',
                        'type' => 'NS',
                        'ip' => $clientIp,
                        'reason' => $vpnCheckResult['reason'] ?? 'unknown',
                    ], $userid ?? 0, null);
                }
                return [
                    'msg' => $msg,
                    'msg_type' => $msg_type,
                    'registerError' => $registerError,
                ];
            }
        }
        if ($isUserBannedOrInactive) {
            $msg = self::actionText('dns.create.banned', '您的账号已被封禁或停用，禁止创建DNS记录。') . ($banReasonText ? (' ' . $banReasonText) : '');
            $msg_type = 'danger';
        } elseif (self::shouldUseAsyncDns('create_dns', $module_settings, $isAsyncReplay)) {
            $jobId = self::enqueueAsyncDnsJob(intval($userid ?? 0), 'create_dns');
            $msg = self::formatAsyncQueuedMessage($jobId);
            $msg_type = 'info';
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }

        $subdomain_id = intval($_POST['subdomain_id']);
        $record_content = trim($_POST['record_content']);
        $record_ttl = cfmod_normalize_ttl($_POST['record_ttl'] ?? 600);
        $record_priority_raw = $_POST['record_priority'] ?? null;
        $record_priority = is_numeric($record_priority_raw) ? intval($record_priority_raw) : 0;
        if ($record_priority < 0) {
            $record_priority = 0;
        }
        if ($record_priority > 65535) {
            $record_priority = 65535;
        }
        $line = trim($_POST['line'] ?? 'default');
        $record_name = trim($_POST['record_name'] ?? '@');
        if ($record_name === '') {
            $record_name = '@';
        }
        $record_weight = intval($_POST['record_weight'] ?? 0);
        if ($record_weight < 0) {
            $record_weight = 0;
        }
        if ($record_weight > 65535) {
            $record_weight = 65535;
        }
        $record_port = intval($_POST['record_port'] ?? 0);
        $record_target = trim($_POST['record_target'] ?? '');
        if ($record_type_upper === 'MX' && $record_priority === 0) {
            $record_priority = 10;
        }
        $shouldProceedDnsCreate = true;
        if ($record_port < 0) {
            $record_port = 0;
        }
        if ($record_port > 65535) {
            $record_port = 65535;
        }

        if ($shouldProceedDnsCreate && $record_type_upper === 'SRV') {
            if ($record_port < 1 || $record_port > 65535) {
                $msg = self::actionText('dns.validation.srv_port', 'SRV记录的端口必须在1-65535之间');
                $msg_type = 'danger';
                $shouldProceedDnsCreate = false;
            }
            $record_priority = max(0, min(65535, $record_priority));
            $record_weight = max(0, min(65535, $record_weight));
            $record_target_clean = rtrim($record_target, '.');
            $record_target_clean = trim($record_target_clean);
            if ($shouldProceedDnsCreate && $record_target_clean === '') {
                $msg = self::actionText('dns.validation.srv_target_required', 'SRV记录的目标地址不能为空');
                $msg_type = 'danger';
                $shouldProceedDnsCreate = false;
            }
            if ($shouldProceedDnsCreate && !cfmod_is_valid_hostname($record_target_clean)) {
                $msg = self::actionText('dns.validation.srv_target_invalid', '请输入有效的SRV目标主机名');
                $msg_type = 'danger';
                $shouldProceedDnsCreate = false;
            }
            if ($shouldProceedDnsCreate) {
                $record_target = $record_target_clean;
                $record_content = $record_priority . ' ' . $record_weight . ' ' . $record_port . ' ' . $record_target;
            }
        }

        if (cfmod_dns_name_has_invalid_edges($record_name)) {
            $msg = self::actionText('dns.validation.name_invalid', "解析名称不能以 '.' 或 '-' 开头或结尾，也不能包含连续的 '.'");
            $msg_type = "danger";
            $shouldProceedDnsCreate = false;
        }

        if ($shouldProceedDnsCreate) {
            // 简单幂等：短时间内相同参数的重复提交直接忽略
            try {
                if (session_status() !== PHP_SESSION_ACTIVE) {
                    @session_start();
                }
            } catch (Exception $e) {}

            $idemSig = 'create|' . implode('|', [
                $subdomain_id,
                $record_type_upper,
                $record_name,
                $record_content,
                $record_ttl,
                $record_priority,
                $line
            ]);
            $nowTs = time();

            if (!empty($_SESSION['cfmod_last_dns_sig'])
                && $_SESSION['cfmod_last_dns_sig'] === $idemSig
                && isset($_SESSION['cfmod_last_dns_time'])
                && ($nowTs - intval($_SESSION['cfmod_last_dns_time'])) < 5
            ) {
                $msg = self::actionText('common.duplicate_submit', '操作已提交，请勿重复点击');
                $msg_type = 'warning';
            } else {
                $_SESSION['cfmod_last_dns_sig'] = $idemSig;
                $_SESSION['cfmod_last_dns_time'] = $nowTs;

                try {
                    $record = Capsule::table('mod_cloudflare_subdomain')
                        ->where('id', $subdomain_id)
                        ->where('userid', $userid)
                        ->first();

                    if ($record) {
                        if ($record->status === 'suspended') {
                            $msg = self::actionText('dns.domain_suspended', '该域名已被暂停，无法进行解析操作');
                            $msg_type = "warning";
                        } else {
                            list($cf, $providerError, $providerContext) = cfmod_client_acquire_provider_for_subdomain($record, $module_settings);
                            if (!$cf) {
                                $msg = $providerError;
                                $msg_type = 'danger';
                            } else {
                                $limitPerSub = intval($module_settings['max_dns_records_per_subdomain'] ?? 0);
                                $final_name = $record_name === '@' ? $record->subdomain : ($record_name . '.' . $record->subdomain);
                                $isRootNs = ($record_type_upper === 'NS' && $final_name === $record->subdomain);
                                $effectiveLimit = $isRootNs ? 0 : $limitPerSub;
                                $creation = null;

                                try {
                                    $creation = cf_atomic_run_with_dns_limit(
                                        $record->id,
                                        $effectiveLimit,
                                        function () use (
                                            $cf,
                                            $record,
                                            $record_type_upper,
                                            $record_content,
                                            $record_priority,
                                            $record_ttl,
                                            $line,
                                            $final_name,
                                            $nsMaxPerDomain,
                                            $isRootNs,
                                            $record_weight,
                                            $record_port,
                                            $record_target
                                        ) {
                                            if ($isRootNs) {
                                                $currentNs = Capsule::table('mod_cloudflare_dns_records')
                                                    ->where('subdomain_id', $record->id)
                                                    ->where('type', 'NS')
                                                    ->where('name', $record->subdomain)
                                                    ->lockForUpdate()
                                                    ->count();
                                                if ($currentNs >= $nsMaxPerDomain) {
                                                    throw new CfAtomicRecordLimitException('ns_limit');
                                                }
                                            }

                                            switch ($record_type_upper) {
                                                case 'MX':
                                                    $res = $cf->createMXRecord($record->cloudflare_zone_id, $final_name, $record_content, $record_priority, $record_ttl);
                                                    break;
                                                case 'SRV':
                                                    $res = $cf->createSRVRecord($record->cloudflare_zone_id, $final_name, $record_target, $record_port, $record_priority, $record_weight, $record_ttl);
                                                    break;
                                                case 'CAA':
                                                    $caa_flag = intval($_POST['caa_flag'] ?? 0);
                                                    $caa_tag = trim($_POST['caa_tag'] ?? 'issue');
                                                    $caa_value = trim($_POST['caa_value'] ?? '');
                                                    if ($caa_value === '') {
                                                        throw new \RuntimeException(self::actionText('dns.validation.caa_value_required', 'CAA记录的Value不能为空'));
                                                    }
                                                    $res = $cf->createCAARecord($record->cloudflare_zone_id, $final_name, $caa_flag, $caa_tag, $caa_value, $record_ttl);
                                                    break;
                                                default:
                                                    $res = $cf->createDnsRecordRaw($record->cloudflare_zone_id, [
                                                        'type' => $record_type_upper,
                                                        'name' => $final_name,
                                                        'content' => $record_content,
                                                        'ttl' => $record_ttl,
                                                        'line' => $line
                                                    ]);
                                                    break;
                                            }

                                            if (!($res['success'] ?? false)) {
                                                $message = $res['errors'][0] ?? ($res['errors'] ?? 'create failed');
                                                if (is_array($message)) {
                                                    $message = json_encode($message, JSON_UNESCAPED_UNICODE);
                                                }
                                                throw new \RuntimeException((string) $message);
                                            }

                                            $cfRecordId = $res['result']['id'] ?? ($res['RecordId'] ?? null);
                                            $now = date('Y-m-d H:i:s');

                                            Capsule::table('mod_cloudflare_dns_records')->insert([
                                                'subdomain_id' => $record->id,
                                                'zone_id' => $record->cloudflare_zone_id,
                                                'record_id' => $cfRecordId !== null ? (string) $cfRecordId : null,
                                                'name' => $final_name,
                                                'type' => $record_type_upper,
                                                'content' => $record_content,
                                                'ttl' => $record_ttl,
                                                'proxied' => 0,
                                                'line' => $line,
                                                'priority' => in_array($record_type_upper, ['MX','SRV']) ? $record_priority : null,
                                                'status' => 'active',
                                                'created_at' => $now,
                                                'updated_at' => $now
                                            ]);
                                            CfSubdomainService::markHasDnsHistory($record->id);

                                            $updateData = [
                                                'notes' => '已解析',
                                                'updated_at' => $now
                                            ];
                                            if ($final_name === $record->subdomain) {
                                                $updateData['dns_record_id'] = $cfRecordId !== null ? (string) $cfRecordId : null;
                                            }
                                            Capsule::table('mod_cloudflare_subdomain')
                                                ->where('id', $record->id)
                                                ->update($updateData);

                                            return [
                                                'record_id' => $cfRecordId !== null ? (string) $cfRecordId : null,
                                                'result' => $res,
                                                'final_name' => $final_name
                                            ];
                                        }
                                    );
                                } catch (CfAtomicRecordLimitException $e) {
                                    if ($e->getMessage() === 'ns_limit') {
                                        $msg = self::actionText('dns.ns.limit_reached', 'NS 服务器最多允许 %s 条，当前已达到上限', [$nsMaxPerDomain]);
                                        $msg_type = 'warning';
                                    } else {
                                        $limitText = $limitPerSub > 0 ? $limitPerSub : self::actionText('common.configured_limit', '配置的上限');
                                        $msg = self::actionText('dns.limit_reached', '已达到该域名的解析数量上限（%s）', [$limitText]);
                                        $msg_type = 'warning';
                                    }
                                    throw new Exception('__handled_limit__');
                                } catch (\RuntimeException $e) {
                                    $errorText = cfmod_format_provider_error($e->getMessage());
                                    $msg = self::actionText('dns.create.failed', 'DNS记录创建失败：%s', [$errorText]);
                                    $msg_type = "danger";
                                    throw new Exception('__handled_error__');
                                }

                                if ($creation) {
                                    try {
                                        $fresh = $cf->getDnsRecords($record->cloudflare_zone_id, $record->subdomain);
                                        if (($fresh['success'] ?? false)) {
                                            foreach (($fresh['result'] ?? []) as $fr) {
                                                $exists = self::findLocalRecordByRemote($subdomain_id, $fr);
                                                if (!$exists) {
                                                    Capsule::table('mod_cloudflare_dns_records')->insert([
                                                        'subdomain_id' => $subdomain_id,
                                                        'zone_id' => $record->cloudflare_zone_id,
                                                        'record_id' => isset($fr['id']) ? (string) $fr['id'] : null,
                                                        'name' => ($fr['name'] ?? $record->subdomain),
                                                        'type' => strtoupper(trim((string)($fr['type'] ?? 'A'))),
                                                        'content' => (string)($fr['content'] ?? ''),
                                                        'ttl' => intval($fr['ttl'] ?? 600),
                                                        'proxied' => 0,
                                                        'status' => 'active',
                                                        'created_at' => date('Y-m-d H:i:s'),
                                                        'updated_at' => date('Y-m-d H:i:s')
                                                    ]);
                                                }
                                            }
                                        }
                                    } catch (Exception $e) {
                                    }

                                    CfSubdomainService::syncDnsHistoryFlag($subdomain_id);

                                    if (function_exists('cloudflare_subdomain_log')) {
                                        cloudflare_subdomain_log(
                                            'client_create_dns',
                                            ['type' => $record_type_upper, 'content' => $record_content, 'ttl' => $record_ttl, 'line' => $line],
                                            $userid,
                                            $subdomain_id
                                        );
                                    }

                                    $successDomain = $record_name === '@' ? $record->subdomain : $final_name;
                                $msg = self::actionText('dns.create.success', "DNS记录创建成功！域名 '%s' 现在可以正常访问了", [$successDomain]);
                                $msg_type = "success";
                                }
                            }
                        }
                    }
                } catch (Exception $e) {
                    if (!in_array($e->getMessage(), ['__handled_limit__', '__handled_error__'], true)) {
                        $errorText = cfmod_format_provider_error($e->getMessage());
                        $msg = self::actionText('dns.create.failed', 'DNS记录创建失败：%s', [$errorText]);
                        $msg_type = "danger";
                    }
                }
            }
        }
    }
}

// 处理域名自助删除
if($_POST['action'] == 'delete_subdomain' && isset($_POST['subdomain_id'])) {
    if (empty($clientDeleteEnabled)) {
        $msg = self::actionText('delete.not_supported', '注册的域名暂不支持自助删除，如需协助请提交工单。');
        $msg_type = 'warning';
    } elseif ($isUserBannedOrInactive) {
        $msg = self::actionText('delete.banned', '您的账号已被封禁或停用，暂无法提交删除申请。') . ($banReasonText ? (' ' . $banReasonText) : '');
        $msg_type = 'danger';
    } else {
        $subdomainId = intval($_POST['subdomain_id']);
        if ($subdomainId <= 0) {
            $msg = self::actionText('delete.invalid_subdomain', '未找到该域名，请刷新后重试。');
            $msg_type = 'warning';
        } else {
            $subdomain = Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomainId)
                ->where('userid', $userid)
                ->first();
            if (!$subdomain) {
                $msg = self::actionText('delete.invalid_subdomain', '未找到该域名，请刷新后重试。');
                $msg_type = 'warning';
            } else {
                $statusLower = strtolower((string)($subdomain->status ?? ''));
                $everHadDns = intval($subdomain->has_dns_history ?? 0) === 1;
                if (!$everHadDns) {
                    try {
                        $currentDnsExists = Capsule::table('mod_cloudflare_dns_records')
                            ->where('subdomain_id', $subdomainId)
                            ->exists();
                        if ($currentDnsExists) {
                            $everHadDns = true;
                            CfSubdomainService::markHasDnsHistory($subdomainId);
                        }
                    } catch (\Throwable $e) {
                    }
                }

                if (in_array($statusLower, ['pending_delete', 'pending_remove'], true)) {
                    $msg = self::actionText('delete.pending', '删除申请已提交，系统稍后会自动处理。');
                    $msg_type = 'info';
                } elseif ($statusLower === 'deleted') {
                    $msg = self::actionText('delete.already_deleted', '该域名已被清理，无需重复操作。');
                    $msg_type = 'info';
                } elseif (intval($subdomain->gift_lock_id ?? 0) > 0) {
                    $msg = self::actionText('delete.gift_locked', '域名当前处于转赠/锁定状态，请先取消后再尝试删除。');
                    $msg_type = 'warning';
                } elseif ($everHadDns) {
                    $msg = self::actionText('delete.history_blocked', '仅允许从未设置解析记录的域名自助删除，如需协助请提交工单。');
                    $msg_type = 'warning';
                } else {
                    $now = date('Y-m-d H:i:s');
                    $deleteNote = '[client_delete ' . $now . '] 用户提交自助删除';
                    $existingNotes = trim((string)($subdomain->notes ?? ''));
                    $noteToStore = $existingNotes === '' ? $deleteNote : ($existingNotes . "\n" . $deleteNote);
                    Capsule::table('mod_cloudflare_subdomain')
                        ->where('id', $subdomainId)
                        ->update([
                            'status' => 'pending_delete',
                            'expires_at' => '1999-12-31 00:00:00',
                            'never_expires' => 0,
                            'auto_deleted_at' => null,
                            'notes' => $noteToStore,
                            'updated_at' => $now,
                        ]);
                    if (function_exists('cloudflare_subdomain_log')) {
                        cloudflare_subdomain_log('client_request_delete', [
                            'subdomain' => $subdomain->subdomain ?? '',
                            'userid' => $userid,
                            'requested_at' => $now,
                        ], $userid, $subdomainId);
                    }
                    $msg = self::actionText('delete.request_submitted', '删除申请已提交，系统将在稍后自动清理该域名。');
                    $msg_type = 'success';
                }
            }
        }
    }

    return [
        'msg' => $msg,
        'msg_type' => $msg_type,
        'registerError' => $registerError,
    ];
}

// 处理DNS记录更新请求（同步记录表）
if($_POST['action'] == "update_dns" && isset($_POST['subdomain_id'])) {
    if ($disableDnsWrite) {
        $msg = self::actionText('dns.operations_disabled', '当前已禁止新增/修改 DNS 记录');
        $msg_type = 'warning';
    } else {
        $record_type = trim($_POST['record_type'] ?? '');
        if ($record_type === '') {
            $record_type = 'A';
        }
        $record_type_upper = strtoupper($record_type);
        if ($enableDnsUnlockFeature && $record_type_upper === 'NS' && !CfDnsUnlockService::userHasUnlocked($userid ?? 0)) {
            $msg = self::actionText('dns.unlock.required', '请先完成 DNS 解锁后再设置 NS 记录。');
            $msg_type = 'warning';
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }
        // VPN/代理检测（仅NS记录）
        if ($record_type_upper === 'NS' && class_exists('CfVpnDetectionService') && CfVpnDetectionService::isDnsCheckEnabled($module_settings)) {
            $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
            $vpnCheckResult = CfVpnDetectionService::shouldBlockDnsOperation($clientIp, $module_settings);
            if (!empty($vpnCheckResult['blocked'])) {
                $msg = self::actionText('dns.vpn_blocked', '检测到您正在使用VPN或代理，请关闭后再进行DNS操作。');
                $msg_type = 'warning';
                if (function_exists('cloudflare_subdomain_log')) {
                    cloudflare_subdomain_log('vpn_detection_blocked_dns', [
                        'action' => 'update_dns',
                        'type' => 'NS',
                        'ip' => $clientIp,
                        'reason' => $vpnCheckResult['reason'] ?? 'unknown',
                    ], $userid ?? 0, null);
                }
                return [
                    'msg' => $msg,
                    'msg_type' => $msg_type,
                    'registerError' => $registerError,
                ];
            }
        }

        if ($isUserBannedOrInactive) {
            $msg = self::actionText('dns.update.banned', '您的账号已被封禁或停用，禁止更新DNS记录。') . ($banReasonText ? (' ' . $banReasonText) : '');
            $msg_type = 'danger';
        } elseif (self::shouldUseAsyncDns('update_dns', $module_settings, $isAsyncReplay)) {
            $jobId = self::enqueueAsyncDnsJob(intval($userid ?? 0), 'update_dns');
            $msg = self::formatAsyncQueuedMessage($jobId);
            $msg_type = 'info';
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }

        $subdomain_id = intval($_POST['subdomain_id']);
        $record_content = trim($_POST['record_content']);
        $record_ttl = cfmod_normalize_ttl($_POST['record_ttl'] ?? 600);
        $record_priority_raw = $_POST['record_priority'] ?? null;
        $record_priority = is_numeric($record_priority_raw) ? intval($record_priority_raw) : 0;
        if ($record_priority < 0) {
            $record_priority = 0;
        }
        if ($record_priority > 65535) {
            $record_priority = 65535;
        }
        $line = trim($_POST['line'] ?? 'default');
        $record_id = trim($_POST['record_id'] ?? '');
        $record_name = trim($_POST['record_name'] ?? '@');
        if ($record_name === '') {
            $record_name = '@';
        }
        $record_weight = intval($_POST['record_weight'] ?? 0);
        if ($record_weight < 0) {
            $record_weight = 0;
        }
        if ($record_weight > 65535) {
            $record_weight = 65535;
        }
        $record_port = intval($_POST['record_port'] ?? 0);
        $record_target = trim($_POST['record_target'] ?? '');
        if ($record_type_upper === 'MX' && $record_priority === 0) {
            $record_priority = 10;
        }
        $shouldProceedDnsUpdate = true;
        if ($record_port < 0) {
            $record_port = 0;
        }
        if ($record_port > 65535) {
            $record_port = 65535;
        }

        if ($shouldProceedDnsUpdate && $record_type_upper === 'SRV') {
            if ($record_port < 1 || $record_port > 65535) {
                $msg = self::actionText('dns.validation.srv_port', 'SRV记录的端口必须在1-65535之间');
                $msg_type = 'danger';
                $shouldProceedDnsUpdate = false;
            }
            $record_priority = max(0, min(65535, $record_priority));
            $record_weight = max(0, min(65535, $record_weight));
            $record_target_clean = rtrim($record_target, '.');
            $record_target_clean = trim($record_target_clean);
            if ($shouldProceedDnsUpdate && $record_target_clean === '') {
                $msg = self::actionText('dns.validation.srv_target_required', 'SRV记录的目标地址不能为空');
                $msg_type = 'danger';
                $shouldProceedDnsUpdate = false;
            }
            if ($shouldProceedDnsUpdate && !cfmod_is_valid_hostname($record_target_clean)) {
                $msg = self::actionText('dns.validation.srv_target_invalid', '请输入有效的SRV目标主机名');
                $msg_type = 'danger';
                $shouldProceedDnsUpdate = false;
            }
            if ($shouldProceedDnsUpdate) {
                $record_target = $record_target_clean;
                $record_content = $record_priority . ' ' . $record_weight . ' ' . $record_port . ' ' . $record_target;
            }
        }

        if (cfmod_dns_name_has_invalid_edges($record_name)) {
            $msg = self::actionText('dns.validation.name_invalid', "解析名称不能以 '.' 或 '-' 开头或结尾，也不能包含连续的 '.'");
            $msg_type = "danger";
            $shouldProceedDnsUpdate = false;
        }

        if ($shouldProceedDnsUpdate) {
            try {
                $record = Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $subdomain_id)
                    ->where('userid', $userid)
                    ->first();

                if ($record) {
                    if ($record->status === 'suspended') {
                        $msg = self::actionText('dns.domain_suspended', '该域名已被暂停，无法进行解析操作');
                        $msg_type = "warning";
                    } else {
                        $targetRecord = null;
                        if ($record_id) {
                            $targetRecord = Capsule::table('mod_cloudflare_dns_records')
                                ->where('subdomain_id', $subdomain_id)
                                ->where('record_id', $record_id)
                                ->first();
                        } elseif ($record_name) {
                            $fullName = $record_name === '@' ? $record->subdomain : ($record_name . '.' . $record->subdomain);
                            $targetRecord = Capsule::table('mod_cloudflare_dns_records')
                                ->where('subdomain_id', $subdomain_id)
                                ->where('name', $fullName)
                                ->first();
                        }

                        if ($targetRecord) {
                            list($cf, $providerError, $providerContext) = cfmod_client_acquire_provider_for_subdomain($record, $module_settings);
                            if (!$cf) {
                                $msg = $providerError;
                                $msg_type = 'danger';
                            } else {
                                $newFullName = ($record_name === '@') ? $record->subdomain : ($record_name . '.' . $record->subdomain);
                                $caa_content = null;

                                if ($record_type_upper === 'CAA') {
                                    $caa_flag = intval($_POST['caa_flag'] ?? 0);
                                    $caa_tag = trim($_POST['caa_tag'] ?? 'issue');
                                    $caa_value = trim($_POST['caa_value'] ?? '');
                                    if ($caa_value === '') {
                                        $msg = self::actionText('dns.validation.caa_value_required', 'CAA记录的Value不能为空');
                                        $msg_type = 'warning';
                                        throw new Exception($msg);
                                    }
                                    $caa_content = $caa_flag . ' ' . $caa_tag . ' "' . str_replace('"', '\"', $caa_value) . '"';
                                    $res = $cf->updateDnsRecord($record->cloudflare_zone_id, $targetRecord->record_id, [
                                        'type' => $record_type_upper,
                                        'name' => $newFullName,
                                        'content' => $caa_content,
                                        'ttl' => $record_ttl
                                    ]);
                                } else {
                                    $res = $cf->updateDnsRecordRaw($record->cloudflare_zone_id, $targetRecord->record_id, [
                                        'type' => $record_type_upper,
                                        'name' => $newFullName,
                                        'content' => $record_content,
                                        'ttl' => $record_ttl,
                                        'line' => $line,
                                        'priority' => $record_priority
                                    ]);
                                }

                                if ($res['success']) {
                                    try {
                                        $fresh = $cf->getDnsRecords($record->cloudflare_zone_id, $record->subdomain);
                                        if (($fresh['success'] ?? false)) {
                                            foreach (($fresh['result'] ?? []) as $fr) {
                                                $exists = self::findLocalRecordByRemote($subdomain_id, $fr);
                                                if (!$exists) {
                                                    Capsule::table('mod_cloudflare_dns_records')->insert([
                                                        'subdomain_id' => $subdomain_id,
                                                        'zone_id' => $record->cloudflare_zone_id,
                                                        'record_id' => isset($fr['id']) ? (string) $fr['id'] : null,
                                                        'name' => ($fr['name'] ?? $record->subdomain),
                                                        'type' => strtoupper(trim((string)($fr['type'] ?? 'A'))),
                                                        'content' => (string)($fr['content'] ?? ''),
                                                        'ttl' => intval($fr['ttl'] ?? 600),
                                                        'proxied' => 0,
                                                        'status' => 'active',
                                                        'created_at' => date('Y-m-d H:i:s'),
                                                        'updated_at' => date('Y-m-d H:i:s')
                                                    ]);
                                                }
                                            }
                                        }
                                    } catch (Exception $e) {
                                    }

                                    CfSubdomainService::syncDnsHistoryFlag($subdomain_id);

                                    $final_content = $record_content;
                                    if ($record_type_upper === 'CAA' && $caa_content !== null) {
                                        $final_content = $caa_content;
                                    }

                                    $updatedRecordId = isset($res['result']['id']) ? (string) $res['result']['id'] : null;

                                    $updatePayload = [
                                        'type' => $record_type_upper,
                                        'name' => $newFullName,
                                        'content' => $final_content,
                                        'ttl' => $record_ttl,
                                        'proxied' => 0,
                                        'line' => $line,
                                        'priority' => in_array($record_type_upper, ['MX','SRV']) ? $record_priority : null,
                                        'updated_at' => date('Y-m-d H:i:s')
                                    ];
                                    if ($updatedRecordId !== null && $updatedRecordId !== '') {
                                        $updatePayload['record_id'] = $updatedRecordId;
                                        $targetRecord->record_id = $updatedRecordId;
                                    }

                                    Capsule::table('mod_cloudflare_dns_records')
                                        ->where('id', $targetRecord->id)
                                        ->update($updatePayload);

                                    if ($newFullName === $record->subdomain) {
                                        Capsule::table('mod_cloudflare_subdomain')
                                            ->where('id', $subdomain_id)
                                            ->update([
                                                'notes' => '已解析',
                                                'updated_at' => date('Y-m-d H:i:s')
                                            ]);
                                    }

                                    if (function_exists('cloudflare_subdomain_log')) {
                                        cloudflare_subdomain_log(
                                            'client_update_dns',
                                            ['record_id' => $targetRecord->record_id, 'type' => $record_type_upper, 'content' => $record_content, 'ttl' => $record_ttl, 'line' => $line],
                                            $userid,
                                            $subdomain_id
                                        );
                                    }

                                    if ($record_name === '@') {
                                        $msg = self::actionText('dns.update.success', 'DNS记录更新成功！域名解析已更新');
                                    } else {
                                        $msg = self::actionText('dns.update.success', 'DNS记录更新成功！域名解析已更新');
                                    }
                                    $msg_type = "success";
                                } else {
                                    $errorText = cfmod_format_provider_error($res['errors'] ?? '');
                                    $msg = self::actionText('dns.update.failed', 'DNS记录更新失败：%s', [$errorText]);
                                    $msg_type = "danger";
                                }
                            }
                        }
                    }
                }
            } catch (Exception $e) {
                $errorText = cfmod_format_provider_error($e->getMessage());
                $msg = self::actionText('dns.update.failed', 'DNS记录更新失败：%s', [$errorText]);
                $msg_type = "danger";
            }
        }
    }
}

// 处理CDN控制请求（同步记录表）
if($_POST['action'] == "toggle_cdn" && isset($_POST['subdomain_id'])) {
    if (!$disableDnsWrite && !$isUserBannedOrInactive && self::shouldUseAsyncDns('toggle_cdn', $module_settings, $isAsyncReplay)) {
        $jobId = self::enqueueAsyncDnsJob(intval($userid ?? 0), 'toggle_cdn');
        $msg = self::formatAsyncQueuedMessage($jobId);
        $msg_type = 'info';
    } elseif ($disableDnsWrite) {
        $msg = self::actionText('dns.operations_disabled', '当前已禁止新增/修改 DNS 记录');
        $msg_type = 'warning';
    } else {
        if ($isUserBannedOrInactive) {
            $msg = self::actionText('dns.cdn.domain.banned', '您的账号已被封禁或停用，禁止更改CDN代理状态。') . ($banReasonText ? (' ' . $banReasonText) : '');
            $msg_type = 'danger';
        }

        $subdomain_id = intval($_POST['subdomain_id']);
        $proxied = $_POST['proxied'] == '1';

        try {
            $record = Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomain_id)
                ->where('userid', $userid)
                ->first();

            if ($record && $record->dns_record_id) {
                if ($record->status === 'suspended') {
                    $msg = self::actionText('dns.domain_suspended', '该域名已被暂停，无法进行解析操作');
                    $msg_type = "warning";
                } else {
                    list($cf, $providerError, $providerContext) = cfmod_client_acquire_provider_for_subdomain($record, $module_settings);
                    if (!$cf) {
                        $msg = $providerError;
                        $msg_type = 'danger';
                    } else {
                        $res = $cf->toggleProxy($record->cloudflare_zone_id, $record->dns_record_id, $proxied);

                        if ($res['success']) {
                            Capsule::table('mod_cloudflare_dns_records')
                                ->where('subdomain_id', $subdomain_id)
                                ->where('record_id', $record->dns_record_id)
                                ->update([
                                    'proxied' => $proxied ? 1 : 0,
                                    'updated_at' => date('Y-m-d H:i:s')
                                ]);

                            if (function_exists('cloudflare_subdomain_log')) {
                                cloudflare_subdomain_log('client_toggle_cdn', ['proxied' => $proxied], $userid, $subdomain_id);
                            }

                            $statusLabel = $proxied ? self::actionText('common.enabled', '启用') : self::actionText('common.disabled', '禁用');
                            $msg = self::actionText('dns.cdn.domain.status', 'CDN状态已%s', [$statusLabel]);
                            $msg_type = "success";
                        } else {
                            $msg = self::actionText('dns.cdn.domain.update_failed', 'CDN状态更新失败');
                            $msg_type = "danger";
                        }
                    }
                }
            }
        } catch (Exception $e) {
            $errorText = cfmod_format_provider_error($e->getMessage(), self::actionText('dns.cdn.domain.retry', 'CDN状态更新失败，请稍后再试。'));
            $msg = self::actionText('dns.cdn.domain.control_failed', 'CDN控制失败：%s', [$errorText]);
            $msg_type = "danger";
        }
    }
}

// 处理单条记录的CDN代理开关
if($_POST['action'] == "toggle_record_cdn" && isset($_POST['subdomain_id']) && isset($_POST['record_id'])) {
    if (!$disableDnsWrite && !$isUserBannedOrInactive && self::shouldUseAsyncDns('toggle_record_cdn', $module_settings, $isAsyncReplay)) {
        $jobId = self::enqueueAsyncDnsJob(intval($userid ?? 0), 'toggle_record_cdn');
        $msg = self::formatAsyncQueuedMessage($jobId);
        $msg_type = 'info';
    } elseif ($disableDnsWrite) {
        $msg = self::actionText('dns.operations_disabled', '当前已禁止新增/修改 DNS 记录');
        $msg_type = 'warning';
    } else {
        if ($isUserBannedOrInactive) {
            $msg = self::actionText('dns.cdn.record.banned', '您的账号已被封禁或停用，禁止更改记录的CDN代理状态。') . ($banReasonText ? (' ' . $banReasonText) : '');
            $msg_type = 'danger';
        }

        $subdomain_id = intval($_POST['subdomain_id']);
        $record_id = trim($_POST['record_id']);
        $proxied = $_POST['proxied'] == '1';

        try {
            $sub = Capsule::table('mod_cloudflare_subdomain')
                ->where('id', $subdomain_id)
                ->where('userid', $userid)
                ->first();

            if ($sub) {
                if ($sub->status === 'suspended') {
                    $msg = self::actionText('dns.domain_suspended', '该域名已被暂停，无法进行解析操作');
                    $msg_type = "warning";
                } else {
                    $rec = Capsule::table('mod_cloudflare_dns_records')
                        ->where('subdomain_id', $subdomain_id)
                        ->where('record_id', $record_id)
                        ->first();

                    if ($rec && in_array($rec->type, ['A','AAAA','CNAME'])) {
                        list($cf, $providerError, $providerContext) = cfmod_client_acquire_provider_for_subdomain($sub, $module_settings);
                        if (!$cf) {
                            $msg = $providerError;
                            $msg_type = 'danger';
                        } else {
                            $res = $cf->toggleProxy($sub->cloudflare_zone_id, $record_id, $proxied);
                            if ($res['success']) {
                                Capsule::table('mod_cloudflare_dns_records')
                                    ->where('id', $rec->id)
                                    ->update([
                                        'proxied' => $proxied ? 1 : 0,
                                        'updated_at' => date('Y-m-d H:i:s')
                                    ]);

                                if (function_exists('cloudflare_subdomain_log')) {
                                    cloudflare_subdomain_log('client_toggle_record_cdn', ['record_id' => $record_id, 'proxied' => $proxied], $userid, $subdomain_id);
                                }

                                $statusLabel = $proxied ? self::actionText('common.enabled', '启用') : self::actionText('common.disabled', '禁用');
                                $msg = self::actionText('dns.cdn.record.status', '记录CDN状态已%s', [$statusLabel]);
                                $msg_type = "success";
                            } else {
                                $msg = self::actionText('dns.cdn.record.update_failed', '记录CDN状态更新失败');
                                $msg_type = "danger";
                            }
                        }
                    }
                }
            }
        } catch (Exception $e) {
            $errorText = cfmod_format_provider_error($e->getMessage());
            $msg = self::actionText('dns.cdn.record.control_failed', '记录CDN控制失败：%s', [$errorText]);
            $msg_type = "danger";
        }
    }
}

// 处理DNS记录删除请求（仅删除某条记录）- 删除操作不检测VPN
if($_POST['action'] == "delete_dns_record" && isset($_POST['record_id']) && isset($_POST['subdomain_id'])) {
    if ($isUserBannedOrInactive) {
        $msg = self::actionText('dns.delete.banned', '您的账号已被封禁或停用，禁止删除DNS记录。') . ($banReasonText ? (' ' . $banReasonText) : '');
        $msg_type = 'danger';
    } elseif (self::shouldUseAsyncDns('delete_dns_record', $module_settings, $isAsyncReplay)) {
        $jobId = self::enqueueAsyncDnsJob(intval($userid ?? 0), 'delete_dns_record');
        $msg = self::formatAsyncQueuedMessage($jobId);
        $msg_type = 'info';
        return [
            'msg' => $msg,
            'msg_type' => $msg_type,
            'registerError' => $registerError,
        ];
    }

    $subdomain_id = intval($_POST['subdomain_id']);
    $record_id = trim($_POST['record_id']);

    try {
        $sub = Capsule::table('mod_cloudflare_subdomain')
            ->where('id', $subdomain_id)
            ->where('userid', $userid)
            ->first();

        if ($sub) {
            $rec = Capsule::table('mod_cloudflare_dns_records')
                ->where('subdomain_id', $subdomain_id)
                ->where('record_id', $record_id)
                ->first();

            if ($rec) {
                list($cf, $providerError, $providerContext) = cfmod_client_acquire_provider_for_subdomain($sub, $module_settings);
                if (!$cf) {
                    $msg = $providerError;
                    $msg_type = 'danger';
                } else {
                    $delRes = $cf->deleteSubdomain($sub->cloudflare_zone_id, $record_id);
                    if ($delRes['success']) {
                        try {
                            $fresh = $cf->getDnsRecords($sub->cloudflare_zone_id, $sub->subdomain);
                            if (($fresh['success'] ?? false)) {
                                foreach (($fresh['result'] ?? []) as $fr) {
                                    $exists = self::findLocalRecordByRemote($subdomain_id, $fr);
                                    if (!$exists) {
                                        Capsule::table('mod_cloudflare_dns_records')->insert([
                                            'subdomain_id' => $subdomain_id,
                                            'zone_id' => $sub->cloudflare_zone_id,
                                            'record_id' => isset($fr['id']) ? (string) $fr['id'] : null,
                                            'name' => ($fr['name'] ?? $sub->subdomain),
                                            'type' => strtoupper($fr['type'] ?? 'A'),
                                            'content' => ($fr['content'] ?? ''),
                                            'ttl' => intval($fr['ttl'] ?? 600),
                                            'proxied' => 0,
                                            'status' => 'active',
                                            'created_at' => date('Y-m-d H:i:s'),
                                            'updated_at' => date('Y-m-d H:i:s')
                                        ]);
                                    }
                                }
                            }
                        } catch (Exception $e) {}

                        CfSubdomainService::syncDnsHistoryFlag($subdomain_id);

                        Capsule::table('mod_cloudflare_dns_records')
                            ->where('id', $rec->id)
                            ->delete();

                        if ($rec->name === $sub->subdomain && $sub->dns_record_id === $record_id) {
                            Capsule::table('mod_cloudflare_subdomain')
                                ->where('id', $subdomain_id)
                                ->update([
                                    'dns_record_id' => null,
                                    'updated_at' => date('Y-m-d H:i:s')
                                ]);
                        }

                        $remainingRecords = Capsule::table('mod_cloudflare_dns_records')
                            ->where('subdomain_id', $subdomain_id)
                            ->count();
                        if ($remainingRecords == 0) {
                            Capsule::table('mod_cloudflare_subdomain')
                                ->where('id', $subdomain_id)
                                ->update([
                                    'notes' => '已注册，等待解析设置',
                                    'updated_at' => date('Y-m-d H:i:s')
                                ]);
                        }

                        if (function_exists('cloudflare_subdomain_log')) {
                            cloudflare_subdomain_log('client_delete_dns_record', ['record_id' => $record_id, 'name' => $rec->name], $userid, $subdomain_id);
                        }

                        $msg = self::actionText('dns.delete.success', '已删除DNS记录');
                        $msg_type = "success";
                    } else {
                        $msg = self::actionText('dns.delete.failed', '删除DNS记录失败');
                        $msg_type = "danger";
                    }
                }
            }
        }
    } catch (Exception $e) {
        $errorText = cfmod_format_provider_error($e->getMessage());
        $msg = self::actionText('dns.delete.failed_detail', '删除DNS记录失败：%s', [$errorText]);
        $msg_type = "danger";
    }
}

// 一键替换入整组 NS（域名委派）
if($_POST['action'] == 'replace_ns_group' && isset($_POST['subdomain_id'])) {
    if ($enableDnsUnlockFeature && !CfDnsUnlockService::userHasUnlocked($userid ?? 0)) {
        $msg = self::actionText('dns.unlock.required', '请先完成 DNS 解锁后再设置 DNS 服务器。');
        $msg_type = 'warning';
        return [
            'msg' => $msg,
            'msg_type' => $msg_type,
            'registerError' => $registerError,
        ];
    }
    // VPN/代理检测（NS替换操作）
    if (class_exists('CfVpnDetectionService') && CfVpnDetectionService::isDnsCheckEnabled($module_settings)) {
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
        $vpnCheckResult = CfVpnDetectionService::shouldBlockDnsOperation($clientIp, $module_settings);
        if (!empty($vpnCheckResult['blocked'])) {
            $msg = self::actionText('dns.vpn_blocked', '检测到您正在使用VPN或代理，请关闭后再进行DNS操作。');
            $msg_type = 'warning';
            if (function_exists('cloudflare_subdomain_log')) {
                cloudflare_subdomain_log('vpn_detection_blocked_dns', [
                    'action' => 'replace_ns_group',
                    'ip' => $clientIp,
                    'reason' => $vpnCheckResult['reason'] ?? 'unknown',
                ], $userid ?? 0, null);
            }
            return [
                'msg' => $msg,
                'msg_type' => $msg_type,
                'registerError' => $registerError,
            ];
        }
    }
    if (!$disableNsManagement && !$disableDnsWrite && self::shouldUseAsyncDns('replace_ns_group', $module_settings, $isAsyncReplay)) {
        $jobId = self::enqueueAsyncDnsJob(intval($userid ?? 0), 'replace_ns_group');
        $msg = self::formatAsyncQueuedMessage($jobId);
        $msg_type = 'info';
        return [
            'msg' => $msg,
            'msg_type' => $msg_type,
            'registerError' => $registerError,
        ];
    }

    if ($disableNsManagement || $disableDnsWrite) {
        $msg = self::actionText('dns.operations_disabled', '当前已禁止新增/修改 DNS 记录');
        $msg_type = 'warning';
    } else {
        if ($disableNsManagement) {
            $msg = self::actionText('dns.ns.disabled', '已禁止设置 DNS 服务器（NS）。');
            $msg_type = 'warning';
        } else {
            $subdomain_id = intval($_POST['subdomain_id']);
            $lines = trim($_POST['ns_lines'] ?? '');
            $forceReplace = isset($_POST['force_replace']) && $_POST['force_replace'] == '1';

            $preList = array_filter(
                array_unique(array_map(function ($x) {
                    return strtolower(trim($x));
                }, explode("\n", $lines))),
                function ($v) {
                    return !empty($v);
                }
            );
            if (count($preList) > $nsMaxPerDomain) {
                $msg = self::actionText('dns.ns.submission_limit', 'NS 服务器最多允许 %1$s 条；当前提交 %2$s 条，请删减后重试', [$nsMaxPerDomain, count($preList)]);
                $msg_type = 'warning';
                throw new Exception($msg);
            }

            try {
                $sub = Capsule::table('mod_cloudflare_subdomain')
                    ->where('id', $subdomain_id)
                    ->where('userid', $userid)
                    ->first();

                if ($sub) {
                    if ($sub->status === 'suspended') {
                        $msg = self::actionText('dns.domain_suspended', '该域名已被暂停，无法进行解析操作');
                        $msg_type = "warning";
                    } else {
                        list($cf, $providerError, $providerContext) = cfmod_client_acquire_provider_for_subdomain($sub, $module_settings);
                        if (!$cf) {
                            $msg = $providerError;
                            $msg_type = 'danger';
                        } else {
                            $deletedCount = 0;
                            $existing = $cf->getDnsRecords($sub->cloudflare_zone_id, $sub->subdomain, ['type' => 'NS']);
                            if ($existing['success']) {
                                foreach ($existing['result'] as $r) {
                                    if (strtoupper($r['type']) === 'NS' && ($r['name'] ?? '') === $sub->subdomain) {
                                        $delRes = $cf->deleteSubdomain($sub->cloudflare_zone_id, $r['id']);
                                        if ($delRes['success']) {
                                            $deletedCount++;
                                        }
                                        Capsule::table('mod_cloudflare_dns_records')
                                            ->where('subdomain_id', $subdomain_id)
                                            ->where('record_id', $r['id'])
                                            ->delete();
                                    }
                                }
                            }

                            $conflictDeleted = 0;
                            if ($forceReplace) {
                                $allAt = $cf->getDnsRecords($sub->cloudflare_zone_id, $sub->subdomain);
                                if ($allAt['success']) {
                                    foreach ($allAt['result'] as $r) {
                                        $t = strtoupper($r['type'] ?? '');
                                        if (($r['name'] ?? '') === $sub->subdomain && $t !== 'NS') {
                                            $delRes = $cf->deleteSubdomain($sub->cloudflare_zone_id, $r['id']);
                                            if ($delRes['success']) {
                                                $conflictDeleted++;
                                            }
                                            Capsule::table('mod_cloudflare_dns_records')
                                                ->where('subdomain_id', $subdomain_id)
                                                ->where('record_id', $r['id'])
                                                ->delete();
                                        }
                                    }
                                }
                            }

                            $list = array_filter(
                                array_unique(array_map(function ($x) {
                                    return strtolower(trim($x));
                                }, explode("\n", $lines))),
                                function ($v) {
                                    return !empty($v);
                                }
                            );
                            $validList = [];
                            $invalidList = [];
                            $domainRegex = '/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+\.?$/i';
                            foreach ($list as $ns) {
                                if (preg_match($domainRegex, $ns)) {
                                    $validList[] = rtrim($ns, '.');
                                } else {
                                    $invalidList[] = $ns;
                                }
                            }
                            if (count($validList) === 0) {
                                $msg = self::actionText('dns.ns.no_valid_servers', '未检测到有效的 NS 服务器，请检查格式（每行一个完整域名）');
                                $msg_type = 'warning';
                                throw new Exception($msg);
                            }

                            $limitPerSub = intval($module_settings['max_dns_records_per_subdomain'] ?? 0);
                            if ($limitPerSub > 0) {
                                $currentCount = Capsule::table('mod_cloudflare_dns_records')
                                    ->where('subdomain_id', $subdomain_id)
                                    ->count();
                                if ($currentCount + count($validList) > $limitPerSub) {
                                    $msg = self::actionText('dns.ns.limit_exceeded', '此次替换将超出该域名的解析数量上限（%s），已取消操作', [$limitPerSub]);
                                    $msg_type = 'warning';
                                    throw new Exception($msg);
                                }
                            }

                            $created = [];
                            $errors = [];
                            foreach ($validList as $ns) {
                                $res = $cf->createDnsRecord($sub->cloudflare_zone_id, $sub->subdomain, 'NS', $ns, 86400, false);
                                if ($res['success']) {
                                    $rid = $res['result']['id'];
                                    Capsule::table('mod_cloudflare_dns_records')->insert([
                                        'subdomain_id' => $subdomain_id,
                                        'zone_id' => $sub->cloudflare_zone_id,
                                        'record_id' => $rid !== null ? (string) $rid : null,
                                        'name' => $sub->subdomain,
                                        'type' => 'NS',
                                        'content' => $ns,
                                        'ttl' => 86400,
                                        'proxied' => 0,
                                        'line' => null,
                                        'status' => 'active',
                                        'created_at' => date('Y-m-d H:i:s'),
                                        'updated_at' => date('Y-m-d H:i:s')
                                    ]);
                                    $created[] = $ns;
                                } else {
                                    $errMsg = self::actionText('errors.unknown', '未知错误');
                                    if (!empty($res['errors'])) {
                                        $errMsg = is_array($res['errors'])
                                            ? json_encode($res['errors'], JSON_UNESCAPED_UNICODE)
                                            : (string) $res['errors'];
                                    }
                                    $errors[] = ['ns' => $ns, 'error' => $errMsg];
                                }
                            }
                            CfSubdomainService::syncDnsHistoryFlag($subdomain_id);

                            if (function_exists('cloudflare_subdomain_log')) {
                                cloudflare_subdomain_log('client_replace_ns_group', [
                                    'deletedCount' => $deletedCount,
                                    'conflictDeleted' => $conflictDeleted,
                                    'created' => $created,
                                    'invalid' => $invalidList,
                                    'errors' => $errors
                                ], $userid, $subdomain_id);
                            }

                            $parts = [];
                            $parts[] = self::actionText('dns.ns.summary.deleted', '已删除旧 NS %s 条', [$deletedCount]);
                            if ($forceReplace) {
                                $parts[] = self::actionText('dns.ns.summary.conflicts', '已清理冲突记录 %s 条', [$conflictDeleted]);
                            }
                            $parts[] = self::actionText('dns.ns.summary.created', '新增成功 %s 条', [count($created)]);
                            if (count($invalidList) > 0) {
                                $preview = implode(', ', array_slice($invalidList, 0, 3));
                                if ($preview) {
                                    $parts[] = self::actionText('dns.ns.summary.invalid_preview', '忽略无效格式 %1$s 条（示例：%2$s）', [count($invalidList), $preview]);
                                } else {
                                    $parts[] = self::actionText('dns.ns.summary.invalid', '忽略无效格式 %s 条', [count($invalidList)]);
                                }
                            }
                            if (count($errors) > 0) {
                                $previewErr = [];
                                foreach (array_slice($errors, 0, 3) as $er) {
                                    $previewErr[] = ($er['ns'] ?? '?') . ' => ' . ($er['error'] ?? '');
                                }
                                if (count($previewErr)) {
                                    $parts[] = self::actionText('dns.ns.summary.failed_preview', '新增失败 %1$s 条（示例：%2$s）', [count($errors), implode('; ', $previewErr)]);
                                } else {
                                    $parts[] = self::actionText('dns.ns.summary.failed', '新增失败 %s 条', [count($errors)]);
                                }
                            }
                            $separator = self::actionText('common.list_separator', '，');
                            $msg = implode($separator, $parts);
                            $msg_type = (count($created) > 0 && count($errors) === 0)
                                ? 'success'
                                : (count($created) > 0 ? 'warning' : 'danger');

                            list($existing, $existing_total, $domainTotalPages, $domainPage) = cfmod_client_load_subdomains_paginated(
                                $userid,
                                $domainPage,
                                $domainPageSize,
                                $domainSearchTerm
                            );
                        }
                    }
                }
            } catch (Exception $e) {
                if (!isset($msg) || !$msg) {
                    $errorText = cfmod_format_provider_error($e->getMessage());
                    $msg = self::actionText('dns.ns.bulk_failed', '批量替换 NS 失败：%s', [$errorText]);
                }
                $msg_type = isset($msg_type) && $msg_type ? $msg_type : 'danger';
            }
        }
    }
}



        return [
            'msg' => $msg,
            'msg_type' => $msg_type,
            'registerError' => $registerError,
        ];
    }

    private static function enforceClientRateLimit(string $action, array $settings, int $userid): void
    {
        $scope = self::resolveClientRateLimitScope($action);
        if ($scope === null) {
            return;
        }
        $limit = CfRateLimiter::resolveLimit($scope, $settings);
        CfRateLimiter::enforce($scope, $limit, [
            'userid' => $userid,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'identifier' => $action,
        ]);
    }

    private static function resolveClientRateLimitScope(string $action): ?string
    {
        static $dnsActions = ['create_dns', 'update_dns', 'delete_dns_record', 'toggle_cdn', 'toggle_record_cdn', 'delete_subdomain'];
        static $quotaActions = ['claim_invite', 'request_invite_reward'];
        if ($action === 'register') {
            return CfRateLimiter::SCOPE_REGISTER;
        }
        if (in_array($action, $dnsActions, true)) {
            return CfRateLimiter::SCOPE_DNS;
        }
        if (in_array($action, $quotaActions, true)) {
            return CfRateLimiter::SCOPE_QUOTA_GIFT;
        }
        if ($action === 'dns_unlock' || $action === 'purchase_dns_unlock') {
            return CfRateLimiter::SCOPE_DNS_UNLOCK;
        }
        return null;
    }

    private static function shouldUseAsyncDns(string $action, array $settings, bool $isAsyncReplay): bool
    {
        if ($isAsyncReplay) {
            return false;
        }
        if (!cfmod_setting_enabled($settings['enable_async_dns_operations'] ?? '0')) {
            return false;
        }
        static $supported = ['create_dns', 'update_dns', 'delete_dns_record', 'replace_ns_group', 'toggle_cdn', 'toggle_record_cdn'];
        return in_array($action, $supported, true);
    }

    private static function enqueueAsyncDnsJob(int $userid, string $action): ?int
    {
        if (!class_exists('CfAsyncDnsJobService')) {
            return null;
        }
        if ($userid <= 0) {
            return null;
        }
        $payload = self::buildAsyncPostPayload($_POST);
        return CfAsyncDnsJobService::enqueue($userid, $action, $payload);
    }

    private static function buildAsyncPostPayload(array $input): array
    {
        $payload = $input;
        unset($payload['token'], $payload['cfmod_csrf_token']);
        $payload['__cf_async_dns'] = 1;
        return $payload;
    }

    private static function formatAsyncQueuedMessage(?int $jobId): string
    {
        $message = self::actionText('dns.async.queued', '操作已提交到后台队列，将在稍后自动执行。');
        if ($jobId) {
            $message .= ' ' . self::actionText('dns.async.job', '任务编号：#%s', [$jobId]);
        }
        return $message;
    }

    private static function actionText(string $key, string $default, array $params = []): string
    {
        $text = cfmod_trans('cfclient.actions.' . $key, $default);
        if (!empty($params)) {
            try {
                $text = vsprintf($text, $params);
            } catch (\Throwable $e) {
                // ignore formatting errors
            }
        }
        return $text;
    }

    private static function resolveClientEmail(int $userid): string
    {
        if ($userid <= 0) {
            return '';
        }
        try {
            $row = Capsule::table('tblclients')->select('email')->where('id', $userid)->first();
            return trim((string) ($row->email ?? ''));
        } catch (\Throwable $e) {
            return '';
        }
    }

    private static function findLocalRecordByRemote(int $subdomainId, array $remoteRecord)
    {
        if ($subdomainId <= 0) {
            return null;
        }
        $remoteRecordId = $remoteRecord['id'] ?? ($remoteRecord['record_id'] ?? null);
        if ($remoteRecordId !== null && $remoteRecordId !== '') {
            $match = Capsule::table('mod_cloudflare_dns_records')
                ->where('subdomain_id', $subdomainId)
                ->where('record_id', (string) $remoteRecordId)
                ->first();
            if ($match) {
                return $match;
            }
        }

        $remoteNameLower = strtolower(trim((string)($remoteRecord['name'] ?? '')));
        $remoteTypeUpper = strtoupper(trim((string)($remoteRecord['type'] ?? '')));
        $remoteContent = (string)($remoteRecord['content'] ?? '');
        if ($remoteNameLower === '' || $remoteTypeUpper === '') {
            return null;
        }
        return Capsule::table('mod_cloudflare_dns_records')
            ->where('subdomain_id', $subdomainId)
            ->whereRaw('LOWER(name) = ?', [$remoteNameLower])
            ->whereRaw('UPPER(type) = ?', [$remoteTypeUpper])
            ->where(function ($query) use ($remoteContent) {
                $query->where('content', $remoteContent)
                    ->orWhereRaw('LOWER(content) = ?', [strtolower($remoteContent)]);
            })
            ->first();
    }
}
