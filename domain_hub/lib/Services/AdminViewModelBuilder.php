<?php
// phpcs:ignoreFile

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfAdminViewModelBuilder
{
    private const BLOCK_KEYS = [
        'alerts',
        'stats',
        'providers',
        'rootdomains',
        'announcements',
        'api',
        'privileged',
        'quotas',
        'domainGifts',
        'bans',
        'invite',
        'jobs',
        'runtime',
        'risk',
        'logs',
        'maintenance',
    ];

    private const STATS_CACHE_SESSION_KEY = 'cfmod_admin_stats_cache_v1';
    private const STATS_CACHE_TTL_SECONDS = 300;

    public static function build(): array
    {
        $moduleSettings = self::loadModuleSettings();
        $providers = self::buildProviders($moduleSettings);

        $viewModel = self::initializeBlocks();
        $viewModel['alerts'] = self::buildAlerts();
        $viewModel['stats'] = self::buildStats();
        $viewModel['providers'] = $providers;
        $rootdomainsView = self::buildRootdomains($moduleSettings, $providers);
        $viewModel['rootdomains'] = $rootdomainsView;
        $viewModel['announcements'] = self::buildAnnouncements($moduleSettings);
        $viewModel['privileged'] = self::buildPrivileged();
        $viewModel['quotas'] = self::buildQuotas($moduleSettings);
        $viewModel['jobs'] = self::buildJobs($moduleSettings, $rootdomainsView['allKnownRootdomains'] ?? []);
        $viewModel['domainGifts'] = self::buildDomainGifts();
        $viewModel['invite'] = self::buildInviteInsights($moduleSettings);
        $viewModel['bans'] = self::buildBans();
        $viewModel['runtime'] = self::buildRuntimeTools();
$viewModel['dnsUnlockLogs'] = self::buildDnsUnlockLogs();
        $viewModel['logs'] = self::buildLogs();

        return $viewModel;
    }

    private static function buildAlerts(): array
    {
        $alerts = $_SESSION['cfmod_admin_flash'] ?? [];
        if (isset($_SESSION['cfmod_admin_flash'])) {
            unset($_SESSION['cfmod_admin_flash']);
        }

        return [
            'messages' => $alerts,
        ];
    }

    private static function buildStats(): array
    {
        $ustPage = max(1, (int) ($_GET['ust_page'] ?? 1));
        $ustPerPage = 20;
        $userActivity = [
            'items' => [],
            'page' => $ustPage,
            'perPage' => $ustPerPage,
            'total' => 0,
            'totalPages' => 1,
        ];

        $stats = [
            'totalSubdomains' => 0,
            'activeSubdomains' => 0,
            'registeredUsers' => 0,
            'subdomainsCreated' => 0,
            'dnsOperations' => 0,
            'registrationTrend' => [],
            'popularRootdomains' => [],
            'dnsRecordTypes' => [],
            'usagePatterns' => [],
            'userActivity' => $userActivity,
        ];

        $heavyStats = self::resolveCachedStats();
        foreach ($heavyStats as $key => $value) {
            if (array_key_exists($key, $stats)) {
                $stats[$key] = $value;
            }
        }

        try {
            $ustBase = Capsule::table('mod_cloudflare_user_stats');
            $ustTotal = $ustBase->count();
            $stats['userActivity']['total'] = $ustTotal;
            $stats['userActivity']['totalPages'] = max(1, (int) ceil($ustTotal / $ustPerPage));
            if ($ustPage > $stats['userActivity']['totalPages']) {
                $ustPage = $stats['userActivity']['totalPages'];
                $stats['userActivity']['page'] = $ustPage;
            }
            $ustOffset = ($ustPage - 1) * $ustPerPage;
            $stats['userActivity']['items'] = self::normalizeRecords(
                $ustBase->orderBy('id', 'desc')->offset($ustOffset)->limit($ustPerPage)->get()
            );
        } catch (\Throwable $e) {
            $stats['userActivity']['items'] = [];
        }

        return $stats;
    }

    private static function buildProviders(array $moduleSettings): array
    {
        $result = [
            'accounts' => [],
            'accountMap' => [],
            'activeAccounts' => [],
            'usageCounts' => [],
            'error' => '',
            'hasActive' => false,
            'defaultAccountId' => intval($moduleSettings['default_provider_account_id'] ?? 0),
            'defaultSelectId' => intval($moduleSettings['default_provider_account_id'] ?? 0),
        ];

        try {
            cfmod_ensure_provider_schema();
            $accounts = Capsule::table(cfmod_get_provider_table_name())
                ->orderBy('is_default', 'desc')
                ->orderBy('id', 'asc')
                ->get();
            $result['accounts'] = $accounts;
            foreach ($accounts as $acct) {
                $pid = intval($acct->id);
                $result['accountMap'][$pid] = $acct;
                if (strtolower($acct->status ?? '') === 'active') {
                    $result['activeAccounts'][] = $acct;
                }
            }
        } catch (\Throwable $e) {
            $result['error'] = $e->getMessage();
        }

        try {
            $usageRows = Capsule::table('mod_cloudflare_rootdomains')
                ->select('provider_account_id', Capsule::raw('COUNT(*) as total'))
                ->groupBy('provider_account_id')
                ->get();
            foreach ($usageRows as $usageRow) {
                $usageProviderId = intval($usageRow->provider_account_id ?? 0);
                if ($usageProviderId > 0) {
                    $result['usageCounts'][$usageProviderId] = intval($usageRow->total ?? 0);
                }
            }
        } catch (\Throwable $e) {
        }

        $result['hasActive'] = count($result['activeAccounts']) > 0;
        $defaultSelect = $result['defaultAccountId'];
        if ($defaultSelect <= 0
            || !isset($result['accountMap'][$defaultSelect])
            || strtolower($result['accountMap'][$defaultSelect]->status ?? '') !== 'active') {
            if (!empty($result['activeAccounts'])) {
                $defaultSelect = intval($result['activeAccounts'][0]->id);
            }
        }
        $result['defaultSelectId'] = $defaultSelect;

        return $result;
    }

    private static function buildRootdomains(array $moduleSettings, array $providers): array
    {
        $result = [
            'hasActiveProviderAccounts' => $providers['hasActive'] ?? false,
            'activeProviderAccounts' => $providers['activeAccounts'] ?? [],
            'defaultProviderSelectId' => $providers['defaultSelectId'] ?? 0,
            'rootdomains' => [],
            'providerAccountMap' => $providers['accountMap'] ?? [],
            'forbiddenDomains' => [],
            'allKnownRootdomains' => [],
        ];

        try {
            $result['rootdomains'] = Capsule::table('mod_cloudflare_rootdomains')
                ->orderBy('display_order', 'asc')
                ->orderBy('id', 'asc')
                ->get();
        } catch (\Throwable $e) {
        }

        try {
            $result['forbiddenDomains'] = Capsule::table('mod_cloudflare_forbidden_domains')
                ->orderBy('id', 'desc')
                ->limit(20)
                ->get();
        } catch (\Throwable $e) {
        }

        if (function_exists('cfmod_get_known_rootdomains')) {
            try {
                $result['allKnownRootdomains'] = cfmod_get_known_rootdomains($moduleSettings);
            } catch (\Throwable $e) {
                $result['allKnownRootdomains'] = [];
            }
        }

        return $result;
    }

    public static function buildRisk(): array
    {
        $riskEventsPerPage = 20;
        $riskEventsPage = max(1, (int) ($_GET['risk_event_page'] ?? 1));
        $riskEventsPerPage = max(1, $riskEventsPerPage);
        $riskEventsOffset = ($riskEventsPage - 1) * $riskEventsPerPage;

        $riskListPerPage = 20;
        $riskListPage = max(1, (int) ($_GET['risk_page'] ?? 1));
        $riskListPerPage = max(1, $riskListPerPage);
        $riskListOffset = ($riskListPage - 1) * $riskListPerPage;
        $levelFilter = trim((string) ($_GET['risk_level'] ?? ''));
        $kwFilter = trim((string) ($_GET['risk_kw'] ?? ''));
        $viewRiskLogId = (int) ($_GET['view_risk_log'] ?? 0);

        $riskData = [
            'top' => [],
            'trend' => [],
            'events' => [
                'items' => [],
                'page' => $riskEventsPage,
                'perPage' => $riskEventsPerPage,
                'total' => 0,
                'totalPages' => 1,
            ],
            'list' => [
                'items' => [],
                'page' => $riskListPage,
                'perPage' => $riskListPerPage,
                'total' => 0,
                'totalPages' => 1,
            ],
            'filters' => [
                'level' => $levelFilter,
                'keyword' => $kwFilter,
            ],
            'log' => [
                'subdomainId' => $viewRiskLogId,
                'entries' => [],
            ],
        ];

        try {
            $riskData['top'] = Capsule::table('mod_cloudflare_domain_risk as r')
                ->leftJoin('mod_cloudflare_subdomain as s', 'r.subdomain_id', '=', 's.id')
                ->select('r.*', 's.subdomain', 's.status')
                ->orderBy('r.risk_score', 'desc')
                ->limit(10)
                ->get();

            $since = date('Y-m-d H:i:s', time() - 7 * 86400);
            $riskData['trend'] = Capsule::table('mod_cloudflare_risk_events')
                ->select(Capsule::raw('DATE(created_at) as d'), Capsule::raw('COUNT(*) as c'))
                ->where('created_at', '>=', $since)
                ->groupBy(Capsule::raw('DATE(created_at)'))
                ->orderBy('d', 'asc')
                ->get();

            $riskEventsTotal = Capsule::table('mod_cloudflare_risk_events')->count();
            $riskEventsTotalPages = max(1, (int) ceil($riskEventsTotal / $riskEventsPerPage));
            if ($riskEventsPage > $riskEventsTotalPages) {
                $riskEventsPage = $riskEventsTotalPages;
                $riskEventsOffset = ($riskEventsPage - 1) * $riskEventsPerPage;
            }

            $riskEventsItems = Capsule::table('mod_cloudflare_risk_events as e')
                ->leftJoin('mod_cloudflare_subdomain as s', 'e.subdomain_id', '=', 's.id')
                ->select('e.*', 's.subdomain')
                ->orderBy('e.id', 'desc')
                ->offset($riskEventsOffset)
                ->limit($riskEventsPerPage)
                ->get();

            $riskData['events']['items'] = $riskEventsItems;
            $riskData['events']['total'] = $riskEventsTotal;
            $riskData['events']['totalPages'] = $riskEventsTotalPages;
            $riskData['events']['page'] = $riskEventsPage;
        } catch (\Throwable $e) {
        }

        try {
            $baseQuery = Capsule::table('mod_cloudflare_domain_risk as r')
                ->leftJoin('mod_cloudflare_subdomain as s', 'r.subdomain_id', '=', 's.id')
                ->select('r.*', 's.subdomain', 's.status');

            if ($levelFilter !== '') {
                $baseQuery->where('r.risk_level', $levelFilter);
            }
            if ($kwFilter !== '') {
                $baseQuery->where('s.subdomain', 'like', '%' . $kwFilter . '%');
            }

            $riskTotal = (clone $baseQuery)->count();
            $riskListTotalPages = max(1, (int) ceil($riskTotal / $riskListPerPage));
            if ($riskTotal === 0) {
                $riskListPage = 1;
                $riskListOffset = 0;
                $riskListItems = [];
            } else {
                if ($riskListPage > $riskListTotalPages) {
                    $riskListPage = $riskListTotalPages;
                    $riskListOffset = ($riskListPage - 1) * $riskListPerPage;
                }
                $riskListItems = (clone $baseQuery)
                    ->orderBy('r.risk_score', 'desc')
                    ->offset($riskListOffset)
                    ->limit($riskListPerPage)
                    ->get();
            }

            $riskData['list']['items'] = $riskListItems;
            $riskData['list']['total'] = $riskTotal;
            $riskData['list']['page'] = $riskListPage;
            $riskData['list']['totalPages'] = $riskListTotalPages;
        } catch (\Throwable $e) {
            $riskData['list']['items'] = [];
            $riskData['list']['total'] = 0;
            $riskData['list']['page'] = 1;
            $riskData['list']['totalPages'] = 1;
        }

        if ($viewRiskLogId > 0) {
            try {
                $riskData['log']['entries'] = Capsule::table('mod_cloudflare_risk_events')
                    ->where('subdomain_id', $viewRiskLogId)
                    ->orderBy('id', 'desc')
                    ->limit(100)
                    ->get();
            } catch (\Throwable $e) {
                $riskData['log']['entries'] = [];
            }
        }

        return $riskData;
    }

    private static function buildAnnouncements(array $moduleSettings): array
    {
        $enabled = (string) ($moduleSettings['admin_announce_enabled'] ?? '0');
        $title = trim((string) ($moduleSettings['admin_announce_title'] ?? '公告')) ?: '公告';
        $rawHtml = (string) ($moduleSettings['admin_announce_html'] ?? '');
        $html = html_entity_decode($rawHtml, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return [
            'enabled' => $enabled,
            'title' => $title,
            'html' => $html,
        ];
    }

    private static function buildJobs(array $moduleSettings = [], array $knownRootdomains = []): array
    {
        $jobsPerPage = 20;
        $jobsPage = max(1, (int) ($_GET['jobs_page'] ?? 1));
        $jobsPerPage = max(1, $jobsPerPage);
        $jobsOffset = ($jobsPage - 1) * $jobsPerPage;

        $jobsTotal = 0;
        $jobsTotalPages = 1;
        $jobsItems = [];

        try {
            $jobsTotal = Capsule::table('mod_cloudflare_jobs')->count();
            $jobsTotalPages = max(1, (int) ceil($jobsTotal / $jobsPerPage));
            if ($jobsPage > $jobsTotalPages) {
                $jobsPage = $jobsTotalPages;
                $jobsOffset = ($jobsPage - 1) * $jobsPerPage;
            }
            $jobsItems = Capsule::table('mod_cloudflare_jobs')
                ->orderBy('id', 'desc')
                ->offset($jobsOffset)
                ->limit($jobsPerPage)
                ->get();
            $jobsItems = self::normalizeRecords($jobsItems);
        } catch (\Throwable $e) {
            $jobsItems = [];
        }

        $diffPerPage = 20;
        $diffPage = max(1, (int) ($_GET['diff_page'] ?? 1));
        $diffPerPage = max(1, $diffPerPage);
        $diffOffset = ($diffPage - 1) * $diffPerPage;
        $diffTotal = 0;
        $diffTotalPages = 1;
        $diffItems = [];
        try {
            $diffTotal = Capsule::table('mod_cloudflare_sync_results')->count();
            $diffTotalPages = max(1, (int) ceil($diffTotal / $diffPerPage));
            if ($diffPage > $diffTotalPages) {
                $diffPage = $diffTotalPages;
                $diffOffset = ($diffPage - 1) * $diffPerPage;
            }
            $diffItems = Capsule::table('mod_cloudflare_sync_results')
                ->orderBy('id', 'desc')
                ->offset($diffOffset)
                ->limit($diffPerPage)
                ->get();
            $diffItems = self::normalizeRecords($diffItems);
        } catch (\Throwable $e) {
            $diffItems = [];
        }

        $jobError = null;
        if (isset($_GET['job_error_id'])) {
            try {
                $job = Capsule::table('mod_cloudflare_jobs')
                    ->where('id', (int) $_GET['job_error_id'])
                    ->first();
                if ($job && !empty($job->last_error) && $job->last_error !== 'OK') {
                    $jobError = $job->last_error;
                }
            } catch (\Throwable $e) {
                $jobError = null;
            }
        }

        $summary = [
            'lastCalibrationTime' => '-',
            'lastCalibrationStatus' => '-',
            'calibrationSummary' => [
                'byKind' => [],
                'byAction' => [],
            ],
            'backlogCount' => 0,
            'errorRate' => '-',
        ];

        try {
            $lastJob = Capsule::table('mod_cloudflare_jobs')
                ->where('type', 'calibrate_all')
                ->orderBy('id', 'desc')
                ->first();
            if ($lastJob) {
                $summary['lastCalibrationTime'] = $lastJob->updated_at ?? $lastJob->created_at ?? '-';
                $summary['lastCalibrationStatus'] = $lastJob->status ?? '-';
                $byKind = Capsule::table('mod_cloudflare_sync_results')
                    ->select('kind', Capsule::raw('COUNT(*) as cnt'))
                    ->where('job_id', $lastJob->id)
                    ->groupBy('kind')
                    ->get();
                foreach (self::normalizeRecords($byKind) as $row) {
                    $summary['calibrationSummary']['byKind'][] = [
                        'k' => $row->kind ?? '',
                        'c' => (int) ($row->cnt ?? 0),
                    ];
                }
                $byAction = Capsule::table('mod_cloudflare_sync_results')
                    ->select('action', Capsule::raw('COUNT(*) as cnt'))
                    ->where('job_id', $lastJob->id)
                    ->groupBy('action')
                    ->get();
                foreach (self::normalizeRecords($byAction) as $row) {
                    $summary['calibrationSummary']['byAction'][] = [
                        'a' => $row->action ?? '',
                        'c' => (int) ($row->cnt ?? 0),
                    ];
                }
            }

            $summary['backlogCount'] = Capsule::table('mod_cloudflare_jobs')
                ->whereIn('status', ['pending', 'running'])
                ->count();

            $recent = Capsule::table('mod_cloudflare_jobs')
                ->orderBy('id', 'desc')
                ->limit(20)
                ->get();
            $fail = 0;
            $total = 0;
            foreach (self::normalizeRecords($recent) as $job) {
                $total++;
                if (($job->status ?? '') === 'failed') {
                    $fail++;
                }
            }
            if ($total > 0) {
                $summary['errorRate'] = round($fail * 100 / $total, 1) . '%';
            } else {
                $summary['errorRate'] = '0%';
            }
        } catch (\Throwable $e) {
        }

        $rootdomainOptions = self::prepareRootdomainOptions($knownRootdomains);

        return [
            'jobs' => [
                'items' => $jobsItems,
                'page' => $jobsPage,
                'perPage' => $jobsPerPage,
                'total' => $jobsTotal,
                'totalPages' => $jobsTotalPages,
            ],
            'diffs' => [
                'items' => $diffItems,
                'page' => $diffPage,
                'perPage' => $diffPerPage,
                'total' => $diffTotal,
                'totalPages' => $diffTotalPages,
            ],
            'error' => $jobError,
            'summary' => $summary,
            'rootdomainOptions' => $rootdomainOptions,
        ];
    }

    private static function prepareRootdomainOptions(array $domains): array
    {
        $options = [];
        $seen = [];
        foreach ($domains as $domain) {
            $label = trim((string) $domain);
            if ($label === '') {
                continue;
            }
            $value = strtolower($label);
            if (isset($seen[$value])) {
                continue;
            }
            $seen[$value] = true;
            $options[] = [
                'value' => $value,
                'label' => $label,
            ];
        }
        usort($options, static function (array $a, array $b): int {
            return strcmp($a['label'], $b['label']);
        });
        return $options;
    }

    private static function buildPrivileged(): array
    {
        $keyword = trim((string) ($_GET['privileged_keyword'] ?? ''));
        $result = [
            'keyword' => $keyword,
            'users' => [],
            'userCount' => 0,
            'ids' => [],
            'search' => [
                'performed' => $keyword !== '',
                'results' => [],
                'count' => 0,
            ],
        ];

        try {
            $rows = Capsule::table('mod_cloudflare_special_users as su')
                ->leftJoin('tblclients as c', 'su.userid', '=', 'c.id')
                ->select('su.*', 'c.firstname', 'c.lastname', 'c.email', 'c.companyname')
                ->orderBy('su.userid', 'desc')
                ->get();
            $users = self::normalizeRecords($rows);
            $result['users'] = $users;
            $result['userCount'] = is_countable($users) ? count($users) : 0;
            $ids = [];
            foreach ($users as $user) {
                $uid = (int) ($user->userid ?? ($user['userid'] ?? 0));
                if ($uid > 0) {
                    $ids[$uid] = $uid;
                }
            }
            $result['ids'] = array_values($ids);
        } catch (\Throwable $e) {
            $result['users'] = [];
            $result['userCount'] = 0;
            $result['ids'] = [];
        }

        if ($keyword !== '') {
            try {
                $query = Capsule::table('tblclients')
                    ->select('id', 'firstname', 'lastname', 'email', 'companyname', 'status')
                    ->orderBy('id', 'desc');
                if (ctype_digit($keyword)) {
                    $query->where('id', intval($keyword));
                } else {
                    $keywordLike = '%' . $keyword . '%';
                    $query->where(function ($q) use ($keyword, $keywordLike) {
                        $q->where('email', $keyword)
                            ->orWhere('email', 'like', $keywordLike)
                            ->orWhere('firstname', 'like', $keywordLike)
                            ->orWhere('lastname', 'like', $keywordLike)
                            ->orWhere('companyname', 'like', $keywordLike);
                    });
                }
                $results = self::normalizeRecords($query->limit(50)->get());
                $result['search']['results'] = $results;
                $result['search']['count'] = is_countable($results) ? count($results) : 0;
            } catch (\Throwable $e) {
                $result['search']['results'] = [];
                $result['search']['count'] = 0;
            }
        }

        return $result;
    }

    private static function buildQuotas(array $moduleSettings): array
    {
        $quotaPage = max(1, (int) ($_GET['quota_page'] ?? 1));
        $quotaPerPage = 20;
        $quotaList = [
            'items' => [],
            'page' => $quotaPage,
            'perPage' => $quotaPerPage,
            'total' => 0,
            'totalPages' => 1,
        ];

        try {
            $base = Capsule::table('mod_cloudflare_subdomain_quotas as q')
                ->leftJoin('tblclients as c', 'q.userid', '=', 'c.id');
            $total = (clone $base)->count();
            $quotaList['total'] = $total;
            $quotaList['totalPages'] = max(1, (int) ceil($total / $quotaPerPage));
            if ($quotaPage > $quotaList['totalPages']) {
                $quotaPage = $quotaList['totalPages'];
                $quotaList['page'] = $quotaPage;
            }
            $offset = ($quotaPage - 1) * $quotaPerPage;
            $quotaList['items'] = self::normalizeRecords(
                $base->select('q.*', 'c.firstname', 'c.lastname', 'c.email', 'c.status')
                    ->orderBy('q.userid', 'desc')
                    ->offset($offset)
                    ->limit($quotaPerPage)
                    ->get()
            );
        } catch (\Throwable $e) {
            $quotaList['items'] = [];
        }

        $keyword = trim((string) ($_GET['quota_search'] ?? ''));
        $search = [
            'keyword' => $keyword,
            'result' => null,
            'error' => '',
        ];
        $prefill = [
            'userId' => 0,
            'email' => '',
            'max' => '',
            'inviteLimit' => '',
            'used' => null,
        ];

        if ($keyword !== '') {
            try {
                $userQuery = Capsule::table('tblclients')
                    ->select('id', 'firstname', 'lastname', 'email', 'status');
                if (ctype_digit($keyword)) {
                    $userQuery->where('id', intval($keyword));
                } else {
                    $userQuery->where(function ($q) use ($keyword) {
                        $q->where('email', $keyword)
                            ->orWhere('email', 'like', '%' . $keyword . '%');
                    });
                }
                $userMatch = $userQuery->orderBy('id', 'desc')->first();
                if ($userMatch) {
                    $userId = (int) $userMatch->id;
                    $quotaRow = Capsule::table('mod_cloudflare_subdomain_quotas')->where('userid', $userId)->first();
                    if (!$quotaRow) {
                        $defaultMax = max(0, (int) ($moduleSettings['max_subdomain_per_user'] ?? 0));
                        $defaultInvite = max(0, (int) ($moduleSettings['invite_bonus_limit_global'] ?? 5));
                        $defaultUsed = 0;
                        try {
                            $defaultUsed = Capsule::table('mod_cloudflare_subdomain')->where('userid', $userId)->count();
                        } catch (\Throwable $e) {
                        }
                        $quotaRow = (object) [
                            'max_count' => $defaultMax,
                            'used_count' => $defaultUsed,
                            'invite_bonus_limit' => $defaultInvite,
                        ];
                    }
                    $search['result'] = [
                        'user' => $userMatch,
                        'quota' => $quotaRow,
                    ];
                    $prefill = [
                        'userId' => $userId,
                        'email' => $userMatch->email ?? '',
                        'max' => (string) max(0, (int) ($quotaRow->max_count ?? 0)),
                        'inviteLimit' => (string) max(0, (int) ($quotaRow->invite_bonus_limit ?? 0)),
                        'used' => max(0, (int) ($quotaRow->used_count ?? 0)),
                    ];
                } else {
                    $search['error'] = '未找到对应用户';
                }
            } catch (\Throwable $e) {
                $search['error'] = '搜索失败: ' . $e->getMessage();
            }
        }

        return [
            'list' => $quotaList,
            'search' => $search,
            'prefill' => $prefill,
            'redeem' => self::buildQuotaRedeem($moduleSettings),
        ];
    }

    private static function buildQuotaRedeem(array $moduleSettings): array
    {
        if (class_exists('CfQuotaRedeemService')) {
            CfQuotaRedeemService::ensureTables();
        } else {
            self::ensureQuotaRedeemTables();
        }

        $enabled = in_array(($moduleSettings['enable_quota_redeem'] ?? '0'), ['1','on','yes','true','enabled'], true);

        $codePage = max(1, (int) ($_GET['redeem_code_page'] ?? 1));
        $codesPerPage = 20;
        $codeSearch = trim((string) ($_GET['redeem_code_search'] ?? ''));
        $codesQuery = Capsule::table('mod_cloudflare_quota_codes');
        if ($codeSearch !== '') {
            $like = '%' . str_replace(['%', '_'], ['\\%', '\\_'], $codeSearch) . '%';
            $codesQuery->where(function ($q) use ($like, $codeSearch) {
                $q->where('code', 'like', $like)
                    ->orWhere('batch_tag', 'like', $like);
                if (ctype_digit($codeSearch)) {
                    $q->orWhere('id', intval($codeSearch));
                }
            });
        }
        $codesTotal = (clone $codesQuery)->count();
        $codesTotalPages = max(1, (int) ceil($codesTotal / $codesPerPage));
        if ($codePage > $codesTotalPages) {
            $codePage = $codesTotalPages;
        }
        $codeRows = self::normalizeRecords(
            $codesQuery->orderBy('id', 'desc')
                ->offset(($codePage - 1) * $codesPerPage)
                ->limit($codesPerPage)
                ->get()
        );

        $historyPage = max(1, (int) ($_GET['redeem_history_page'] ?? 1));
        $historyPerPage = 20;
        $historyUserFilter = trim((string) ($_GET['redeem_history_user'] ?? ''));
        $historyCodeFilter = trim((string) ($_GET['redeem_history_code'] ?? ''));
        $historyQuery = Capsule::table('mod_cloudflare_quota_redemptions as r')
            ->leftJoin('tblclients as c', 'r.userid', '=', 'c.id')
            ->leftJoin('mod_cloudflare_quota_codes as qc', 'qc.id', '=', 'r.code_id')
            ->select('r.*', 'c.email', 'c.firstname', 'c.lastname', 'qc.mode');

        if ($historyUserFilter !== '') {
            if (ctype_digit($historyUserFilter)) {
                $historyQuery->where('r.userid', intval($historyUserFilter));
            } else {
                $historyQuery->where('c.email', 'like', '%' . str_replace(['%', '_'], ['\\%', '\\_'], $historyUserFilter) . '%');
            }
        }
        if ($historyCodeFilter !== '') {
            $historyQuery->where('r.code', 'like', '%' . str_replace(['%', '_'], ['\\%', '\\_'], $historyCodeFilter) . '%');
        }

        $historyTotal = (clone $historyQuery)->count();
        $historyTotalPages = max(1, (int) ceil($historyTotal / $historyPerPage));
        if ($historyPage > $historyTotalPages) {
            $historyPage = $historyTotalPages;
        }
        $historyRows = self::normalizeRecords(
            $historyQuery->orderBy('r.id', 'desc')
                ->offset(($historyPage - 1) * $historyPerPage)
                ->limit($historyPerPage)
                ->get()
        );

        return [
            'enabled' => $enabled,
            'codes' => [
                'items' => $codeRows,
                'page' => $codePage,
                'perPage' => $codesPerPage,
                'total' => $codesTotal,
                'totalPages' => $codesTotalPages,
                'search' => $codeSearch,
            ],
            'history' => [
                'items' => $historyRows,
                'page' => $historyPage,
                'perPage' => $historyPerPage,
                'total' => $historyTotal,
                'totalPages' => $historyTotalPages,
                'filters' => [
                    'user' => $historyUserFilter,
                    'code' => $historyCodeFilter,
                ],
            ],
        ];
    }

    private static function buildDomainGifts(): array
    {
        $statusOptions = [
            '' => '全部状态',
            'pending' => '进行中',
            'accepted' => '已完成',
            'cancelled' => '已取消',
            'expired' => '已过期',
        ];

        $statusFilter = strtolower(trim((string) ($_GET['gift_status'] ?? '')));
        if (!array_key_exists($statusFilter, $statusOptions)) {
            $statusFilter = '';
        }
        $searchTerm = trim((string) ($_GET['gift_search'] ?? ''));
        $page = max(1, (int) ($_GET['gift_page'] ?? 1));
        $perPage = 30;
        $perPage = max(1, $perPage);

        $query = Capsule::table('mod_cloudflare_domain_gifts as g')
            ->leftJoin('mod_cloudflare_subdomain as s', 's.id', '=', 'g.subdomain_id')
            ->select('g.*', 's.gift_lock_id as subdomain_gift_lock_id', 's.userid as current_owner');

        if ($statusFilter !== '') {
            $query->where('g.status', $statusFilter);
        }
        if ($searchTerm !== '') {
            $giftSearchEscaped = str_replace(['%', '_'], ['\\%', '\\_'], $searchTerm);
            $likeValue = '%' . $giftSearchEscaped . '%';
            $query->where(function ($q) use ($likeValue, $searchTerm) {
                $q->where('g.full_domain', 'like', $likeValue)
                    ->orWhere('g.code', 'like', $likeValue);
                if (ctype_digit($searchTerm)) {
                    $uid = (int) $searchTerm;
                    $q->orWhere('g.from_userid', $uid)
                        ->orWhere('g.to_userid', $uid);
                }
            });
        }

        $total = 0;
        $totalPages = 1;
        $rows = [];
        try {
            $total = (clone $query)->count();
            $totalPages = max(1, (int) ceil($total / $perPage));
            if ($page > $totalPages) {
                $page = $totalPages;
            }
            $rows = $query->orderBy('g.id', 'desc')
                ->offset(($page - 1) * $perPage)
                ->limit($perPage)
                ->get();
            $rows = self::normalizeRecords($rows);
        } catch (\Throwable $e) {
            $rows = [];
        }

        $userMap = [];
        if (!empty($rows)) {
            $userIds = [];
            foreach ($rows as $row) {
                $fromId = (int) ($row->from_userid ?? 0);
                $toId = (int) ($row->to_userid ?? 0);
                if ($fromId > 0) {
                    $userIds[$fromId] = true;
                }
                if ($toId > 0) {
                    $userIds[$toId] = true;
                }
            }
            if (!empty($userIds)) {
                try {
                    $userRecords = Capsule::table('tblclients')
                        ->select('id', 'firstname', 'lastname', 'email')
                        ->whereIn('id', array_keys($userIds))
                        ->get();
                    foreach ($userRecords as $userRecord) {
                        $userMap[(int) $userRecord->id] = $userRecord;
                    }
                } catch (\Throwable $e) {
                    $userMap = [];
                }
            }
        }

        return [
            'statusOptions' => $statusOptions,
            'filters' => [
                'status' => $statusFilter,
                'search' => $searchTerm,
            ],
            'pagination' => [
                'page' => $page,
                'perPage' => $perPage,
                'total' => $total,
                'totalPages' => $totalPages,
            ],
            'rows' => $rows,
            'users' => $userMap,
        ];
    }

    private static function buildInviteInsights(array $moduleSettings): array
    {
        self::ensureInviteTables();

        $viewAllInviteStats = (($_GET['view_all_invite_stats'] ?? '') === '1');

        $inviteStats = [
            'items' => [],
            'page' => 1,
            'perPage' => 20,
            'total' => 0,
            'totalPages' => 1,
            'showAll' => $viewAllInviteStats,
        ];

        $baseInviteStatsQuery = Capsule::table('mod_cloudflare_invitation_claims as ic')
            ->leftJoin('tblclients as c', 'ic.inviter_userid', '=', 'c.id')
            ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as claims'), Capsule::raw('MAX(ic.created_at) as last_claim'), 'c.email as inviter_email')
            ->groupBy('ic.inviter_userid', 'c.email')
            ->orderBy('claims', 'desc');

        if ($viewAllInviteStats) {
            try {
                $records = (clone $baseInviteStatsQuery)->get();
                $inviteStats['items'] = self::normalizeRecords($records);
                $inviteStats['total'] = is_countable($inviteStats['items']) ? count($inviteStats['items']) : 0;
                $inviteStats['totalPages'] = 1;
                $inviteStats['page'] = 1;
            } catch (\Throwable $e) {
                $inviteStats['items'] = [];
            }
        } else {
            $invPage = max(1, (int) ($_GET['inv_page'] ?? 1));
            $invPerPage = 20;
            $invPerPage = max(1, $invPerPage);
            $invOffset = ($invPage - 1) * $invPerPage;

            try {
                $invTotal = Capsule::table('mod_cloudflare_invitation_claims')->distinct()->count('inviter_userid');
                $invTotalPages = max(1, (int) ceil($invTotal / $invPerPage));
                if ($invPage > $invTotalPages) {
                    $invPage = $invTotalPages;
                    $invOffset = ($invPage - 1) * $invPerPage;
                }
                $records = (clone $baseInviteStatsQuery)
                    ->offset($invOffset)
                    ->limit($invPerPage)
                    ->get();
                $inviteStats['items'] = self::normalizeRecords($records);
                $inviteStats['total'] = $invTotal;
                $inviteStats['page'] = $invPage;
                $inviteStats['totalPages'] = $invTotalPages;
                $inviteStats['perPage'] = $invPerPage;
            } catch (\Throwable $e) {
                $inviteStats['items'] = [];
            }
        }

        $top20 = [];
        try {
            $records = Capsule::table('mod_cloudflare_invitation_claims as ic')
                ->leftJoin('tblclients as c', 'ic.inviter_userid', '=', 'c.id')
                ->select('ic.inviter_userid', Capsule::raw('COUNT(*) as claims'), Capsule::raw('MAX(ic.created_at) as last_claim'), 'c.email')
                ->groupBy('ic.inviter_userid', 'c.email')
                ->orderBy('claims', 'desc')
                ->limit(20)
                ->get();
            $top20 = self::normalizeRecords($records);
        } catch (\Throwable $e) {
            $top20 = [];
        }

        $snapPage = isset($_GET['snap_page']) ? max(1, (int) $_GET['snap_page']) : 1;
        $snapPerPage = 20;
        $snapPerPage = max(1, $snapPerPage);
        $snapOffset = ($snapPage - 1) * $snapPerPage;
        $snapshots = [
            'items' => [],
            'page' => $snapPage,
            'perPage' => $snapPerPage,
            'total' => 0,
            'totalPages' => 1,
        ];
        try {
            $snapTotal = Capsule::table('mod_cloudflare_invite_leaderboard')->count();
            $snapshots['total'] = $snapTotal;
            $snapshots['totalPages'] = max(1, (int) ceil($snapTotal / $snapPerPage));
            if ($snapPage > $snapshots['totalPages']) {
                $snapPage = $snapshots['totalPages'];
                $snapOffset = ($snapPage - 1) * $snapPerPage;
            }
            $records = Capsule::table('mod_cloudflare_invite_leaderboard')
                ->orderBy('period_end', 'desc')
                ->offset($snapOffset)
                ->limit($snapPerPage)
                ->get();
            $snapshots['items'] = self::normalizeRecords($records);
            $snapshots['page'] = $snapPage;
        } catch (\Throwable $e) {
            $snapshots['items'] = [];
        }

        $inviteLeaderboardDays = max(1, (int) ($moduleSettings['invite_leaderboard_period_days'] ?? 7));
        $cycleStart = trim((string) ($moduleSettings['invite_cycle_start'] ?? ''));
        if ($cycleStart !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $cycleStart)) {
            $periodStart = $cycleStart;
            $periodEnd = date('Y-m-d', strtotime($periodStart . ' +' . ($inviteLeaderboardDays - 1) . ' days'));
        } else {
            $periodEnd = date('Y-m-d', strtotime('yesterday'));
            $periodStart = date('Y-m-d', strtotime($periodEnd . ' -' . ($inviteLeaderboardDays - 1) . ' days'));
        }

        $rewardList = [];
        try {
            $records = Capsule::table('mod_cloudflare_invite_rewards as r')
                ->leftJoin('tblclients as c', 'r.inviter_userid', '=', 'c.id')
                ->select('r.*', 'c.email')
                ->where('r.period_start', $periodStart)
                ->where('r.period_end', $periodEnd)
                ->orderBy('r.rank', 'asc')
                ->get();
            $rewardList = self::normalizeRecords($records);
        } catch (\Throwable $e) {
            $rewardList = [];
        }

        return [
            'stats' => $inviteStats,
            'top' => $top20,
            'history' => $snapshots,
            'rewards' => [
                'periodStart' => $periodStart,
                'periodEnd' => $periodEnd,
                'items' => $rewardList,
            ],
        ];
    }

    private static function ensureInviteTables(): void
    {
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_invitation_codes')) {
                Capsule::schema()->create('mod_cloudflare_invitation_codes', function ($table) {
                    $table->increments('id');
                    $table->integer('userid')->unsigned()->unique();
                    $table->string('code', 64)->unique();
                    $table->timestamps();
                    $table->index('userid');
                    $table->index('code');
                });
            }
            if (!Capsule::schema()->hasTable('mod_cloudflare_invitation_claims')) {
                Capsule::schema()->create('mod_cloudflare_invitation_claims', function ($table) {
                    $table->increments('id');
                    $table->integer('inviter_userid')->unsigned();
                    $table->integer('invitee_userid')->unsigned();
                    $table->string('code', 64);
                    $table->timestamps();
                    $table->index('inviter_userid');
                    $table->index('invitee_userid');
                    $table->index('code');
                });
            }
            if (!Capsule::schema()->hasTable('mod_cloudflare_invite_leaderboard')) {
                Capsule::schema()->create('mod_cloudflare_invite_leaderboard', function ($table) {
                    $table->increments('id');
                    $table->date('period_start');
                    $table->date('period_end');
                    $table->text('top_json');
                    $table->timestamps();
                    $table->unique(['period_start', 'period_end']);
                    $table->index('period_start');
                });
            }
            if (!Capsule::schema()->hasTable('mod_cloudflare_invite_rewards')) {
                Capsule::schema()->create('mod_cloudflare_invite_rewards', function ($table) {
                    $table->increments('id');
                    $table->date('period_start');
                    $table->date('period_end');
                    $table->integer('inviter_userid')->unsigned();
                    $table->string('code', 64);
                    $table->integer('rank')->unsigned();
                    $table->integer('count')->unsigned();
                    $table->string('status', 20)->default('eligible');
                    $table->dateTime('requested_at')->nullable();
                    $table->dateTime('claimed_at')->nullable();
                    $table->text('notes')->nullable();
                    $table->timestamps();
                    $table->index(['period_start', 'period_end']);
                    $table->index(['inviter_userid', 'period_start']);
                    $table->index('status');
                });
            } else {
                if (!Capsule::schema()->hasColumn('mod_cloudflare_invite_rewards', 'requested_at')) {
                    Capsule::schema()->table('mod_cloudflare_invite_rewards', function ($table) {
                        $table->dateTime('requested_at')->nullable()->after('status');
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_invite_rewards', 'claimed_at')) {
                    Capsule::schema()->table('mod_cloudflare_invite_rewards', function ($table) {
                        $table->dateTime('claimed_at')->nullable()->after('requested_at');
                    });
                }
                if (!Capsule::schema()->hasColumn('mod_cloudflare_invite_rewards', 'notes')) {
                    Capsule::schema()->table('mod_cloudflare_invite_rewards', function ($table) {
                        $table->text('notes')->nullable()->after('claimed_at');
                    });
                }
            }
        } catch (\Throwable $e) {
            // ignore
        }
    }

    private static function ensureQuotaRedeemTables(): void
    {
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_quota_codes')) {
                Capsule::schema()->create('mod_cloudflare_quota_codes', function ($table) {
                    $table->increments('id');
                    $table->string('code', 191)->unique();
                    $table->integer('grant_amount')->unsigned()->default(1);
                    $table->string('mode', 20)->default('single_use');
                    $table->integer('max_total_uses')->unsigned()->default(1);
                    $table->integer('per_user_limit')->unsigned()->default(1);
                    $table->integer('redeemed_total')->unsigned()->default(0);
                    $table->dateTime('valid_from')->nullable();
                    $table->dateTime('valid_to')->nullable();
                    $table->string('status', 20)->default('active');
                    $table->string('batch_tag', 64)->nullable();
                    $table->integer('created_by_admin_id')->unsigned()->nullable();
                    $table->text('notes')->nullable();
                    $table->timestamps();
                    $table->index('status');
                    $table->index('valid_to');
                    $table->index('batch_tag');
                });
            }
            if (!Capsule::schema()->hasTable('mod_cloudflare_quota_redemptions')) {
                Capsule::schema()->create('mod_cloudflare_quota_redemptions', function ($table) {
                    $table->increments('id');
                    $table->integer('code_id')->unsigned();
                    $table->string('code', 191);
                    $table->integer('userid')->unsigned();
                    $table->integer('grant_amount')->unsigned()->default(1);
                    $table->string('status', 20)->default('success');
                    $table->text('message')->nullable();
                    $table->bigInteger('before_quota')->default(0);
                    $table->bigInteger('after_quota')->default(0);
                    $table->string('client_ip', 45)->nullable();
                    $table->timestamps();
                    $table->index('code_id');
                    $table->index('userid');
                    $table->index('code');
                    $table->index('status');
                    $table->index('created_at');
                });
            }
        } catch (\Throwable $e) {
            // ignore schema errors
        }
    }

    private static function buildBans(): array
    {
        self::ensureUserBansTableExists();

        $page = isset($_GET['ban_page']) ? max(1, (int) $_GET['ban_page']) : 1;
        $perPage = 10;
        $total = 0;
        $totalPages = 1;
        $items = [];

        try {
            $baseQuery = Capsule::table('mod_cloudflare_user_bans as b')
                ->leftJoin('tblclients as c', 'b.userid', '=', 'c.id')
                ->select('b.*', 'c.firstname', 'c.lastname', 'c.email')
                ->where('b.status', 'banned');

            $total = (clone $baseQuery)->count();
            $totalPages = max(1, (int) ceil($total / $perPage));
            if ($page > $totalPages) {
                $page = $totalPages;
            }
            $offset = ($page - 1) * $perPage;

            $records = (clone $baseQuery)
                ->orderBy('b.banned_at', 'desc')
                ->offset($offset)
                ->limit($perPage)
                ->get();
            $items = self::normalizeRecords($records);
        } catch (\Throwable $e) {
            $items = [];
        }

        return [
            'items' => $items,
            'pagination' => [
                'page' => $page,
                'perPage' => $perPage,
                'total' => $total,
                'totalPages' => $totalPages,
            ],
        ];
    }

    private static function buildDnsUnlockLogs(): array
    {
        $search = trim((string) ($_GET['dns_unlock_search'] ?? ''));
        $page = max(1, (int) ($_GET['dns_unlock_page'] ?? 1));
        try {
            $data = CfDnsUnlockService::fetchAdminLogs($search, $page, 20);
            return $data;
        } catch (\Throwable $e) {
            return [
                'items' => [],
                'search' => $search,
                'pagination' => [
                    'page' => $page,
                    'perPage' => 20,
                    'total' => 0,
                    'totalPages' => 1,
                ],
            ];
        }
    }

    private static function buildRuntimeTools(): array
    {
        $rootdomains = [];
        try {
            $records = Capsule::table('mod_cloudflare_rootdomains')
                ->orderBy('domain', 'asc')
                ->get();
            $rootdomains = self::normalizeRecords($records);
        } catch (\Throwable $e) {
            $rootdomains = [];
        }

        $orphanCursors = ['default' => 0, 'list' => []];
        if (class_exists('CfAdminActionService') && method_exists('CfAdminActionService', 'getOrphanCursorSummaryForView')) {
            try {
                $orphanCursors = CfAdminActionService::getOrphanCursorSummaryForView();
            } catch (\Throwable $e) {
                $orphanCursors = ['default' => 0, 'list' => []];
            }
        }

        return [
            'rootdomains' => $rootdomains,
            'orphanCursors' => $orphanCursors,
        ];
    }

    private static function buildLogs(): array
    {
        $showAll = (($_GET['view_all_logs'] ?? '') === '1');
        $logsUserFilter = trim((string) ($_GET['logs_user'] ?? ''));
        $logsPage = isset($_GET['logs_page']) ? max(1, (int) $_GET['logs_page']) : 1;
        $logsPerPage = 20;
        $logsPerPage = max(1, $logsPerPage);
        $logsOffset = ($logsPage - 1) * $logsPerPage;
        $logsTotal = 0;
        $logsTotalPages = 1;
        $logs = [];

        try {
            if ($logsUserFilter !== '') {
                $query = Capsule::table('mod_cloudflare_logs as l')
                    ->select('l.*')
                    ->orderBy('l.id', 'desc');
                if (ctype_digit($logsUserFilter)) {
                    $query->where('l.userid', (int) $logsUserFilter);
                } else {
                    $query->leftJoin('tblclients as c', 'l.userid', '=', 'c.id')
                        ->where('c.email', 'like', '%' . $logsUserFilter . '%');
                }
                $logsTotal = $query->count();
                $logsTotalPages = max(1, (int) ceil($logsTotal / $logsPerPage));
                if ($logsPage > $logsTotalPages) {
                    $logsPage = $logsTotalPages;
                    $logsOffset = ($logsPage - 1) * $logsPerPage;
                }
                $logs = $query->offset($logsOffset)->limit($logsPerPage)->get();
            } else {
                if ($showAll) {
                    $logs = Capsule::table('mod_cloudflare_logs')
                        ->orderBy('id', 'desc')
                        ->get();
                    $logsTotal = is_array($logs) ? count($logs) : ($logs instanceof \Illuminate\Support\Collection ? $logs->count() : 0);
                    $logsTotalPages = 1;
                    $logsPage = 1;
                } else {
                    $logsTotal = Capsule::table('mod_cloudflare_logs')->count();
                    $logsTotalPages = max(1, (int) ceil($logsTotal / $logsPerPage));
                    if ($logsPage > $logsTotalPages) {
                        $logsPage = $logsTotalPages;
                        $logsOffset = ($logsPage - 1) * $logsPerPage;
                    }
                    $logs = Capsule::table('mod_cloudflare_logs')
                        ->orderBy('id', 'desc')
                        ->offset($logsOffset)
                        ->limit($logsPerPage)
                        ->get();
                }
            }
            $logs = self::normalizeRecords($logs);
        } catch (\Throwable $e) {
            $logs = [];
            $logsTotal = 0;
            $logsTotalPages = 1;
            $logsPage = 1;
        }

        return [
            'entries' => $logs,
            'userFilter' => $logsUserFilter,
            'showAll' => $showAll,
            'pagination' => [
                'page' => $logsPage,
                'perPage' => $logsPerPage,
                'total' => $logsTotal,
                'totalPages' => $logsTotalPages,
            ],
        ];
    }

    private static function ensureUserBansTableExists(): void
    {
        try {
            if (Capsule::schema()->hasTable('mod_cloudflare_user_bans')) {
                return;
            }
            Capsule::schema()->create('mod_cloudflare_user_bans', function ($table) {
                $table->increments('id');
                $table->integer('userid')->unsigned();
                $table->text('ban_reason');
                $table->string('banned_by', 100);
                $table->dateTime('banned_at');
                $table->dateTime('unbanned_at')->nullable();
                $table->string('status', 20)->default('banned');
                $table->timestamps();
                $table->index('userid');
                $table->index('status');
                $table->index('banned_at');
            });
        } catch (\Throwable $e) {
            // ignore
        }
    }

    public static function flushStatsCache(): void
    {
        if (session_status() === PHP_SESSION_DISABLED) {
            return;
        }
        self::ensureStatsCacheSession();
        if (isset($_SESSION[self::STATS_CACHE_SESSION_KEY])) {
            unset($_SESSION[self::STATS_CACHE_SESSION_KEY]);
        }
    }

    private static function resolveCachedStats(): array
    {
        $cached = self::getCachedStats();
        if ($cached !== null) {
            return $cached;
        }
        $fresh = self::computeHeavyStats();
        self::storeCachedStats($fresh);
        return $fresh;
    }

    private static function computeHeavyStats(): array
    {
        $data = [
            'totalSubdomains' => 0,
            'activeSubdomains' => 0,
            'registeredUsers' => 0,
            'subdomainsCreated' => 0,
            'dnsOperations' => 0,
            'registrationTrend' => [],
            'popularRootdomains' => [],
            'dnsRecordTypes' => [],
            'usagePatterns' => [],
        ];

        try {
            $counts = Capsule::table('mod_cloudflare_subdomain')
                ->selectRaw('COUNT(*) as total_count, SUM(CASE WHEN status = "active" THEN 1 ELSE 0 END) as active_count, COUNT(DISTINCT userid) as user_count')
                ->first();
            if ($counts) {
                $data['totalSubdomains'] = (int) ($counts->total_count ?? 0);
                $data['activeSubdomains'] = (int) ($counts->active_count ?? 0);
                $data['registeredUsers'] = (int) ($counts->user_count ?? 0);
            }
        } catch (\Throwable $e) {
        }

        try {
            if (Capsule::schema()->hasTable('mod_cloudflare_user_stats')) {
                $summary = Capsule::table('mod_cloudflare_user_stats')
                    ->selectRaw('SUM(subdomains_created) as total_subdomains, SUM(dns_records_created + dns_records_updated + dns_records_deleted) as dns_ops')
                    ->first();
                if ($summary) {
                    $data['subdomainsCreated'] = (int) ($summary->total_subdomains ?? 0);
                    $data['dnsOperations'] = (int) ($summary->dns_ops ?? 0);
                }
            }
        } catch (\Throwable $e) {
        }

        try {
            $trend = Capsule::table('mod_cloudflare_subdomain')
                ->selectRaw('DATE(created_at) as date, COUNT(*) as count')
                ->where('created_at', '>=', date('Y-m-d', strtotime('-30 days')))
                ->groupBy('date')
                ->orderBy('date')
                ->get();
            $data['registrationTrend'] = self::normalizeRecords($trend);
        } catch (\Throwable $e) {
            $data['registrationTrend'] = [];
        }

        try {
            $popular = Capsule::table('mod_cloudflare_subdomain')
                ->selectRaw('rootdomain, COUNT(*) as count')
                ->groupBy('rootdomain')
                ->orderBy('count', 'desc')
                ->limit(10)
                ->get();
            $data['popularRootdomains'] = self::normalizeRecords($popular);
        } catch (\Throwable $e) {
            $data['popularRootdomains'] = [];
        }

        try {
            $types = Capsule::table('mod_cloudflare_dns_records')
                ->selectRaw('type, COUNT(*) as count')
                ->groupBy('type')
                ->orderBy('count', 'desc')
                ->get();
            $data['dnsRecordTypes'] = self::normalizeRecords($types);
        } catch (\Throwable $e) {
            $data['dnsRecordTypes'] = [];
        }

        try {
            if (Capsule::schema()->hasTable('mod_cloudflare_user_stats')) {
                $patterns = Capsule::table('mod_cloudflare_user_stats')
                    ->selectRaw('CASE WHEN subdomains_created = 0 THEN "未使用" WHEN subdomains_created BETWEEN 1 AND 3 THEN "轻度使用" WHEN subdomains_created BETWEEN 4 AND 10 THEN "中度使用" ELSE "重度使用" END as usage_level, COUNT(*) as user_count')
                    ->groupBy('usage_level')
                    ->orderBy('user_count', 'desc')
                    ->get();
                $data['usagePatterns'] = self::normalizeRecords($patterns);
            } else {
                $data['usagePatterns'] = [];
            }
        } catch (\Throwable $e) {
            $data['usagePatterns'] = [];
        }

        return $data;
    }

    private static function getCachedStats(): ?array
    {
        if (session_status() === PHP_SESSION_DISABLED) {
            return null;
        }
        self::ensureStatsCacheSession();
        $cache = $_SESSION[self::STATS_CACHE_SESSION_KEY] ?? null;
        if (!is_array($cache)) {
            return null;
        }
        $generatedAt = (int) ($cache['generated_at'] ?? 0);
        if ($generatedAt <= 0 || ($generatedAt + self::STATS_CACHE_TTL_SECONDS) < time()) {
            return null;
        }
        $data = $cache['data'] ?? null;
        return is_array($data) ? $data : null;
    }

    private static function storeCachedStats(array $data): void
    {
        if (session_status() === PHP_SESSION_DISABLED) {
            return;
        }
        self::ensureStatsCacheSession();
        $_SESSION[self::STATS_CACHE_SESSION_KEY] = [
            'generated_at' => time(),
            'data' => $data,
        ];
    }

    private static function ensureStatsCacheSession(): void
    {
        if (session_status() === PHP_SESSION_DISABLED || session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        try {
            @session_start();
        } catch (\Throwable $e) {
        }
    }

    private static function normalizeRecords($records): array
    {
        if ($records instanceof \Illuminate\Support\Collection) {
            return $records->all();
        }
        if ($records === null) {
            return [];
        }
        if (is_array($records)) {
            return $records;
        }
        return [$records];
    }

    private static function initializeBlocks(): array
    {
        $blocks = [];
        foreach (self::BLOCK_KEYS as $key) {
            $blocks[$key] = [];
        }
        return $blocks;
    }

    private static function loadModuleSettings(): array
    {
        if (function_exists('cf_get_module_settings_cached')) {
            $settings = cf_get_module_settings_cached();
            if (is_array($settings) && !empty($settings)) {
                return $settings;
            }
        }

        $module = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
        try {
            $rows = Capsule::table('tbladdonmodules')->where('module', $module)->get();
            $settings = [];
            foreach ($rows as $row) {
                $settings[$row->setting] = $row->value;
            }
            if (!empty($settings)) {
                return $settings;
            }
        } catch (\Throwable $e) {
        }

        return [];
    }
}
