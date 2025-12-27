<?php

use WHMCS\Database\Capsule;

if (!function_exists('cfmod_get_rootdomain_limits_map')) {
    function cfmod_get_rootdomain_limits_map(): array {
        if (isset($GLOBALS['cfmod_rootdomain_limits_cache']) && is_array($GLOBALS['cfmod_rootdomain_limits_cache'])) {
            return $GLOBALS['cfmod_rootdomain_limits_cache'];
        }

        $map = [];
        try {
            if (!Capsule::schema()->hasTable('mod_cloudflare_rootdomains')) {
                $GLOBALS['cfmod_rootdomain_limits_cache'] = $map;
                return $map;
            }

            $rows = Capsule::table('mod_cloudflare_rootdomains')->select('domain', 'per_user_limit')->get();
            foreach ($rows as $row) {
                $domain = strtolower(trim($row->domain ?? ''));
                if ($domain === '') {
                    continue;
                }
                $limit = max(0, (int) ($row->per_user_limit ?? 0));
                $map[$domain] = $limit;
            }
        } catch (\Throwable $e) {
            // ignore table/connection errors, return current map (possibly empty)
        }

        $GLOBALS['cfmod_rootdomain_limits_cache'] = $map;
        return $map;
    }
}

if (!function_exists('cfmod_clear_rootdomain_limits_cache')) {
    function cfmod_clear_rootdomain_limits_cache(): void {
        unset($GLOBALS['cfmod_rootdomain_limits_cache']);
    }
}

if (!function_exists('cfmod_get_rootdomain_limit')) {
    function cfmod_get_rootdomain_limit(string $rootdomain): int {
        $rootdomain = strtolower(trim($rootdomain));
        if ($rootdomain === '') {
            return 0;
        }
        $map = cfmod_get_rootdomain_limits_map();
        return isset($map[$rootdomain]) ? max(0, (int) $map[$rootdomain]) : 0;
    }
}

if (!function_exists('cfmod_format_rootdomain_limit_message')) {
    function cfmod_format_rootdomain_limit_message(string $rootdomain, int $limit): string {
        $rootdomain = trim($rootdomain);
        $limit = max(0, (int) $limit);
        if ($rootdomain === '' || $limit <= 0) {
            return '';
        }
        return sprintf('%s 每个账号最多注册 %d 个，您已达到上限', $rootdomain, $limit);
    }
}

if (!function_exists('cfmod_check_rootdomain_user_limit')) {
    function cfmod_check_rootdomain_user_limit(int $userid, string $rootdomain, int $expectedNewDomains = 1): array {
        return CfSubdomainService::instance()->checkRootdomainUserLimit($userid, $rootdomain, $expectedNewDomains);
    }
}
