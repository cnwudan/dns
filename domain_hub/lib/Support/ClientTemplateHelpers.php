<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

if (!function_exists('cfmod_client_acquire_provider_for_subdomain')) {
    function cfmod_client_acquire_provider_for_subdomain($record, array $moduleSettings, string $errorMessage = '当前子域绑定的 DNS 供应商不可用，请联系管理员'): array
    {
        if (!$record) {
            return [null, $errorMessage, null];
        }
        $context = cfmod_make_provider_client_for_subdomain($record, $moduleSettings);
        if (!$context || empty($context['client'])) {
            return [null, $errorMessage, null];
        }
        return [$context['client'], null, $context];
    }
}

if (!function_exists('cfmod_has_invalid_edge_character')) {
    function cfmod_has_invalid_edge_character(string $value): bool
    {
        $value = trim($value);
        if ($value === '') {
            return false;
        }
        $first = $value[0];
        $last = $value[strlen($value) - 1];
        return ($first === '.' || $first === '-') || ($last === '.' || $last === '-');
    }
}

if (!function_exists('cfmod_dns_name_has_invalid_edges')) {
    function cfmod_dns_name_has_invalid_edges(string $name): bool
    {
        $name = trim($name);
        if ($name === '' || $name === '@') {
            return false;
        }
        if (cfmod_has_invalid_edge_character($name) || strpos($name, '..') !== false) {
            return true;
        }
        $labels = explode('.', $name);
        foreach ($labels as $label) {
            if ($label === '' || cfmod_has_invalid_edge_character($label)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('cfmod_is_valid_hostname')) {
    function cfmod_is_valid_hostname(string $host): bool
    {
        $host = trim($host);
        if ($host === '') {
            return false;
        }
        if (strpos($host, '..') !== false) {
            return false;
        }
        if ($host[0] === '-' || substr($host, -1) === '-') {
            return false;
        }
        return (bool) preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$/', $host);
    }
}

if (!function_exists('cfmod_client_mask_leaderboard_email')) {
    function cfmod_client_mask_leaderboard_email(?string $email): string
    {
        $email = trim((string) $email);
        if ($email === '') {
            return '***';
        }
        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            return '***';
        }
        $local = $parts[0];
        $domain = $parts[1];
        $localMasked = strlen($local) > 2
            ? substr($local, 0, 2) . str_repeat('*', max(0, strlen($local) - 2))
            : str_repeat('*', strlen($local));
        $domainMasked = preg_replace('/(^.).*(\..{1,2})$/', '$1***$2', $domain);
        if ($domainMasked === null || $domainMasked === '') {
            $domainMasked = '***';
        }
        return $localMasked . '@' . $domainMasked;
    }
}

if (!function_exists('cfmod_client_fetch_invite_user_meta')) {
    function cfmod_client_fetch_invite_user_meta(array $userIds): array
    {
        $userIds = array_values(array_unique(array_filter(array_map(static function ($id) {
            return is_numeric($id) ? (int) $id : 0;
        }, $userIds), static function ($id) {
            return $id > 0;
        })));
        $emailMap = [];
        $codeMap = [];
        if (empty($userIds)) {
            return [$emailMap, $codeMap];
        }
        try {
            $users = Capsule::table('tblclients')->select('id', 'email')->whereIn('id', $userIds)->get();
            foreach ($users as $user) {
                $emailMap[(int) ($user->id ?? 0)] = $user->email ?? '';
            }
        } catch (Exception $e) {
        }
        try {
            $codes = Capsule::table('mod_cloudflare_invitation_codes')->select('userid', 'code')->whereIn('userid', $userIds)->get();
            foreach ($codes as $row) {
                $codeMap[(int) ($row->userid ?? 0)] = $row->code ?? '';
            }
        } catch (Exception $e) {
        }
        return [$emailMap, $codeMap];
    }
}

if (!function_exists('cfmod_client_load_subdomains_paginated')) {
    function cfmod_client_load_subdomains_paginated(int $userid, int $page, int $pageSize, string $searchTerm = ''): array
    {
        return \CfSubdomainService::instance()->loadSubdomainsPaginated($userid, $page, $pageSize, $searchTerm);
    }
}
