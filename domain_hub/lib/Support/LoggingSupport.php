<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfLoggingSupport
{
    public static function log(string $action, $details = '', $userid = null, $subdomainId = null): void
    {
        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? null;
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;

            Capsule::table('mod_cloudflare_logs')->insert([
                'userid' => $userid,
                'subdomain_id' => $subdomainId,
                'action' => $action,
                'details' => is_array($details) ? json_encode($details, JSON_UNESCAPED_UNICODE) : $details,
                'ip' => $ip,
                'user_agent' => $userAgent,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ]);

            if ($userid) {
                $stats = Capsule::table('mod_cloudflare_user_stats')->where('userid', $userid)->first();
                if (!$stats) {
                    Capsule::table('mod_cloudflare_user_stats')->insert([
                        'userid' => $userid,
                        'subdomains_created' => 0,
                        'dns_records_created' => 0,
                        'dns_records_updated' => 0,
                        'dns_records_deleted' => 0,
                        'last_activity' => date('Y-m-d H:i:s'),
                        'created_at' => date('Y-m-d H:i:s'),
                        'updated_at' => date('Y-m-d H:i:s')
                    ]);
                } else {
                    $update = ['last_activity' => date('Y-m-d H:i:s'), 'updated_at' => date('Y-m-d H:i:s')];
                    switch ($action) {
                        case 'client_register_subdomain':
                            $update['subdomains_created'] = ($stats->subdomains_created ?? 0) + 1;
                            break;
                        case 'client_create_dns':
                            $update['dns_records_created'] = ($stats->dns_records_created ?? 0) + 1;
                            break;
                        case 'client_update_dns':
                            $update['dns_records_updated'] = ($stats->dns_records_updated ?? 0) + 1;
                            break;
                        case 'client_delete_dns_record':
                            $update['dns_records_deleted'] = ($stats->dns_records_deleted ?? 0) + 1;
                            break;
                    }
                    Capsule::table('mod_cloudflare_user_stats')->where('userid', $userid)->update($update);
                }
            }
        } catch (\Throwable $e) {
            // Silently ignore logging errors
        }
    }
}

if (!function_exists('cloudflare_subdomain_log')) {
    function cloudflare_subdomain_log($action, $details = '', $userid = null, $subdomain_id = null): void
    {
        CfLoggingSupport::log((string) $action, $details, $userid, $subdomain_id);
    }
}
