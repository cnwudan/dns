<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

require_once __DIR__ . '/../SecurityHelpers.php';

class CfLoggingService
{
    private static ?self $instance = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function reportException(string $context, \Throwable $exception): void
    {
        $details = [
            'context' => $context,
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
        ];
        $trace = $exception->getTraceAsString();
        if ($trace !== '') {
            $details['trace'] = substr($trace, 0, 2000);
        }

        $this->insertGeneralLog('job_error', $details, null, null);
    }

    public function logJobEvent(string $action, array $details = [], ?int $userId = null, ?int $subdomainId = null): void
    {
        $this->insertGeneralLog($action, $details, $userId, $subdomainId);
    }

    public function logApiRequest($keyRow, string $endpoint, string $method, $request, $response, int $code, float $startedAt): void
    {
        $requestPayload = cfmod_sanitize_log_payload($request);
        $responsePayload = cfmod_sanitize_log_payload($response);
        $requestData = is_string($requestPayload) ? $requestPayload : json_encode($requestPayload, JSON_UNESCAPED_UNICODE);
        $responseData = is_string($responsePayload) ? $responsePayload : json_encode($responsePayload, JSON_UNESCAPED_UNICODE);
        if ($requestData === false) {
            $requestData = '{}';
        }
        if ($responseData === false) {
            $responseData = '{}';
        }

        $now = date('Y-m-d H:i:s');

        try {
            Capsule::table('mod_cloudflare_api_logs')->insert([
                'api_key_id' => $keyRow->id,
                'userid' => $keyRow->userid,
                'endpoint' => substr($endpoint, 0, 100),
                'method' => $method,
                'request_data' => $requestData,
                'response_data' => $responseData,
                'response_code' => $code,
                'ip' => api_client_ip(),
                'user_agent' => ($_SERVER['HTTP_USER_AGENT'] ?? ''),
                'execution_time' => round(microtime(true) - $startedAt, 3),
                'created_at' => $now,
                'updated_at' => $now,
            ]);

            Capsule::table('mod_cloudflare_api_keys')->where('id', $keyRow->id)->update([
                'request_count' => intval($keyRow->request_count) + 1,
                'last_used_at' => $now,
                'updated_at' => $now,
            ]);
        } catch (\Throwable $e) {
            // ignore log failures
        }
    }

    private function insertGeneralLog(string $action, array $details, ?int $userId, ?int $subdomainId): void
    {
        try {
            Capsule::table('mod_cloudflare_logs')->insert([
                'userid' => $userId,
                'subdomain_id' => $subdomainId,
                'action' => $action,
                'details' => json_encode($details, JSON_UNESCAPED_UNICODE),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
        } catch (\Throwable $e) {
            // swallow logging failures
        }
    }
}

if (!function_exists('cfmod_report_exception')) {
    function cfmod_report_exception(string $context, \Throwable $exception): void
    {
        CfLoggingService::instance()->reportException($context, $exception);
    }
}

if (!function_exists('cfmod_log_job')) {
    function cfmod_log_job(string $action, array $details = [], ?int $userId = null, ?int $subdomainId = null): void
    {
        CfLoggingService::instance()->logJobEvent($action, $details, $userId, $subdomainId);
    }
}

if (!function_exists('cfmod_log_api_request')) {
    function cfmod_log_api_request($keyRow, string $endpoint, string $method, $request, $response, int $code, float $startedAt): void
    {
        CfLoggingService::instance()->logApiRequest($keyRow, $endpoint, $method, $request, $response, $code, $startedAt);
    }
}
