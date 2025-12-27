<?php

declare(strict_types=1);

use InvalidArgumentException;
use RuntimeException;
use WHMCS\Database\Capsule;

class CfAsyncDnsJobService
{
    public static function enqueue(int $userId, string $action, array $postData, array $options = []): int
    {
        if ($userId <= 0) {
            throw new InvalidArgumentException('Invalid user id for async DNS job');
        }
        if ($action === '') {
            throw new InvalidArgumentException('Missing DNS action for async job');
        }

        $payload = [
            'user_id' => $userId,
            'action' => $action,
            'post' => $postData,
            'request_ip' => $_SERVER['REMOTE_ADDR'] ?? null,
            'meta' => [
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'queued_at' => date('c'),
            ],
        ];
        if (!empty($options)) {
            $payload['options'] = $options;
        }

        $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE);
        if ($payloadJson === false) {
            throw new RuntimeException('Failed to encode async DNS payload');
        }

        $now = date('Y-m-d H:i:s');
        return Capsule::table('mod_cloudflare_jobs')->insertGetId([
            'type' => 'client_dns_operation',
            'payload_json' => $payloadJson,
            'priority' => 6,
            'status' => 'pending',
            'attempts' => 0,
            'next_run_at' => null,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }
}
