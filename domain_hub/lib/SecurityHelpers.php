<?php

use WHMCS\Utility\SafeStorage;

if (!function_exists('cfmod_get_safe_storage')) {
    function cfmod_get_safe_storage(): ?SafeStorage
    {
        static $instance = null;
        if ($instance === false) {
            return null;
        }
        if ($instance === null) {
            try {
                $instance = new SafeStorage();
            } catch (\Throwable $e) {
                $instance = false;
                return null;
            }
        }
        return $instance ?: null;
    }
}

if (!function_exists('cfmod_encrypt_sensitive')) {
    function cfmod_encrypt_sensitive(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return $value;
        }
        $storage = cfmod_get_safe_storage();
        if ($storage) {
            try {
                return $storage->encrypt($value);
            } catch (\Throwable $e) {
                // fallback below
            }
        }
        return base64_encode($value);
    }
}

if (!function_exists('cfmod_decrypt_sensitive')) {
    function cfmod_decrypt_sensitive(?string $value): string
    {
        if ($value === null || $value === '') {
            return '';
        }
        $storage = cfmod_get_safe_storage();
        if ($storage) {
            try {
                return (string) $storage->decrypt($value);
            } catch (\Throwable $e) {
                // fallback below
            }
        }
        $decoded = base64_decode($value, true);
        if ($decoded !== false) {
            return $decoded;
        }
        return (string) $value;
    }
}

if (!function_exists('cfmod_redact_sensitive_string')) {
    function cfmod_redact_sensitive_string(string $value): string
    {
        if ($value === '') {
            return $value;
        }
        $patterns = [
            '/(api[_-]?secret\s*[:=]\s*)([^&"\s]+)/i',
            '/(api[_-]?key\s*[:=]\s*)([^&"\s]+)/i',
            '/(x-api-key\s*[:=]\s*)([^&"\s]+)/i',
            '/(x-api-secret\s*[:=]\s*)([^&"\s]+)/i',
            '/("authorization"\s*:\s*")[^"]+("?)/i',
            '/(authorization:\s*)([^\r\n]+)/i',
        ];
        foreach ($patterns as $pattern) {
            $value = preg_replace($pattern, '$1[redacted]$2', $value);
        }
        return $value;
    }
}

if (!function_exists('cfmod_redact_sensitive_value')) {
    function cfmod_redact_sensitive_value($value, ?string $key = null)
    {
        if (is_array($value)) {
            return cfmod_redact_sensitive_array($value);
        }
        if (is_object($value)) {
            $value = json_decode(json_encode($value), true);
            return cfmod_redact_sensitive_array(is_array($value) ? $value : []);
        }
        if ($key !== null) {
            $normalized = strtolower($key);
            $sensitiveKeys = [
                'api_key', 'api-secret', 'api_secret', 'apikey', 'apisecret',
                'x-api-key', 'x-api-secret', 'authorization', 'access_key',
                'access_secret', 'token', 'bearer', 'secret'
            ];
            if (in_array($normalized, $sensitiveKeys, true)) {
                return '[redacted]';
            }
        }
        if (is_string($value)) {
            return cfmod_redact_sensitive_string($value);
        }
        return $value;
    }
}

if (!function_exists('cfmod_redact_sensitive_array')) {
    function cfmod_redact_sensitive_array(array $data): array
    {
        foreach ($data as $k => $v) {
            $data[$k] = cfmod_redact_sensitive_value($v, is_string($k) ? strtolower($k) : null);
        }
        return $data;
    }
}

if (!function_exists('cfmod_sanitize_log_payload')) {
    function cfmod_sanitize_log_payload($payload)
    {
        if (is_array($payload)) {
            return cfmod_redact_sensitive_array($payload);
        }
        if (is_object($payload)) {
            $converted = json_decode(json_encode($payload), true);
            if (is_array($converted)) {
                return cfmod_redact_sensitive_array($converted);
            }
        }
        if (is_string($payload)) {
            return cfmod_redact_sensitive_string($payload);
        }
        return $payload;
    }
}
