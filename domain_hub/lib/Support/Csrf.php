<?php

declare(strict_types=1);

class CfCsrf
{
    public static function ensureClientSeed(): void
    {
        self::ensureSession();

        if (empty($_SESSION['cfmod_csrf'])) {
            $_SESSION['cfmod_csrf'] = bin2hex(random_bytes(32));
        }
    }

    public static function ensureAdminSeed(): void
    {
        self::ensureSession();

        if (empty($_SESSION['cfmod_admin_csrf'])) {
            $_SESSION['cfmod_admin_csrf'] = bin2hex(random_bytes(32));
        }
    }

    public static function validateClientRequest(): bool
    {
        if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return true;
        }

        self::ensureClientSeed();
        $expected = $_SESSION['cfmod_csrf'] ?? '';

        if ($expected === '') {
            return false;
        }

        $candidates = [];
        if (isset($_POST['cfmod_csrf_token'])) {
            $candidates[] = (string) $_POST['cfmod_csrf_token'];
        }
        if (!empty($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $candidates[] = (string) $_SERVER['HTTP_X_CSRF_TOKEN'];
        }

        foreach ($candidates as $candidate) {
            if (self::isTokenValid($expected, $candidate)) {
                return true;
            }
        }

        return false;
    }

    public static function validateAdminRequest(): bool
    {
        if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return true;
        }

        self::ensureAdminSeed();
        $expected = $_SESSION['cfmod_admin_csrf'] ?? '';
        $provided = $_POST['cfmod_admin_csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');

        return self::isTokenValid($expected, (string) $provided);
    }

    public static function isTokenValid(?string $expected, ?string $candidate): bool
    {
        if (!is_string($expected) || $expected === '' || !is_string($candidate) || $candidate === '') {
            return false;
        }

        return hash_equals($expected, $candidate);
    }

    private static function ensureSession(): void
    {
        try {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                @session_start();
            }
        } catch (\Throwable $e) {
            // ignore
        }
    }
}
