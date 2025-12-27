<?php

declare(strict_types=1);

class CfSecuritySupport
{
    public static function isValidCsrfToken(?string $expected, ?string $candidate): bool
    {
        return CfCsrf::isTokenValid($expected, $candidate);
    }

    public static function ensureClientSeed(): void
    {
        CfCsrf::ensureClientSeed();
    }

    public static function validateClientRequest(): bool
    {
        return CfCsrf::validateClientRequest();
    }

    public static function ensureAdminSeed(): void
    {
        CfCsrf::ensureAdminSeed();
    }

    public static function validateAdminRequest(): bool
    {
        return CfCsrf::validateAdminRequest();
    }
}

if (!function_exists('cfmod_is_valid_csrf_token')) {
    function cfmod_is_valid_csrf_token(?string $expected, ?string $candidate): bool
    {
        return CfSecuritySupport::isValidCsrfToken($expected, $candidate);
    }
}

if (!function_exists('cfmod_ensure_client_csrf_seed')) {
    function cfmod_ensure_client_csrf_seed(): void
    {
        CfSecuritySupport::ensureClientSeed();
    }
}

if (!function_exists('cfmod_validate_client_area_csrf')) {
    function cfmod_validate_client_area_csrf(): bool
    {
        return CfSecuritySupport::validateClientRequest();
    }
}

if (!function_exists('cfmod_ensure_admin_csrf_seed')) {
    function cfmod_ensure_admin_csrf_seed(): void
    {
        CfSecuritySupport::ensureAdminSeed();
    }
}

if (!function_exists('cfmod_validate_admin_csrf')) {
    function cfmod_validate_admin_csrf(): bool
    {
        return CfSecuritySupport::validateAdminRequest();
    }
}
