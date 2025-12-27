<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfModuleSettings
{
    public const DEFAULT_MODULE = 'domain_hub';
    public const DEFAULT_LEGACY_MODULE = 'cloudflare_subdomain';

    /**
     * Ensure constants exist and migrate legacy settings one time per request.
     */
    public static function bootstrap(): void
    {
        self::ensureConstants();
        self::ensureMigrated();
    }

    public static function ensureConstants(): void
    {
        if (!defined('CF_MODULE_NAME')) {
            define('CF_MODULE_NAME', self::DEFAULT_MODULE);
        }
        if (!defined('CF_MODULE_NAME_LEGACY')) {
            define('CF_MODULE_NAME_LEGACY', self::DEFAULT_LEGACY_MODULE);
        }
    }

    public static function moduleName(): string
    {
        return defined('CF_MODULE_NAME') ? CF_MODULE_NAME : self::DEFAULT_MODULE;
    }

    public static function legacyModuleName(): string
    {
        return defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : self::DEFAULT_LEGACY_MODULE;
    }

    public static function ensureMigrated(): void
    {
        static $migrated = false;
        if ($migrated) {
            return;
        }

        $migrated = true;
        try {
            $currentModule = self::moduleName();
            $legacyModule = self::legacyModuleName();

            $newCount = Capsule::table('tbladdonmodules')->where('module', $currentModule)->count();
            if ($newCount === 0 && $legacyModule !== $currentModule) {
                $legacyRows = Capsule::table('tbladdonmodules')->where('module', $legacyModule)->get();
                foreach ($legacyRows as $row) {
                    Capsule::table('tbladdonmodules')->updateOrInsert(
                        ['module' => $currentModule, 'setting' => $row->setting],
                        ['value' => $row->value]
                    );
                }
            }
        } catch (\Throwable $e) {
            // Best effort migration. Swallow exceptions to avoid breaking activation.
        }
    }
}
