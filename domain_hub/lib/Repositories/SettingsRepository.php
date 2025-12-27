<?php

declare(strict_types=1);

use WHMCS\Database\Capsule;

class CfSettingsRepository
{
    private static ?self $instance = null;

    /** @var array<string, mixed>|null */
    private ?array $cache = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * 获取全部配置（含默认值与迁移）
     */
    public function getAll(): array
    {
        if ($this->cache === null) {
            $this->cache = $this->loadSettings();
        }

        return $this->cache;
    }

    /**
     * 获取指定配置
     */
    public function get(string $key, $default = null)
    {
        $settings = $this->getAll();

        return array_key_exists($key, $settings) ? $settings[$key] : $default;
    }

    /**
     * 刷新缓存
     */
    public function refresh(): array
    {
        $this->cache = $this->loadSettings();

        return $this->cache;
    }

    private function loadSettings(): array
    {
        $settings = [];

        try {
            if (function_exists('cf_ensure_module_settings_migrated')) {
                cf_ensure_module_settings_migrated();
            }

            $module = $this->currentModuleSlug();
            $legacy = $this->legacyModuleSlug();

            $configs = Capsule::table('tbladdonmodules')
                ->where('module', $module)
                ->get();

            if (count($configs) === 0 && $legacy !== $module) {
                $configs = Capsule::table('tbladdonmodules')
                    ->where('module', $legacy)
                    ->get();
            }

            foreach ($configs as $config) {
                $settings[$config->setting] = $config->value;
            }
        } catch (\Throwable $e) {
            $settings = [];
        }

        $settings = $this->applyDefaults($settings);
        $settings = $this->synchronizeProviders($settings);
        $settings = $this->migrateLegacyFields($settings);

        return $settings;
    }

    private function applyDefaults(array $settings): array
    {
        $defaults = [
            'domain_registration_term_years' => '1',
            'domain_free_renew_window_days' => '30',
            'domain_grace_period_days' => '45',
            'domain_redemption_days' => '0',
            'domain_redemption_mode' => 'manual',
            'domain_redemption_fee_amount' => '0',
            'domain_redemption_cleanup_days' => '0',
            'domain_expiry_enable_legacy_never' => 'yes',
            'domain_cleanup_batch_size' => '50',
            'domain_cleanup_deep_delete' => 'yes',
            'redeem_ticket_url' => '',
            'api_logs_retention_days' => '30',
            'general_logs_retention_days' => '90',
            'sync_logs_retention_days' => '30',
            'whois_require_api_key' => 'no',
            'whois_email_mode' => 'anonymous',
            'whois_anonymous_email' => 'whois@example.com',
            'whois_default_nameservers' => '',
            'whois_rate_limit_per_minute' => '2',
            'enable_client_domain_delete' => '0',
            'domain_cleanup_interval_hours' => '24',
        ];

        foreach ($defaults as $key => $value) {
            if (!array_key_exists($key, $settings)) {
                $settings[$key] = $value;
            }
        }

        return $settings;
    }

    private function migrateLegacyFields(array $settings): array
    {
        if (!array_key_exists('domain_grace_period_days', $settings)
            && array_key_exists('domain_auto_delete_grace_days', $settings)
        ) {
            $legacyGrace = $settings['domain_auto_delete_grace_days'];
            $settings['domain_grace_period_days'] = $legacyGrace;

            try {
                Capsule::table('tbladdonmodules')->updateOrInsert(
                    ['module' => $this->currentModuleSlug(), 'setting' => 'domain_grace_period_days'],
                    ['value' => $legacyGrace]
                );
            } catch (\Throwable $e) {
                // best-effort
            }
        }

        if (!array_key_exists('domain_auto_delete_grace_days', $settings)
            && array_key_exists('domain_grace_period_days', $settings)
        ) {
            $settings['domain_auto_delete_grace_days'] = $settings['domain_grace_period_days'];
        }

        if (function_exists('cfmod_migrate_legacy_rootdomains')) {
            try {
                cfmod_migrate_legacy_rootdomains($settings);
            } catch (\Throwable $ignored) {
            }
        }

        return $settings;
    }

    private function synchronizeProviders(array $settings): array
    {
        try {
            if (function_exists('cfmod_sync_default_provider_account')) {
                $defaultProviderId = cfmod_sync_default_provider_account($settings);
                if ($defaultProviderId !== null && !array_key_exists('default_provider_account_id', $settings)) {
                    $settings['default_provider_account_id'] = (string) $defaultProviderId;
                }
            }
        } catch (\Throwable $ignored) {
        }

        try {
            if (function_exists('cfmod_get_provider_account') && function_exists('cfmod_get_default_provider_account')) {
                $providerForSettings = null;

                if (!empty($settings['default_provider_account_id'])) {
                    $providerForSettings = cfmod_get_provider_account((int) $settings['default_provider_account_id'], true);
                } else {
                    $providerForSettings = cfmod_get_default_provider_account(true);
                    if ($providerForSettings && !empty($providerForSettings['id'])) {
                        $settings['default_provider_account_id'] = (string) $providerForSettings['id'];
                        try {
                            Capsule::table('tbladdonmodules')->updateOrInsert(
                                ['module' => $this->currentModuleSlug(), 'setting' => 'default_provider_account_id'],
                                ['value' => $providerForSettings['id']]
                            );
                        } catch (\Throwable $ignored) {
                        }
                    }
                }

                if ($providerForSettings) {
                    $settings['cloudflare_email'] = $providerForSettings['access_key_id'] ?? '';
                    $settings['cloudflare_api_key'] = $providerForSettings['access_key_secret'] ?? '';
                }
            }
        } catch (\Throwable $ignored) {
        }

        return $settings;
    }

    private function currentModuleSlug(): string
    {
        return defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
    }

    private function legacyModuleSlug(): string
    {
        return defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : 'cloudflare_subdomain';
    }
}
