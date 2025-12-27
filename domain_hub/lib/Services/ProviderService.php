<?php

declare(strict_types=1);

class CfProviderService
{
    private static ?self $instance = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function acquireProviderClientForSubdomain($subdomainRow, ?array $settings = null): ?array
    {
        if (!$subdomainRow) {
            return null;
        }

        $settings = cfmod_provider_resolve_settings($settings);
        return cfmod_make_provider_client_for_subdomain($subdomainRow, $settings);
    }

    public function acquireProviderClientForRootdomain($rootdomain, ?array $settings = null): ?array
    {
        $settings = cfmod_provider_resolve_settings($settings);
        if ($rootdomain === null || $rootdomain === '') {
            return cfmod_acquire_default_provider_client($settings);
        }

        return cfmod_make_provider_client_for_rootdomain($rootdomain, $settings);
    }

    public function resolveProviderAccountId(?int $providerAccountId = null, ?string $rootdomain = null, ?int $subdomainId = null, ?array $settings = null, bool $forceProvider = false): ?int
    {
        if ($forceProvider) {
            return cfmod_filter_active_provider_id($providerAccountId);
        }

        $rootProviderId = null;
        if (!empty($rootdomain)) {
            $rootCandidate = cfmod_lookup_rootdomain_provider_id($rootdomain);
            if (is_numeric($rootCandidate) && (int) $rootCandidate > 0) {
                $rootProviderId = (int) $rootCandidate;
            }
        }

        $candidate = cfmod_filter_active_provider_id($providerAccountId);
        if ($candidate !== null) {
            if ($rootProviderId && $candidate !== $rootProviderId) {
                if ($subdomainId && $rootProviderId > 0) {
                    cfmod_update_subdomain_provider_reference_if_needed($subdomainId, $rootProviderId, $candidate);
                }
                return $rootProviderId;
            }
            return $candidate;
        }

        $subProvider = null;
        if (is_numeric($subdomainId) && (int) $subdomainId > 0) {
            $subProvider = cfmod_lookup_subdomain_provider_id((int) $subdomainId);
            if ($subProvider && $subProvider > 0) {
                $candidate = cfmod_filter_active_provider_id($subProvider);
                if ($candidate !== null) {
                    if ($rootProviderId && $candidate !== $rootProviderId) {
                        cfmod_update_subdomain_provider_reference_if_needed($subdomainId, $rootProviderId, $subProvider);
                        return $rootProviderId;
                    }
                    return $candidate;
                }
            }
        }

        if ($rootProviderId) {
            if ($subdomainId && $rootProviderId > 0) {
                cfmod_update_subdomain_provider_reference_if_needed($subdomainId, $rootProviderId, $subProvider);
            }
            return $rootProviderId;
        }

        $defaultId = cfmod_filter_active_provider_id(cfmod_get_default_provider_account_id($settings));
        if ($defaultId !== null && $defaultId > 0) {
            if ($subdomainId) {
                cfmod_update_subdomain_provider_reference_if_needed($subdomainId, $defaultId, $subProvider);
            }
            return $defaultId;
        }

        return null;
    }
}
