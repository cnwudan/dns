<?php

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    static $classMap = [
        'CfSettingsRepository' => __DIR__ . '/Repositories/SettingsRepository.php',
        'CfCsrf' => __DIR__ . '/Support/Csrf.php',
        'CfProviderService' => __DIR__ . '/Services/ProviderService.php',
        'CfQuotaRepository' => __DIR__ . '/Repositories/QuotaRepository.php',
        'CfQuotaRedeemService' => __DIR__ . '/Services/QuotaRedeemService.php',
        'CfSubdomainService' => __DIR__ . '/Services/SubdomainService.php',
        'CfLoggingService' => __DIR__ . '/Services/LoggingService.php',
        'CfAdminController' => __DIR__ . '/Http/AdminController.php',
        'CfClientController' => __DIR__ . '/Http/ClientController.php',
        'CfApiDispatcher' => __DIR__ . '/Http/ApiDispatcher.php',
        'CfClientViewModelBuilder' => __DIR__ . '/Services/ClientViewModelBuilder.php',
        'CfClientActionService' => __DIR__ . '/Services/ClientActionService.php',
        'CfAsyncDnsJobService' => __DIR__ . '/Services/AsyncDnsJobService.php',
        'CfAdminActionService' => __DIR__ . '/Services/AdminActionService.php',
        'CfAdminViewModelBuilder' => __DIR__ . '/Services/AdminViewModelBuilder.php',
        'CfDnsUnlockService' => __DIR__ . '/Services/DnsUnlockService.php',
        'CfVpnDetectionService' => __DIR__ . '/Services/VpnDetectionService.php',

        'CfRateLimiter' => __DIR__ . '/Services/RateLimiter.php',
        'CfModuleSettings' => __DIR__ . '/Support/ModuleSettings.php',
        'CfModuleInstaller' => __DIR__ . '/Setup/ModuleInstaller.php',
        'CfHookRegistrar' => __DIR__ . '/Hooks/Registrar.php',
        'CfApiRouter' => __DIR__ . '/Support/ApiRouter.php',
    ];

    if (isset($classMap[$class])) {
        $path = $classMap[$class];
        if (is_file($path)) {
            require_once $path;
        }
    }
});

require_once __DIR__ . '/Services/LoggingService.php';
require_once __DIR__ . '/Support/SecuritySupport.php';
require_once __DIR__ . '/Support/LoggingSupport.php';
require_once __DIR__ . '/Support/BanSupport.php';
require_once __DIR__ . '/Support/QuotaSupport.php';
require_once __DIR__ . '/Support/ClientTemplateHelpers.php';
require_once __DIR__ . '/Support/I18n.php';
