<?php
/**
 * Cloudflare 二级域名分发插件激活检查脚本
 * 用于检查插件是否正确激活和配置
 */

use WHMCS\Database\Capsule;

// 检查是否在命令行运行
if (php_sapi_name() !== 'cli') {
    die("此脚本只能在命令行中运行\n");
}

echo "========================================\n";
echo "Cloudflare 二级域名分发插件激活检查\n";
echo "========================================\n\n";

// 检查WHMCS环境
$whmcs_path = '';
$current_dir = getcwd();

// 尝试找到WHMCS根目录
$dirs_to_check = [
    $current_dir,
    dirname($current_dir),
    dirname(dirname($current_dir)),
    dirname(dirname(dirname($current_dir)))
];

foreach ($dirs_to_check as $dir) {
    if (file_exists($dir . '/configuration.php') || file_exists($dir . '/init.php')) {
        $whmcs_path = $dir;
        break;
    }
}

if (!$whmcs_path) {
    echo "❌ 无法找到WHMCS根目录\n";
    echo "请确保此脚本在WHMCS的modules/addons/domain_hub/目录中运行\n\n";
    exit(1);
}

echo "✓ 找到WHMCS根目录: $whmcs_path\n";

$moduleSlug = defined('CF_MODULE_NAME') ? CF_MODULE_NAME : 'domain_hub';
$moduleSlugLegacy = defined('CF_MODULE_NAME_LEGACY') ? CF_MODULE_NAME_LEGACY : 'cloudflare_subdomain';

// 尝试加载WHMCS
try {
    if (file_exists($whmcs_path . '/init.php')) {
        require_once $whmcs_path . '/init.php';
        echo "✓ WHMCS初始化文件加载成功\n";
    } elseif (file_exists($whmcs_path . '/configuration.php')) {
        require_once $whmcs_path . '/configuration.php';
        echo "✓ WHMCS配置文件加载成功\n";
    } else {
        echo "❌ 无法加载WHMCS文件\n";
        exit(1);
    }
} catch (Exception $e) {
    echo "❌ WHMCS加载失败: " . $e->getMessage() . "\n";
    exit(1);
}

// 检查数据库连接
echo "\n检查数据库连接...\n";
try {
    $result = \WHMCS\Database\Capsule::select('SELECT 1 as test');
    if ($result) {
        echo "✓ 数据库连接成功\n";
    } else {
        echo "❌ 数据库连接失败\n";
        exit(1);
    }
} catch (Exception $e) {
    echo "❌ 数据库连接失败: " . $e->getMessage() . "\n";
    exit(1);
}

// 检查插件表是否存在
echo "\n检查插件数据库表...\n";
try {
    $tables_to_check = [
        'mod_cloudflare_subdomain',
        'mod_cloudflare_subdomain_quotas'
    ];
    
    foreach ($tables_to_check as $table) {
        if (Capsule::schema()->hasTable($table)) {
            echo "✓ 表 $table 存在\n";
            
            // 检查表结构
            $columns = Capsule::schema()->getColumnListing($table);
            echo "  列: " . implode(', ', $columns) . "\n";
        } else {
            echo "❌ 表 $table 不存在\n";
        }
    }
} catch (Exception $e) {
    echo "❌ 数据库表检查失败: " . $e->getMessage() . "\n";
}

// 检查插件配置
echo "\n检查插件配置...\n";
try {
    $configs = Capsule::table('tbladdonmodules')
    ->where('module', $moduleSlug)
    ->get();
    if (count($configs) === 0 && $moduleSlugLegacy !== $moduleSlug) {
        $configs = Capsule::table('tbladdonmodules')
        ->where('module', $moduleSlugLegacy)
        ->get();
    }

    if (count($configs) > 0) {

        foreach ($configs as $config) {
            echo "  {$config->setting}: {$config->value}\n";
        }
    } else {
        echo "❌ 未找到插件配置记录\n";
        echo "  请确保插件已在WHMCS后台激活\n";
    }
} catch (Exception $e) {
    echo "❌ 插件配置检查失败: " . $e->getMessage() . "\n";
}

// 检查插件文件
echo "\n检查插件文件...\n";
$required_files = [
    'domain_hub.php',
    'lib/CloudflareAPI.php',
    'templates/admin.tpl',
    'templates/client.tpl'
];

foreach ($required_files as $file) {
    if (file_exists($file)) {
        echo "✓ $file 存在\n";
    } else {
        echo "❌ $file 不存在\n";
    }
}

// 检查文件权限
echo "\n检查文件权限...\n";
$files_to_check = [
    'domain_hub.php' => '0644',
    'lib/CloudflareAPI.php' => '0644',
    'templates/admin.tpl' => '0644',
    'templates/client.tpl' => '0644'
];

foreach ($files_to_check as $file => $expected_perm) {
    if (file_exists($file)) {
        $current_perm = substr(sprintf('%o', fileperms($file)), -4);
        if ($current_perm == $expected_perm) {
            echo "✓ $file: $current_perm\n";
        } else {
            echo "⚠ $file: $current_perm (建议: $expected_perm)\n";
        }
    }
}

// 检查目录权限
echo "\n检查目录权限...\n";
$dirs_to_check = [
    '.' => '0755',
    'lib' => '0755',
    'templates' => '0755'
];

foreach ($dirs_to_check as $dir => $expected_perm) {
    if (is_dir($dir)) {
        $current_perm = substr(sprintf('%o', fileperms($dir)), -4);
        if ($current_perm == $expected_perm) {
            echo "✓ $dir/: $current_perm\n";
        } else {
            echo "⚠ $dir/: $current_perm (建议: $expected_perm)\n";
        }
    }
}

// 检查PHP语法
echo "\n检查PHP语法...\n";
$php_files = [
    'domain_hub.php',
    'lib/CloudflareAPI.php'
];

foreach ($php_files as $file) {
    if (file_exists($file)) {
        $output = [];
        $return_var = 0;
        exec("php -l $file 2>&1", $output, $return_var);
        
        if ($return_var === 0) {
            echo "✓ $file: 语法正确\n";
        } else {
            echo "❌ $file: 语法错误\n";
            foreach ($output as $line) {
                echo "  $line\n";
            }
        }
    }
}

// 总结和建议
echo "\n========================================\n";
echo "检查完成！\n";
echo "========================================\n\n";

echo "如果看到 ❌ 错误，请按以下步骤解决：\n\n";

echo "1. 激活插件：\n";
echo "   - 登录WHMCS管理后台\n";
echo "   - 进入 设置 → 插件模块\n";
echo "   - 找到 'Cloudflare 二级域名分发' 插件\n";
echo "   - 点击 '激活' 按钮\n\n";

echo "2. 配置插件：\n";
echo "   - 点击 '配置' 按钮\n";
echo "   - 填写Cloudflare API信息\n";
echo "   - 设置根域名和配额限制\n";
echo "   - 保存配置\n\n";

echo "3. 检查文件权限：\n";
echo "   chmod -R 755 /path/to/whmcs/modules/addons/domain_hub\n";
echo "   chmod 644 /path/to/whmcs/modules/addons/domain_hub/*.php\n\n";

echo "4. 如果仍有问题：\n";
echo "   - 查看WHMCS错误日志\n";
echo "   - 检查PHP错误日志\n";
echo "   - 确认WHMCS版本 >= 7.10\n";
echo "   - 确认PHP版本 >= 7.4\n\n";

echo "插件激活成功后，数据库表将自动创建，\n";
echo "然后就可以正常使用所有功能了！\n";

// 提示：可在系统计划任务中每分钟运行一次队列worker，例如：
// php -r "require 'modules/addons/domain_hub/worker.php'; run_cf_queue_once();"
// 或以 WHMCS 内置Cron为入口引导执行。
?>