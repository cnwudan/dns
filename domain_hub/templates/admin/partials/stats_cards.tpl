<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$statsView = $cfAdminViewModel['stats'] ?? [];
$totalSubdomains = (int) ($statsView['totalSubdomains'] ?? 0);
$activeSubdomains = (int) ($statsView['activeSubdomains'] ?? 0);
$registeredUsers = (int) ($statsView['registeredUsers'] ?? 0);
$subdomainsCreated = (int) ($statsView['subdomainsCreated'] ?? 0);
$dnsOperations = (int) ($statsView['dnsOperations'] ?? 0);
?>

<div class="row mb-4">
    <div class="col-md-2">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <h5 class="card-title">总子域名</h5>
                <h2><?php echo $totalSubdomains; ?></h2>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card bg-success text-white">
            <div class="card-body">
                <h5 class="card-title">活跃子域名</h5>
                <h2><?php echo $activeSubdomains; ?></h2>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card bg-info text-white">
            <div class="card-body">
                <h5 class="card-title">注册用户</h5>
                <h2><?php echo $registeredUsers; ?></h2>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card bg-secondary text-white">
            <div class="card-body">
                <h5 class="card-title">用户创建</h5>
                <h2><?php echo $subdomainsCreated; ?></h2>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card bg-warning text-white">
            <div class="card-body">
                <h5 class="card-title">DNS 操作</h5>
                <h2><?php echo $dnsOperations; ?></h2>
            </div>
        </div>
    </div>
</div>
