<?php
$cfAdminViewModel = $cfAdminViewModel ?? [];
$cfAdminAlerts = $cfAdminAlerts ?? ($cfAdminViewModel['alerts']['messages'] ?? []);
$msg = $msg ?? '';
$msg_type = $msg_type ?? 'info';
?>

<?php if (!empty($cfAdminAlerts)): ?>
    <?php foreach ($cfAdminAlerts as $alert): ?>
        <?php
            $alertType = $alert['type'] ?? 'info';
            $alertClass = 'alert-' . $alertType;
            if ($alertType === 'info') {
                $alertClass = 'alert-primary';
            }
        ?>
        <div class="alert <?php echo $alertClass; ?> alert-dismissible fade in" role="alert">
            <?php echo $alert['message']; ?>
            <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
        </div>
    <?php endforeach; ?>
<?php endif; ?>

<?php if (!empty($msg)): ?>
    <?php
        $legacyClass = 'alert-' . ($msg_type ?? 'info');
        if ($msg_type === 'info') {
            $legacyClass = 'alert-primary';
        }
    ?>
    <div class="alert <?php echo $legacyClass; ?> alert-dismissible fade in" role="alert">
        <?php echo htmlspecialchars($msg); ?>
        <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
    </div>
<?php endif; ?>
