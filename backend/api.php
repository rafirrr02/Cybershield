<?php
// CyberShield v4.2-ENT — JSON API (PHP + MySQL)
// Created for: Rafi Raihan Rijal | NIM 242502040029 | Class 3TI01
//
// How to use (XAMPP): import backend/schema.sql into MySQL, copy the
// CyberShield folder to htdocs, then call this file, e.g.:
//   GET  backend/api.php?action=stats
//   GET  backend/api.php?action=list_rules
//   POST backend/api.php?action=add_rule   (name, ip, port, protocol, action)
//   POST backend/api.php?action=toggle_rule (id, active: 1/0)
//   POST backend/api.php?action=delete_rule (id)
//   GET  backend/api.php?action=list_logs
//   POST backend/api.php?action=clear_logs
//   GET  backend/api.php?action=list_blacklist
//   POST backend/api.php?action=add_blacklist (ip, reason)
//   POST backend/api.php?action=remove_blacklist (id)
//
// Note: the demo on GitHub Pages cannot run PHP/MySQL (static files only),
// so the demo app stores the same data in the browser's localStorage.
// This backend is for the server version (XAMPP / PHP hosting).

header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/db.php';

function input($key, $default = null) {
    if (isset($_POST[$key])) return $_POST[$key];
    if (isset($_GET[$key])) return $_GET[$key];
    static $json = null;
    if ($json === null) {
        $raw = file_get_contents('php://input');
        $json = $raw ? json_decode($raw, true) : [];
        if (!is_array($json)) $json = [];
    }
    return isset($json[$key]) ? $json[$key] : $default;
}

function ok($data = []) {
    echo json_encode(array_merge(['ok' => true], $data));
    exit;
}

function fail($message) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => $message]);
    exit;
}

$action = input('action', '');

try {
    $pdo = getPDO();

    switch ($action) {
        case 'stats':
            $totalRules = (int) $pdo->query("SELECT COUNT(*) FROM firewall_rules")->fetchColumn();
            $activeRules = (int) $pdo->query("SELECT COUNT(*) FROM firewall_rules WHERE is_active = 1")->fetchColumn();
            $totalLogs = (int) $pdo->query("SELECT COUNT(*) FROM security_logs")->fetchColumn();
            $blocked = (int) $pdo->query("SELECT COUNT(*) FROM security_logs WHERE action = 'BLOCKED'")->fetchColumn();
            $allowed = (int) $pdo->query("SELECT COUNT(*) FROM security_logs WHERE action = 'ALLOWED'")->fetchColumn();
            $blacklist = (int) $pdo->query("SELECT COUNT(*) FROM blacklist_ips")->fetchColumn();
            ok([
                'total_rules' => $totalRules,
                'active_rules' => $activeRules,
                'total_logs' => $totalLogs,
                'blocked' => $blocked,
                'allowed' => $allowed,
                'blacklist' => $blacklist,
            ]);
            break;

        case 'list_rules':
            $rows = $pdo->query("SELECT * FROM firewall_rules ORDER BY id ASC")->fetchAll();
            ok(['rules' => $rows]);
            break;

        case 'add_rule': {
            $name = trim((string) input('name', ''));
            $ip = trim((string) input('ip', ''));
            $port = (int) input('port', 0);
            $protocol = strtoupper(trim((string) input('protocol', 'TCP')));
            $ruleAction = strtoupper(trim((string) input('action', 'ALLOW')));
            if ($name === '' || $ip === '') fail('name and ip are required');
            if ($port < 1 || $port > 65535) fail('port must be 1-65535');
            if (!in_array($protocol, ['TCP', 'UDP', 'TCP/UDP'], true)) fail('protocol must be TCP, UDP or TCP/UDP');
            if (!in_array($ruleAction, ['ALLOW', 'BLOCK'], true)) fail('action must be ALLOW or BLOCK');
            $stmt = $pdo->prepare("INSERT INTO firewall_rules (name, ip, port, protocol, action, is_active) VALUES (?, ?, ?, ?, ?, 1)");
            $stmt->execute([$name, $ip, $port, $protocol, $ruleAction]);
            ok(['id' => (int) $pdo->lastInsertId()]);
            break;
        }

        case 'toggle_rule': {
            $id = (int) input('id', 0);
            $active = (int) input('active', 1) ? 1 : 0;
            $stmt = $pdo->prepare("UPDATE firewall_rules SET is_active = ? WHERE id = ?");
            $stmt->execute([$active, $id]);
            ok(['updated' => $stmt->rowCount()]);
            break;
        }

        case 'delete_rule': {
            $id = (int) input('id', 0);
            $stmt = $pdo->prepare("DELETE FROM firewall_rules WHERE id = ?");
            $stmt->execute([$id]);
            ok(['deleted' => $stmt->rowCount()]);
            break;
        }

        case 'list_logs':
            $rows = $pdo->query("SELECT * FROM security_logs ORDER BY event_time DESC, id DESC LIMIT 500")->fetchAll();
            ok(['logs' => $rows]);
            break;

        case 'add_log': {
            $ip = trim((string) input('source_ip', ''));
            $port = (int) input('dest_port', 0);
            $activity = trim((string) input('activity_type', ''));
            $logAction = strtoupper(trim((string) input('action', 'ALLOWED')));
            if ($ip === '' || $activity === '') fail('source_ip and activity_type are required');
            if (!in_array($logAction, ['ALLOWED', 'BLOCKED'], true)) fail('action must be ALLOWED or BLOCKED');
            $stmt = $pdo->prepare("INSERT INTO security_logs (source_ip, dest_port, activity_type, action) VALUES (?, ?, ?, ?)");
            $stmt->execute([$ip, $port, $activity, $logAction]);
            ok(['id' => (int) $pdo->lastInsertId()]);
            break;
        }

        case 'clear_logs':
            $pdo->exec("DELETE FROM security_logs");
            ok(['cleared' => true]);
            break;

        case 'list_blacklist':
            $rows = $pdo->query("SELECT * FROM blacklist_ips ORDER BY added_date DESC")->fetchAll();
            ok(['blacklist' => $rows]);
            break;

        case 'add_blacklist': {
            $ip = trim((string) input('ip', ''));
            $reason = trim((string) input('reason', 'Blocked manually'));
            if ($ip === '') fail('ip is required');
            $stmt = $pdo->prepare("INSERT INTO blacklist_ips (ip, reason) VALUES (?, ?)");
            $stmt->execute([$ip, $reason]);
            ok(['id' => (int) $pdo->lastInsertId()]);
            break;
        }

        case 'remove_blacklist': {
            $id = (int) input('id', 0);
            $stmt = $pdo->prepare("DELETE FROM blacklist_ips WHERE id = ?");
            $stmt->execute([$id]);
            ok(['deleted' => $stmt->rowCount()]);
            break;
        }

        default:
            fail('unknown action: ' . $action);
    }
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Database error: ' . $e->getMessage()]);
}
