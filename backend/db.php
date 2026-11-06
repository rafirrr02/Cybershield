<?php
// CyberShield v4.2-ENT — Database connection (PDO MySQL)
// Created for: Rafi Raihan Rijal | NIM 242502040029 | Class 3TI01
// XAMPP defaults: host localhost, user root, no password.
// Change these values if your MySQL uses a different user/password.

define('DB_HOST', 'localhost');
define('DB_NAME', 'cybershield');
define('DB_USER', 'root');
define('DB_PASS', '');

function getPDO() {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}
