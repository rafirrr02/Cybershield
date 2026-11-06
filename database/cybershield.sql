-- ============================================================
-- CyberShield v4.2-ENT — Database MySQL
-- Created for: Rafi Raihan Rijal | NIM 242502040029 | Class 3TI01
-- How to use: import this file in phpMyAdmin (or: mysql -u root -p < cybershield.sql)
-- The demo app (index.html) uses localStorage with the SAME
-- table structure as below, so it can be demoed
-- without a server — and can still be moved to PHP + MySQL.
-- ============================================================

CREATE DATABASE IF NOT EXISTS cybershield CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cybershield;

-- 1) firewall_rules — Firewall Rule Management
CREATE TABLE IF NOT EXISTS firewall_rules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  ip VARCHAR(45) NOT NULL COMMENT 'IP or CIDR, e.g. 45.227.45.10 or 192.168.1.0/24',
  port INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol ENUM('TCP','UDP','TCP/UDP') NOT NULL DEFAULT 'TCP',
  action ENUM('ALLOW','BLOCK') NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2) security_logs — Security Log
CREATE TABLE IF NOT EXISTS security_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source_ip VARCHAR(45) NOT NULL,
  dest_port INT NOT NULL,
  activity_type VARCHAR(100) NOT NULL COMMENT 'e.g. Normal traffic (HTTPS), SSH Brute Force attempt',
  action ENUM('ALLOWED','BLOCKED') NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3) blacklist_ips — Blacklist IPs
CREATE TABLE IF NOT EXISTS blacklist_ips (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(45) NOT NULL UNIQUE,
  reason VARCHAR(150) NOT NULL,
  added_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------- Seed data (same as in js/app.js) ----------
-- Evaluation order: Blacklist -> BLOCK -> ALLOW -> default deny.
-- '*' = All IPs. The SSH Admin (LAN) rule is intentionally inactive.
INSERT INTO firewall_rules (name, ip, port, protocol, action, is_active) VALUES
('Allow HTTP',           '*',              80,   'TCP', 'ALLOW', 1),
('Allow HTTPS',          '*',             443,   'TCP', 'ALLOW', 1),
('Allow DNS',            '*',              53,   'UDP', 'ALLOW', 1),
('Block Telnet',          '*',              23,   'TCP', 'BLOCK', 1),
('Allow SSH Admin (LAN)','192.168.1.0/24', 22,   'TCP', 'ALLOW', 0);

INSERT INTO security_logs (event_time, source_ip, dest_port, activity_type, action) VALUES
('2026-11-06 02:47:58', '104.179.86.20',   53, 'Normal traffic (DNS)',     'ALLOWED'),
('2026-11-06 02:47:58', '203.54.142.233', 443, 'Normal traffic (HTTPS)',   'ALLOWED'),
('2026-11-06 02:47:58', '192.168.1.206', 1433, 'External database access',      'BLOCKED'),
('2026-11-06 02:47:57', '203.155.152.203',3306, 'External database access',      'BLOCKED'),
('2026-11-06 02:47:57', '203.65.149.93',   21, 'FTP access attempt',           'BLOCKED'),
('2026-11-06 02:47:56', '192.168.1.138',   23, 'Unauthorized Telnet access',        'BLOCKED'),
('2026-11-06 02:47:56', '192.168.1.135',   80, 'Normal traffic (HTTP)',    'ALLOWED'),
('2026-11-06 02:47:56', '203.58.29.70',    22, 'SSH Brute Force attempt',     'BLOCKED');

INSERT INTO blacklist_ips (ip, reason, added_date) VALUES
('185.220.101.45',  'TOR exit node - scanning activity', '2026-10-31 14:32:10'),
('45.155.205.233',  'SSH brute force source',             '2026-11-01 14:32:10'),
('91.240.118.172',  'Malware C2 server',                  '2026-11-03 09:32:10');
