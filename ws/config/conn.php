<?php
date_default_timezone_set('Asia/Jakarta');

class conn
{
    public function DBConnect(array $data): PDO
    {
        $host = (string)($data['host'] ?? '');
        $user = (string)($data['user'] ?? '');
        $pass = (string)($data['pass'] ?? '');
        $db   = (string)($data['name'] ?? '');
        $port = (string)($data['port'] ?? '3306');

        $dsn = "mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4";

        try {
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_TIMEOUT => 5,
            ];
            if (defined('PDO::MYSQL_ATTR_CONNECT_TIMEOUT')) {
                $options[PDO::MYSQL_ATTR_CONNECT_TIMEOUT] = 5;
            }

            $pdo = new PDO($dsn, $user, $pass, $options);
            return $pdo;
        } catch (PDOException $e) {
            throw new RuntimeException("DB_CONNECT_FAIL: " . $e->getMessage(), 0, $e);
        }
    }
}
