<?php

class conn extends DbClass
{
    public function DBConnect(array $config): ?PDO
    {
        $host = $config["host"] ?? "127.0.0.1";
        $port = $config["port"] ?? "3306";
        $name = $config["name"] ?? "";
        $user = $config["user"] ?? "";
        $pass = $config["pass"] ?? "";

        $dsn = "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4";

        return new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
}
