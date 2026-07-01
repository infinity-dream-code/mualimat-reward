<?php
error_reporting(E_ALL);
ini_set("display_errors", 1);
date_default_timezone_set("Asia/Jakarta");

$libDb = __DIR__ . "/lib/DbClass.php";
$libConn = __DIR__ . "/lib/conn.php";
$libJwt = __DIR__ . "/lib/jwt.php";
$cfgDb = __DIR__ . "/config/DbClass.php";
$cfgConn = __DIR__ . "/config/conn.php";
$cfgJwt = __DIR__ . "/config/jwt.php";

if (file_exists($libDb) && file_exists($libConn) && file_exists($libJwt)) {
    require_once $libDb;
    require_once $libConn;
    require_once $libJwt;
} elseif (file_exists($cfgDb) && file_exists($cfgConn) && file_exists($cfgJwt)) {
    require_once $cfgDb;
    require_once $cfgConn;
    require_once $cfgJwt;
} else {
    http_response_code(500);
    header("Content-Type: application/json; charset=utf-8");
    echo json_encode([
        "status" => 500,
        "message" => "Dependency WS tidak lengkap: butuh lib/* atau config/*",
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

function writeLog($data): void
{
    $line = "[" . date("Y-m-d H:i:s") . "] ";
    $line .= is_array($data) || is_object($data)
        ? json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        : (string) $data;
    file_put_contents(__DIR__ . "/error.log", $line . "\n", FILE_APPEND);
}

function loadEnv(string $path): void
{
    if (!file_exists($path)) {
        writeLog(["level" => "ERROR", "event" => "ENV_NOT_FOUND", "path" => $path]);
        http_response_code(500);
        echo json_encode(["status" => 500, "message" => "ENV tidak ditemukan"], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === "" || str_starts_with($line, "#")) continue;
        if (!str_contains($line, "=")) continue;

        [$name, $value] = explode("=", $line, 2);
        $name = trim($name);
        $value = trim($value);
        $value = trim($value, "\"'");

        putenv("$name=$value");
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

function getJsonInput(): array
{
    $raw = file_get_contents("php://input");
    $json = json_decode($raw, true);
    if (is_array($json)) return $json;
    if (!empty($_POST)) return $_POST;
    return [];
}

function dbConnectPdo(): PDO
{
    $host = (string) ($_ENV["DB_HOST"] ?? "");
    $user = (string) ($_ENV["DB_USERNAME"] ?? "");
    $pass = (string) ($_ENV["DB_PASSWORD"] ?? "");
    $port = (string) ($_ENV["DB_PORT"] ?? "3306");
    $name = (string) ($_ENV["DB_DATABASE"] ?? "");

    if ($host === "" || $user === "" || $name === "") {
        throw new RuntimeException("ENV_DB_INCOMPLETE");
    }

    $resolvedHost = gethostbyname($host);
    writeLog([
        "level" => "INFO",
        "event" => "DB_CONNECT_ATTEMPT",
        "host" => $host,
        "resolved_host" => $resolvedHost,
        "port" => $port,
        "database" => $name,
        "username" => $user,
        "password_masked" => str_repeat("*", min(strlen($pass), 12)),
        "password_len" => strlen($pass),
    ]);

    try {
        $conn = new conn();
        $pdo = $conn->DBConnect([
            "host" => $host,
            "user" => $user,
            "pass" => $pass,
            "port" => $port,
            "name" => $name,
        ]);
    } catch (Throwable $e) {
        writeLog([
            "level" => "ERROR",
            "event" => "DB_CONNECT_FAIL",
            "host" => $host,
            "resolved_host" => $resolvedHost,
            "port" => $port,
            "database" => $name,
            "username" => $user,
            "password_masked" => str_repeat("*", min(strlen($pass), 12)),
            "password_len" => strlen($pass),
            "error" => $e->getMessage(),
        ]);
        throw new RuntimeException("DB_CONNECT_FAIL: " . $e->getMessage());
    }

    if (!$pdo instanceof PDO) {
        throw new RuntimeException("DBConnect tidak mengembalikan PDO");
    }

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
}

function getTableColumns(PDO $pdo, string $table): array
{
    $stmt = $pdo->prepare("DESCRIBE `$table`");
    $stmt->execute();
    $rows = $stmt->fetchAll();
    $cols = [];
    foreach ($rows as $r) {
        if (isset($r["Field"])) $cols[] = (string) $r["Field"];
    }
    return $cols;
}

function pickColumn(array $cols, array $candidates): ?string
{
    $lowerMap = [];
    foreach ($cols as $c) $lowerMap[strtolower($c)] = $c;
    foreach ($candidates as $cand) {
        $k = strtolower($cand);
        if (isset($lowerMap[$k])) return $lowerMap[$k];
    }
    return null;
}

function slugify(string $s): string
{
    $s = strtolower(trim($s));
    $s = preg_replace('/[^a-z0-9]+/', '_', $s);
    return trim($s, '_');
}

function buildPublicFileUrl(string $relativePath): string
{
    $baseUrl = trim((string) ($_ENV["PUBLIC_BASE_URL"] ?? ""));
    if ($baseUrl === "") {
        $isHttps = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off")
            || (($_SERVER["SERVER_PORT"] ?? "") === "443");
        $scheme = $isHttps ? "https" : "http";
        $host = (string) ($_SERVER["HTTP_HOST"] ?? "");
        if ($host !== "") {
            $baseUrl = $scheme . "://" . $host;
        }
    }

    $relativePath = "/" . ltrim($relativePath, "/");
    if ($baseUrl === "") {
        return $relativePath;
    }

    return rtrim($baseUrl, "/") . $relativePath;
}

function fail(int $code, string $message): void
{
    http_response_code($code);
    echo json_encode(["status" => $code, "message" => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

function verifyPassword(string $password, string $stored): bool
{
    $stored = trim($stored);
    if ($stored === "") {
        return false;
    }

    $info = password_get_info($stored);
    if ($info["algo"] !== null) {
        return password_verify($password, $stored);
    }

    $lower = strtolower($stored);

    if (hash_equals($lower, sha1($password))) {
        return true;
    }
    if (hash_equals($lower, hash("sha256", $password))) {
        return true;
    }
    if (hash_equals($lower, md5($password))) {
        return true;
    }

    return hash_equals($stored, $password);
}

function doLogin(array $req): array
{
    $username = trim((string) ($req["username"] ?? ""));
    $password = trim((string) ($req["password"] ?? ""));

    if ($username === "" || $password === "") {
        fail(422, "Username dan password wajib diisi");
    }

    $pdo = dbConnectPdo();

    $userCols = getTableColumns($pdo, "sm_user");
    $usernameCol = pickColumn($userCols, ["userlogin", "username", "user_name", "login", "userid"]);
    $passwordCol = pickColumn($userCols, ["kunci", "password", "passwd", "pwd"]);

    if ($usernameCol === null || $passwordCol === null) {
        throw new RuntimeException("Kolom login tidak ditemukan di sm_user");
    }

    $stmt = $pdo->prepare("SELECT * FROM `sm_user` WHERE `$usernameCol` = :username LIMIT 1");
    $stmt->bindValue(":username", $username, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch();

    if (!$user) {
        fail(401, "Username atau password salah");
    }

    if (!verifyPassword($password, (string) $user[$passwordCol])) {
        fail(401, "Username atau password salah");
    }

    $nocust = trim((string) $user[$usernameCol]);

    $custStmt = $pdo->prepare("
        SELECT CUSTID AS custid, NOCUST AS nocust, NMCUST AS nmcust, DESC02 AS kelas
        FROM scctcust
        WHERE NOCUST = :nocust
        ORDER BY CUSTID DESC
        LIMIT 1
    ");
    $custStmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
    $custStmt->execute();
    $cust = $custStmt->fetch();

    if (!$cust) {
        fail(404, "Data siswa untuk akun ini tidak ditemukan");
    }

    $jwt = new JWT();
    $key = (string) ($_ENV["JWT_KEY"] ?? "");
    if ($key === "") {
        throw new RuntimeException("JWT_KEY belum di set");
    }

    $payload = [
        "custid" => $cust["custid"],
        "nocust" => $cust["nocust"],
        "nmcust" => $cust["nmcust"],
        "kelas"  => $cust["kelas"],
        "iat"    => time(),
        "exp"    => time() + (60 * 60 * 12),
    ];
    $token = $jwt->encode($payload, $key, "HS256");

    return [
        "token"  => $token,
        "custid" => $cust["custid"],
        "nocust" => $cust["nocust"],
        "nmcust" => $cust["nmcust"],
        "kelas"  => $cust["kelas"],
    ];
}

function saveUploadedFile(string $nocust, string $jenisPrestasi, string $keterangan): string
{
    if (!isset($_FILES["file"]) || $_FILES["file"]["error"] !== UPLOAD_ERR_OK) {
        fail(422, "File wajib diupload");
    }

    $file = $_FILES["file"];
    $maxSize = 2 * 1024 * 1024;
    if ($file["size"] > $maxSize) {
        fail(422, "Ukuran file maksimal 2MB");
    }

    $allowedExt = ["png", "jpg", "jpeg", "pdf"];
    $ext = strtolower(pathinfo($file["name"], PATHINFO_EXTENSION));
    if (!in_array($ext, $allowedExt, true)) {
        fail(422, "Format file harus png/jpg/jpeg/pdf");
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file["tmp_name"]);
    finfo_close($finfo);

    $allowedMime = ["image/png", "image/jpeg", "application/pdf"];
    if (!in_array($mime, $allowedMime, true)) {
        fail(422, "Tipe file tidak valid");
    }

    $uploadRoot = trim((string) ($_ENV["UPLOAD_ABS_PATH"] ?? ""));
    if ($uploadRoot === "") {
        $uploadRoot = __DIR__ . "/public/uploads";
    }
    $uploadRoot = rtrim($uploadRoot, "/\\");

    $folder = $uploadRoot . "/" . $nocust;
    if (!is_dir($folder)) {
        if (!mkdir($folder, 0755, true) && !is_dir($folder)) {
            throw new RuntimeException("Gagal membuat folder upload: " . $folder);
        }
    }
    if (!is_writable($folder)) {
        throw new RuntimeException("Folder upload tidak bisa ditulis: " . $folder);
    }

    $baseName = slugify($jenisPrestasi) . "_" . slugify($keterangan);
    if ($baseName === "_" || $baseName === "") {
        $baseName = "prestasi";
    }
    $fileName = $baseName . "_" . time() . "." . $ext;
    $target = $folder . "/" . $fileName;

    if (!move_uploaded_file($file["tmp_name"], $target)) {
        throw new RuntimeException("Gagal menyimpan file upload");
    }

    $urlPrefix = trim((string) ($_ENV["UPLOAD_URL_PREFIX"] ?? "/uploads"));
    $relativePath = rtrim($urlPrefix, "/") . "/" . $nocust . "/" . $fileName;
    return buildPublicFileUrl($relativePath);
}

function doSubmitPrestasi(array $req, array $auth): array
{
    $jenisPrestasi    = trim((string) ($req["jenis_prestasi"] ?? ""));
    $keterangan       = trim((string) ($req["keterangan"] ?? ""));
    $nilaiPenghargaan = trim((string) ($req["nilai_penghargaan"] ?? ""));
    $tahunAkademik    = trim((string) ($req["tahun_akademik"] ?? ($req["bta"] ?? "")));

    if ($jenisPrestasi === "" || $keterangan === "" || $tahunAkademik === "") {
        fail(422, "Jenis prestasi, keterangan, dan tahun akademik wajib diisi");
    }

    $custId = (string) ($auth["custid"] ?? "");
    $nocust = (string) ($auth["nocust"] ?? "");
    $nmcust = (string) ($auth["nmcust"] ?? "");
    $kelas  = (string) ($auth["kelas"] ?? "");

    if ($custId === "" || $nocust === "") {
        fail(401, "Sesi tidak valid, silakan login ulang");
    }

    $url = saveUploadedFile($nocust, $jenisPrestasi, $keterangan);

    $pdo = dbConnectPdo();
    $sql = "
        INSERT INTO aka_reward
            (custid, nocust, nmcust, kelas, jenis_prestasi, keterangan, nilai_penghargaan, bta, url, isapproved, approveddate, approvedby, created_at, updated_at)
        VALUES
            (:custid, :nocust, :nmcust, :kelas, :jenis, :keterangan, :nilai, :bta, :url, 0, NULL, NULL, NOW(), NOW())
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(":custid", $custId, PDO::PARAM_STR);
    $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
    $stmt->bindValue(":nmcust", $nmcust, PDO::PARAM_STR);
    $stmt->bindValue(":kelas", $kelas, PDO::PARAM_STR);
    $stmt->bindValue(":jenis", $jenisPrestasi, PDO::PARAM_STR);
    $stmt->bindValue(":keterangan", $keterangan, PDO::PARAM_STR);
    $stmt->bindValue(":nilai", $nilaiPenghargaan, PDO::PARAM_STR);
    $stmt->bindValue(":bta", $tahunAkademik, PDO::PARAM_STR);
    $stmt->bindValue(":url", $url, PDO::PARAM_STR);
    $stmt->execute();

    return [
        "id"  => $pdo->lastInsertId(),
        "url" => $url,
    ];
}

function doGetTahunAkademik(): array
{
    $pdo = dbConnectPdo();
    $stmt = $pdo->prepare("SELECT thn_aka FROM mst_thn_aka ORDER BY urut ASC");
    $stmt->execute();
    $rows = $stmt->fetchAll();

    $result = [];
    foreach ($rows as $row) {
        $value = trim((string) ($row["thn_aka"] ?? ""));
        if ($value !== "") {
            $result[] = $value;
        }
    }

    return ["tahun_akademik" => $result];
}

loadEnv(__DIR__ . "/.env");

header("Content-Type: application/json; charset=utf-8");

$corsOrigin = (string) ($_ENV["CORS_ORIGIN"] ?? getenv("CORS_ORIGIN") ?: "*");
header("Access-Control-Allow-Origin: " . $corsOrigin);
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

if (($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS") {
    http_response_code(204);
    exit;
}

try {
    $req = getJsonInput();
    if (empty($req) && !empty($_POST)) {
        $req = $_POST;
    }

    $method = trim((string) ($req["method"] ?? ""));
    if ($method === "") $method = "login";

    if ($method === "login") {
        $data = doLogin($req);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $token = null;
    if (isset($req["token"]) && is_string($req["token"]) && $req["token"] !== "") {
        $token = $req["token"];
    } elseif (isset($_SERVER["HTTP_AUTHORIZATION"])) {
        $authHeader = $_SERVER["HTTP_AUTHORIZATION"];
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $token = $matches[1];
        }
    }

    if (!$token) {
        fail(401, "Token wajib diisi");
    }

    $jwt = new JWT();
    $key = (string) ($_ENV["JWT_KEY"] ?? "");
    if ($key === "") {
        fail(500, "JWT_KEY belum di set");
    }

    try {
        $decoded = $jwt->decode($token, $key, ["HS256"]);
        if (is_object($decoded)) $decoded = (array) $decoded;
    } catch (Throwable $e) {
        fail(401, "Token JWT tidak valid");
    }

    if ($method === "getTahunAkademik") {
        $data = doGetTahunAkademik();
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "submitPrestasi") {
        $data = doSubmitPrestasi($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    fail(422, "Metode '$method' tidak valid");
} catch (Throwable $e) {
    writeLog([
        "level" => "ERROR",
        "event" => "EXCEPTION",
        "type" => get_class($e),
        "message" => $e->getMessage(),
        "file" => $e->getFile(),
        "line" => $e->getLine()
    ]);

    http_response_code(500);
    echo json_encode(["status" => 500, "message" => "Terjadi kesalahan: " . $e->getMessage()], JSON_UNESCAPED_UNICODE);
    exit;
}
