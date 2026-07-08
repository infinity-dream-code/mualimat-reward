<?php
error_reporting(E_ALL);
ini_set("display_errors", "0");
ini_set("log_errors", "1");
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
        "message" => "Konfigurasi server belum lengkap",
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

const SECURE_INPUT_MAX_UPLOAD_BYTES = 2097152;

const SECURE_INPUT_DANGEROUS_EXT = [
    'php',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php7',
    'php8',
    'phar',
    'phps',
    'cgi',
    'pl',
    'py',
    'rb',
    'exe',
    'dll',
    'so',
    'sh',
    'bash',
    'bat',
    'cmd',
    'com',
    'js',
    'mjs',
    'html',
    'htm',
    'xhtml',
    'svg',
    'asp',
    'aspx',
    'jsp',
    'htaccess',
    'ini',
    'config',
    'shtml',
    'war',
    'jar',
];

const SECURE_INPUT_ALLOWED_METHODS = ['login', 'getTahunAkademik', 'submitPrestasi'];

function secure_sanitize_basename(string $filename): string
{
    $filename = str_replace(["\0", '\\'], ['', '/'], $filename);
    $filename = basename($filename);
    return trim($filename);
}

function secure_filename_has_dangerous_part(string $filename): bool
{
    $filename = strtolower(secure_sanitize_basename($filename));
    if ($filename === '') {
        return true;
    }

    $parts = explode('.', $filename);
    foreach ($parts as $part) {
        if ($part === '' || in_array($part, SECURE_INPUT_DANGEROUS_EXT, true)) {
            return true;
        }
    }

    return false;
}

/**
 * @return array{valid: bool, ext: string, error: string}
 */
function secure_inspect_upload(string $tmpPath, string $originalName, int $size): array
{
    $fail = static function (string $error): array {
        return ['valid' => false, 'ext' => '', 'error' => $error];
    };

    if ($size <= 0) {
        return $fail('File wajib diupload');
    }
    if ($size > SECURE_INPUT_MAX_UPLOAD_BYTES) {
        return $fail('Ukuran file maksimal 2MB');
    }
    if (!is_readable($tmpPath)) {
        return $fail('File upload tidak valid');
    }

    $originalName = secure_sanitize_basename($originalName);
    if ($originalName === '' || secure_filename_has_dangerous_part($originalName)) {
        return $fail('Nama file tidak valid');
    }

    $clientExt = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    if (!in_array($clientExt, ['png', 'jpg', 'jpeg', 'pdf'], true)) {
        return $fail('Format file harus PNG, JPG, atau PDF');
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        return $fail('File upload tidak valid');
    }
    $mime = (string) finfo_file($finfo, $tmpPath);
    finfo_close($finfo);

    $ext = '';
    if ($mime === 'image/png') {
        $info = @getimagesize($tmpPath);
        if ($info === false || ($info[2] ?? 0) !== IMAGETYPE_PNG) {
            return $fail('File gambar tidak valid');
        }
        $ext = 'png';
    } elseif ($mime === 'image/jpeg') {
        $info = @getimagesize($tmpPath);
        if ($info === false || ($info[2] ?? 0) !== IMAGETYPE_JPEG) {
            return $fail('File gambar tidak valid');
        }
        $ext = 'jpg';
    } elseif ($mime === 'application/pdf') {
        $handle = fopen($tmpPath, 'rb');
        if ($handle === false) {
            return $fail('File upload tidak valid');
        }
        $header = (string) fread($handle, 5);
        fclose($handle);
        if ($header !== '%PDF-') {
            return $fail('File PDF tidak valid');
        }
        $ext = 'pdf';
    } else {
        return $fail('Tipe file tidak valid');
    }

    if ($clientExt === 'pdf' && $ext !== 'pdf') {
        return $fail('Tipe file tidak valid');
    }
    if (in_array($clientExt, ['png', 'jpg', 'jpeg'], true) && !in_array($ext, ['png', 'jpg'], true)) {
        return $fail('Tipe file tidak valid');
    }

    return ['valid' => true, 'ext' => $ext, 'error' => ''];
}

function secure_validate_method(string $method): ?string
{
    $method = trim($method);
    return in_array($method, SECURE_INPUT_ALLOWED_METHODS, true) ? $method : null;
}

function secure_validate_username(string $username): ?string
{
    $username = trim($username);
    if ($username === '' || strlen($username) > 50) {
        return null;
    }
    if (!preg_match('/^[a-zA-Z0-9._@-]+$/', $username)) {
        return null;
    }
    return $username;
}

function secure_validate_password(string $password): ?string
{
    if ($password === '' || strlen($password) > 128) {
        return null;
    }
    if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $password)) {
        return null;
    }
    return $password;
}

function secure_validate_token_format(string $token): bool
{
    $token = trim($token);
    if ($token === '' || strlen($token) > 4096) {
        return false;
    }

    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }

    foreach ($parts as $part) {
        if ($part === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $part)) {
            return false;
        }
    }

    return true;
}

function secure_validate_text_field(string $value, int $maxLength, int $minLength = 1): ?string
{
    $value = trim($value);
    if (strlen($value) < $minLength || strlen($value) > $maxLength) {
        return null;
    }
    if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value)) {
        return null;
    }
    if (preg_match('/<[^>]*>/', $value)) {
        return null;
    }
    return $value;
}

function secure_validate_nilai_penghargaan(string $value): ?string
{
    $value = trim(str_replace(',', '.', $value));
    if ($value === '') {
        return '0.00';
    }
    if (!preg_match('/^\d{1,13}(\.\d{1,2})?$/', $value)) {
        return null;
    }

    return number_format((float) $value, 2, '.', '');
}

function secure_validate_tahun_akademik(string $value): ?string
{
    $value = trim($value);
    if (!preg_match('/^\d{4}\/\d{4}$/', $value)) {
        return null;
    }

    [$start, $end] = array_map('intval', explode('/', $value));
    if ($end !== $start + 1) {
        return null;
    }

    return $value;
}

function secure_validate_nocust(string $nocust): bool
{
    return (bool) preg_match('/^[a-zA-Z0-9._-]{1,50}$/', $nocust);
}

function secure_validate_upload_url(string $url, array $allowedHosts = []): bool
{
    $url = trim($url);
    if ($url === '' || strlen($url) > 2048) {
        return false;
    }

    $parsed = parse_url($url);
    if (!is_array($parsed)) {
        return false;
    }

    $scheme = strtolower((string) ($parsed['scheme'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true)) {
        return false;
    }

    $host = strtolower((string) ($parsed['host'] ?? ''));
    if ($host === '') {
        return false;
    }

    if ($allowedHosts !== []) {
        $allowed = array_map('strtolower', $allowedHosts);
        if (!in_array($host, $allowed, true)) {
            return false;
        }
    }

    $path = (string) ($parsed['path'] ?? '');
    if (
        str_contains($path, '..')
        || str_contains($path, '%')
        || str_contains($path, '\\')
        || !preg_match('#^/uploads/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+\.(png|jpg|pdf)$#', $path)
    ) {
        return false;
    }

    return true;
}

function secure_build_upload_filename(string $jenis, string $keterangan, string $ext): string
{
    $base = slugify_secure($jenis) . '_' . slugify_secure($keterangan);
    $base = trim($base, '_');
    if ($base === '') {
        $base = 'prestasi';
    }

    $base = substr($base, 0, 80);
    $suffix = time() . '_' . bin2hex(random_bytes(4));

    return $base . '_' . $suffix . '.' . $ext;
}

function slugify_secure(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace('/[^a-z0-9]+/', '_', $value);
    return trim((string) $value, '_');
}

function loadEnv(string $path): void
{
    if (!file_exists($path)) {
        http_response_code(500);
        echo json_encode(["status" => 500, "message" => "Konfigurasi server belum lengkap"], JSON_UNESCAPED_UNICODE);
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
    // multipart/form-data (upload) → field ada di $_POST, bukan php://input
    if (!empty($_POST)) {
        return $_POST;
    }

    $raw = file_get_contents("php://input");
    $json = json_decode($raw, true);
    return is_array($json) ? $json : [];
}

function dbConnectPdo(): PDO
{
    $host = (string) ($_ENV["DB_HOST"] ?? "");
    $user = (string) ($_ENV["DB_USERNAME"] ?? "");
    $pass = (string) ($_ENV["DB_PASSWORD"] ?? "");
    $port = (string) ($_ENV["DB_PORT"] ?? "3306");
    $name = (string) ($_ENV["DB_DATABASE"] ?? "");

    if ($host === "" || $user === "" || $name === "") {
        throw new RuntimeException("DB_UNAVAILABLE");
    }

    try {
        $conn = new conn();
        $pdo = $conn->DBConnect([
            "host" => $host,
            "user" => $user,
            "pass" => $pass,
            "port" => $port,
            "name" => $name,
        ]);
    } catch (Throwable) {
        throw new RuntimeException("DB_UNAVAILABLE");
    }

    if (!$pdo instanceof PDO) {
        throw new RuntimeException("DB_UNAVAILABLE");
    }

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
}

function ensureAutoIncrementInsert(PDO $pdo): void
{
    try {
        $mode = (string) $pdo->query("SELECT @@SESSION.sql_mode")->fetchColumn();
        $mode = trim((string) preg_replace('/\bNO_AUTO_VALUE_ON_ZERO\b,?/', '', $mode), ',');
        if ($mode !== '') {
            $pdo->exec("SET SESSION sql_mode = " . $pdo->quote($mode));
        }
    } catch (Throwable) {
        // Abaikan jika server tidak mengizinkan ubah sql_mode.
    }
}

function allocateRewardId(PDO $pdo): int
{
    $nextId = (int) $pdo->query("SELECT COALESCE(MAX(id), 0) + 1 FROM aka_reward")->fetchColumn();
    return max(1, $nextId);
}

function fetchLastRewardInsertId(PDO $pdo, string $custId, string $nocust, int $fallbackId = 0): int
{
    $insertId = (int) $pdo->lastInsertId();
    if ($insertId > 0) {
        return $insertId;
    }
    if ($fallbackId > 0) {
        return $fallbackId;
    }

    $stmt = $pdo->prepare("
        SELECT id FROM aka_reward
        WHERE custid = :custid AND nocust = :nocust
        ORDER BY created_at DESC, id DESC
        LIMIT 1
    ");
    $stmt->bindValue(":custid", $custId, PDO::PARAM_STR);
    $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
    $stmt->execute();

    return (int) ($stmt->fetchColumn() ?: 0);
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

function failSystem(int $code = 500): void
{
    fail($code, "Terjadi kesalahan sistem. Silakan coba lagi.");
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
    $username = secure_validate_username((string) ($req["username"] ?? ""));
    $password = secure_validate_password((string) ($req["password"] ?? ""));

    if ($username === null || $password === null) {
        fail(422, "Username atau password tidak valid");
    }

    $pdo = dbConnectPdo();

    $stmt = $pdo->prepare("SELECT * FROM `sholat_user` WHERE `username` = :username LIMIT 1");
    $stmt->bindValue(":username", $username, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch();

    if (!$user) {
        fail(401, "Username atau password salah");
    }

    if (!verifyPassword($password, (string) ($user["password"] ?? ""))) {
        fail(401, "Username atau password salah");
    }

    $cust = [
        "custid" => (string) ($user["idincrement"] ?? ""),
        "nocust" => trim((string) ($user["username"] ?? "")),
        "nmcust" => trim((string) ($user["nama"] ?? "")),
        "kelas"  => trim((string) ($user["role"] ?? "")),
    ];

    if ($cust["custid"] === "" || $cust["nocust"] === "") {
        fail(500, "Data akun tidak lengkap");
    }

    $jwt = new JWT();
    $key = (string) ($_ENV["JWT_KEY"] ?? "");
    if ($key === "") {
        throw new RuntimeException("CONFIG_ERROR");
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
    $inspected = secure_inspect_upload(
        (string) $file["tmp_name"],
        (string) ($file["name"] ?? ""),
        (int) ($file["size"] ?? 0)
    );
    if (!$inspected["valid"]) {
        fail(422, $inspected["error"] !== "" ? $inspected["error"] : "File upload tidak valid");
    }

    if (!secure_validate_nocust($nocust)) {
        fail(422, "Data upload tidak valid");
    }

    $uploadRoot = trim((string) ($_ENV["UPLOAD_ABS_PATH"] ?? ""));
    if ($uploadRoot === "") {
        $uploadRoot = __DIR__ . "/public/uploads";
    }
    $uploadRoot = rtrim($uploadRoot, "/\\");

    $folder = $uploadRoot . "/" . $nocust;
    if (!is_dir($folder)) {
        if (!mkdir($folder, 0755, true) && !is_dir($folder)) {
            throw new RuntimeException("UPLOAD_DIR_ERROR");
        }
    }
    if (!is_writable($folder)) {
        throw new RuntimeException("UPLOAD_DIR_ERROR");
    }

    $fileName = secure_build_upload_filename($jenisPrestasi, $keterangan, $inspected["ext"]);
    $target = $folder . "/" . $fileName;

    if (!move_uploaded_file($file["tmp_name"], $target)) {
        throw new RuntimeException("UPLOAD_SAVE_ERROR");
    }

    $urlPrefix = trim((string) ($_ENV["UPLOAD_URL_PREFIX"] ?? "/uploads"));
    $relativePath = rtrim($urlPrefix, "/") . "/" . $nocust . "/" . $fileName;
    return buildPublicFileUrl($relativePath);
}

function validatePrestasiInput(array $req): array
{
    $jenis = secure_validate_text_field((string) ($req["jenis_prestasi"] ?? ""), 150);
    $keterangan = secure_validate_text_field((string) ($req["keterangan"] ?? ""), 500);
    $nilai = secure_validate_nilai_penghargaan((string) ($req["nilai_penghargaan"] ?? ""));
    $tahun = secure_validate_tahun_akademik((string) ($req["tahun_akademik"] ?? ($req["bta"] ?? "")));

    if ($jenis === null || $keterangan === null || $tahun === null) {
        fail(422, "Data prestasi tidak valid");
    }
    if ($nilai === null) {
        fail(422, "Nilai penghargaan harus angka (maks. 2 desimal)");
    }

    return [
        "jenis_prestasi" => $jenis,
        "keterangan" => $keterangan,
        "nilai_penghargaan" => $nilai,
        "tahun_akademik" => $tahun,
    ];
}

function assertTahunAkademikExists(PDO $pdo, string $tahun): void
{
    $stmt = $pdo->prepare("SELECT 1 FROM mst_thn_aka WHERE thn_aka = :tahun LIMIT 1");
    $stmt->bindValue(":tahun", $tahun, PDO::PARAM_STR);
    $stmt->execute();
    if (!$stmt->fetchColumn()) {
        fail(422, "Tahun akademik tidak valid");
    }
}

function allowedUploadHosts(): array
{
    $hosts = [];
    $base = trim((string) ($_ENV["PUBLIC_BASE_URL"] ?? ""));
    if ($base !== "") {
        $host = parse_url($base, PHP_URL_HOST);
        if (is_string($host) && $host !== "") {
            $hosts[] = $host;
        }
    }
    $laravel = trim((string) ($_ENV["LARAVEL_APP_URL"] ?? ""));
    if ($laravel !== "") {
        $host = parse_url($laravel, PHP_URL_HOST);
        if (is_string($host) && $host !== "") {
            $hosts[] = $host;
        }
    }
    return array_values(array_unique($hosts));
}

function doSubmitPrestasi(array $req, array $auth): array
{
    $fields = validatePrestasiInput($req);

    $custId = (string) ($auth["custid"] ?? "");
    $nocust = (string) ($auth["nocust"] ?? "");
    $nmcust = (string) ($auth["nmcust"] ?? "");
    $kelas  = (string) ($auth["kelas"] ?? "");

    if ($custId === "" || $nocust === "" || !secure_validate_nocust($nocust)) {
        fail(401, "Sesi tidak valid, silakan login ulang");
    }

    $pdo = dbConnectPdo();
    ensureAutoIncrementInsert($pdo);
    assertTahunAkademikExists($pdo, $fields["tahun_akademik"]);

    $url = trim((string) ($req["url"] ?? ""));
    if ($url !== "") {
        if (!secure_validate_upload_url($url, allowedUploadHosts())) {
            fail(422, "URL bukti tidak valid");
        }
    } else {
        $url = saveUploadedFile($nocust, $fields["jenis_prestasi"], $fields["keterangan"]);
    }

    $rewardId = allocateRewardId($pdo);

    $sql = "
        INSERT INTO aka_reward
            (id, custid, nocust, nmcust, kelas, jenis_prestasi, keterangan, nilai_penghargaan, bta, url, isapproved, approveddate, approvedby, created_at, updated_at)
        VALUES
            (:id, :custid, :nocust, :nmcust, :kelas, :jenis, :keterangan, :nilai, :bta, :url, 0, NULL, NULL, NOW(), NOW())
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(":id", $rewardId, PDO::PARAM_INT);
    $stmt->bindValue(":custid", $custId, PDO::PARAM_STR);
    $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
    $stmt->bindValue(":nmcust", $nmcust, PDO::PARAM_STR);
    $stmt->bindValue(":kelas", $kelas, PDO::PARAM_STR);
    $stmt->bindValue(":jenis", $fields["jenis_prestasi"], PDO::PARAM_STR);
    $stmt->bindValue(":keterangan", $fields["keterangan"], PDO::PARAM_STR);
    $stmt->bindValue(":nilai", $fields["nilai_penghargaan"], PDO::PARAM_STR);
    $stmt->bindValue(":bta", $fields["tahun_akademik"], PDO::PARAM_STR);
    $stmt->bindValue(":url", $url, PDO::PARAM_STR);
    $stmt->execute();

    return [
        "id"  => fetchLastRewardInsertId($pdo, $custId, $nocust, $rewardId),
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

    $method = secure_validate_method(trim((string) ($req["method"] ?? "")));
    if ($method === null) {
        fail(422, "Permintaan tidak valid");
    }

    if ($method === "login") {
        $data = doLogin($req);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "getTahunAkademik") {
        $data = doGetTahunAkademik();
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

    if (!$token || !secure_validate_token_format($token)) {
        fail(401, "Token wajib diisi");
    }

    $jwt = new JWT();
    $key = (string) ($_ENV["JWT_KEY"] ?? "");
    if ($key === "") {
        failSystem(500);
    }

    try {
        $decoded = $jwt->decode($token, $key, ["HS256"]);
        if (is_object($decoded)) $decoded = (array) $decoded;
    } catch (Throwable $e) {
        fail(401, "Token JWT tidak valid");
    }

    if ($method === "submitPrestasi") {
        $data = doSubmitPrestasi($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    fail(422, "Permintaan tidak valid");
} catch (Throwable) {
    failSystem(500);
}
