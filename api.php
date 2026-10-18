<?php
declare(strict_types=1);

// ---- 設定 ----------------------------------------------------
const DEFAULT_PASSWORD = 'beauty123'; // 初回のみ使用。ログイン後すぐ変更してください
const MAX_RANGE = 1000;
// 設定の保存先。可能なら公開ディレクトリの「外」に変更してください
$DATA_DIR = __DIR__ . '/data';
// --------------------------------------------------------------

session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => !empty($_SERVER['HTTPS'])]);
session_start();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function out(array $d, int $code = 200): void { http_response_code($code); echo json_encode($d, JSON_UNESCAPED_UNICODE); exit; }
function readJson(string $f, array $def): array { if (!is_file($f)) return $def; $j = json_decode((string)file_get_contents($f), true); return is_array($j) ? $j : $def; }
function writeJson(string $f, array $d): bool { return file_put_contents($f, json_encode($d, JSON_UNESCAPED_UNICODE), LOCK_EX) !== false; }

if (!is_dir($DATA_DIR)) { @mkdir($DATA_DIR, 0755, true); }
if (!is_file($DATA_DIR . '/.htaccess')) { @file_put_contents($DATA_DIR . '/.htaccess', "Require all denied\n"); }
$SETTINGS = $DATA_DIR . '/settings.json';
$AUTH     = $DATA_DIR . '/auth.json';
$FAILS    = $DATA_DIR . '/fails.json';

$action = $_GET['action'] ?? '';
$isPost = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';
$body = [];
if ($isPost) {
    // JSON以外は拒否（他サイトからのフォーム送信対策）
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) out(['ok' => false, 'error' => 'bad_request'], 400);
    $body = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($body)) $body = [];
}
$authed = !empty($_SESSION['admin']);

switch ($action) {
    case 'settings': // 誰でも取得可
        $s = readJson($SETTINGS, []);
        out(['ok' => true, 'min' => (int)($s['min'] ?? 1), 'max' => (int)($s['max'] ?? 10), 'nr' => (bool)($s['nr'] ?? false)]);

    case 'login':
        if (!$isPost) out(['ok' => false], 405);
        $ip = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? '');
        $fails = readJson($FAILS, []);
        $now = time();
        foreach ($fails as $k => $v) { if ($now - (int)($v['t'] ?? 0) > 600) unset($fails[$k]); }
        if ((int)($fails[$ip]['n'] ?? 0) >= 5) out(['ok' => false, 'error' => 'locked'], 429);
        $a = readJson($AUTH, []);
        $hash = $a['hash'] ?? password_hash(DEFAULT_PASSWORD, PASSWORD_DEFAULT);
        if (password_verify((string)($body['password'] ?? ''), $hash)) {
            unset($fails[$ip]); writeJson($FAILS, $fails);
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            out(['ok' => true]);
        }
        $fails[$ip] = ['n' => (int)($fails[$ip]['n'] ?? 0) + 1, 't' => $now];
        writeJson($FAILS, $fails);
        sleep(1);
        out(['ok' => false, 'error' => 'invalid'], 401);

    case 'save':
        if (!$isPost) out(['ok' => false], 405);
        if (!$authed) out(['ok' => false, 'error' => 'unauthorized'], 401);
        $min = filter_var($body['min'] ?? null, FILTER_VALIDATE_INT);
        $max = filter_var($body['max'] ?? null, FILTER_VALIDATE_INT);
        if ($min === false || $max === false) out(['ok' => false, 'error' => 'invalid'], 400);
        if ($min > $max) { [$min, $max] = [$max, $min]; }
        if ($max - $min + 1 > MAX_RANGE) out(['ok' => false, 'error' => 'too_many'], 400);
        if (!writeJson($SETTINGS, ['min' => $min, 'max' => $max, 'nr' => !empty($body['nr'])])) out(['ok' => false, 'error' => 'write'], 500);
        out(['ok' => true]);

    case 'changepw':
        if (!$isPost) out(['ok' => false], 405);
        if (!$authed) out(['ok' => false, 'error' => 'unauthorized'], 401);
        $pw = (string)($body['password'] ?? '');
        if (mb_strlen($pw) < 6) out(['ok' => false, 'error' => 'short'], 400);
        if (!writeJson($AUTH, ['hash' => password_hash($pw, PASSWORD_DEFAULT)])) out(['ok' => false, 'error' => 'write'], 500);
        out(['ok' => true]);

    case 'logout':
        $_SESSION = [];
        session_destroy();
        out(['ok' => true]);

    default:
        out(['ok' => false, 'error' => 'not_found'], 404);
}
