<?php

declare(strict_types=1);

use pocketmine\nethernet\crypto\Base64Url;
use pocketmine\nethernet\identity\IdentityAssertion;
use pocketmine\nethernet\identity\JsonWebSignature;
use pocketmine\nethernet\identity\JsonWebToken;
use pocketmine\nethernet\identity\ServerIdentity;
use pocketmine\nethernet\sdp\Fingerprint;

if (PHP_VERSION_ID < 80400 || PHP_INT_SIZE !== 8 || $argc !== 2) {
    fwrite(STDERR, "Usage: php tools/generate_issuer_fixtures.php NETHERNET_DIR\nRequires 64-bit PHP 8.4, OpenSSL and Git\n");
    exit(2);
}
$directory = $argv[1];
$revision = '6ecacdaed3b0605a6a523235e5536f9c09ea56fd';
function gitOutput(string $directory, array $arguments): string {
    $process = proc_open(['git', '-C', $directory, ...$arguments], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Cannot start Git');
    }
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    if (proc_close($process) !== 0) {
        throw new RuntimeException('Git verification failed: ' . $error);
    }
    return trim($output);
}
if (gitOutput($directory, ['rev-parse', 'HEAD']) !== $revision || gitOutput($directory, ['status', '--porcelain', '--untracked-files=all']) !== '') {
    throw new RuntimeException('NetherNet must be clean at the recorded default-branch revision');
}
spl_autoload_register(static function (string $class) use ($directory): void {
    $prefix = 'pocketmine\\nethernet\\';
    if (!str_starts_with($class, $prefix)) {
        throw new RuntimeException('Unexpected oracle dependency: ' . $class);
    }
    $relative = substr($class, strlen($prefix));
    if (preg_match('/^(?:(?:identity|crypto)\\\\[A-Za-z][A-Za-z0-9]*|sdp\\\\(?:Fingerprint|SdpException)|NetherNetException)$/D', $relative) !== 1) {
        throw new RuntimeException('Unexpected oracle dependency: ' . $class);
    }
    require $directory . '/src/' . str_replace('\\', '/', $relative) . '.php';
});

// The ephemeral oracle key never leaves this process. Fixtures retain public
// keys and valid signatures, allowing serialization tests to replay signatures
// only when their complete signing input matches the independent source bytes.
$identity = ServerIdentity::generate();
$public = $identity->getPublicKey();
$details = openssl_pkey_get_details($identity->getPrivateKey());
if (!is_array($details) || !isset($details['ec']['x'], $details['ec']['y'])) {
    throw new RuntimeException('Cannot read synthetic public coordinates');
}
$jwk = ['kty' => 'EC', 'crv' => 'P-384',
    'x' => Base64Url::encode(str_pad($details['ec']['x'], 48, "\x00", STR_PAD_LEFT)),
    'y' => Base64Url::encode(str_pad($details['ec']['y'], 48, "\x00", STR_PAD_LEFT))];
$fingerprint = Fingerprint::parse('sha-256 ' . implode(':', array_map(static fn(int $value): string => sprintf('%02X', $value), range(0, 31))));
$payload = $fingerprint->toCanonicalPayload();
$multiple = json_encode(['fingerprint' => [
    ['algorithm' => 'sha-256', 'digest' => $fingerprint->getDigest()],
    ['algorithm' => 'SHA-256', 'digest' => $fingerprint->getDigest()],
]], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
$cases = [];
foreach ([
    ['legacy', 'legacy_der', 1000, 60, 'self', $payload],
    ['jwk', 'jwk', 1000, 60, 'self', $payload],
    ['escaped_domain', 'jwk', 1000, 60, "synthetic/\"\\\n\x00é🟪\u{2028}", $payload],
    ['minimum_lifetime', 'jwk', 1000, 1, 'synthetic.example', $payload],
    ['negative_clock', 'legacy_der', -1, 1, 'self', $payload],
    ['upper_clock', 'jwk', PHP_INT_MAX - 60, 60, 'self', $payload],
    ['multiple_fingerprints', 'jwk', 1000, 60, 'self', $multiple],
    ['empty_crypto_payload', 'legacy_der', 1000, 60, 'self', ''],
] as [$name, $encoding, $now, $lifetime, $domain, $currentPayload]) {
    $token = JsonWebToken::create(['x5u' => $public->toBase64Der()],
        ['exp' => $now + $lifetime, 'iat' => $now, 'cpk' => $encoding === 'jwk' ? $jwk : $public->toBase64Der()], $identity);
    $proof = JsonWebSignature::signDetached($currentPayload, $identity);
    $assertion = IdentityAssertion::create($domain, $token, $proof);
    $tokenParts = explode('.', $token->toString());
    $proofParts = explode('.', $proof);
    if (!$token->isSignedBy($public) || !JsonWebSignature::verifyDetached($proof, $currentPayload, $public)) {
        throw new RuntimeException('Oracle rejected its issued signatures');
    }
    $cases[] = ['name' => $name, 'encoding' => $encoding, 'now' => $now, 'lifetime' => $lifetime,
        'domain' => $domain, 'payload_hex' => bin2hex($currentPayload),
        'public_key_der_hex' => bin2hex(base64_decode($public->toBase64Der(), true)),
        'token_input_hex' => bin2hex($tokenParts[0] . '.' . $tokenParts[1]),
        'token_signature_hex' => bin2hex(Base64Url::decode($tokenParts[2])),
        'proof_input_hex' => bin2hex($proofParts[0] . '.' . Base64Url::encode($currentPayload)),
        'proof_signature_hex' => bin2hex(Base64Url::decode($proofParts[2])), 'attribute' => $assertion->encode()];
}
$oracle = ['repository' => 'https://github.com/axolotl-pm/nethernet', 'branch' => 'master', 'revision' => $revision, 'license' => 'LGPL-3.0-or-later'];
$json = json_encode(['oracle' => $oracle, 'cases' => $cases], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
$output = __DIR__ . '/../src/transport/fixtures';
if (file_put_contents($output . '/issuer.json', $json) !== strlen($json)) {
    throw new RuntimeException('Cannot write issuer fixtures');
}
$manifest = ['schema' => 1, 'oracle' => $oracle, 'php' => PHP_VERSION, 'generator_sha256' => hash_file('sha256', __FILE__),
    'cases' => count($cases), 'bytes' => strlen($json), 'sha256' => hash('sha256', $json)];
$manifestJson = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
if (file_put_contents($output . '/issuer-manifest.json', $manifestJson) !== strlen($manifestJson)) {
    throw new RuntimeException('Cannot write issuer fixture manifest');
}
echo 'Generated ' . count($cases) . " independent assertion issuance cases\n";
