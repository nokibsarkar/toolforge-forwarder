<?php

declare(strict_types=1);

const UPSTREAM_API = 'https://commons.wikimedia.org/w/api.php';


$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$queryString = $_SERVER['QUERY_STRING'] ?? '';

$upstreamUrl = UPSTREAM_API;
if ($queryString !== '') {
    $upstreamUrl .= '?' . $queryString;
}

$requestBody = file_get_contents('php://input');
if ($requestBody === false) {
    $requestBody = '';
}

$curl = curl_init($upstreamUrl);

if ($curl === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Failed to initialize cURL';
    exit;
}

$requestHeaders = buildForwardHeaders();

curl_setopt_array($curl, [
    CURLOPT_CUSTOMREQUEST => $method,
    CURLOPT_HTTPHEADER => $requestHeaders,

    // Keep upstream redirects transparent.
    CURLOPT_FOLLOWLOCATION => false,

    // Stream response body directly.
    CURLOPT_RETURNTRANSFER => false,

    // Verify Wikimedia HTTPS normally.
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,

    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 120,

    CURLOPT_HEADERFUNCTION => function ($curl, string $headerLine): int {
        $length = strlen($headerLine);
        $line = trim($headerLine);

        if ($line === '') {
            return $length;
        }

        if (preg_match('#^HTTP/\S+\s+(\d{3})#i', $line, $matches)) {
            http_response_code((int) $matches[1]);
            return $length;
        }

        $parts = explode(':', $line, 2);
        if (count($parts) !== 2) {
            return $length;
        }

        $name = trim($parts[0]);
        $value = trim($parts[1]);

        if (shouldDropResponseHeader($name)) {
            return $length;
        }

        header($name . ': ' . $value, false);

        return $length;
    },

    CURLOPT_WRITEFUNCTION => function ($curl, string $data): int {
        echo $data;
        return strlen($data);
    },
]);

if ($method === 'HEAD') {
    curl_setopt($curl, CURLOPT_NOBODY, true);
} elseif (requestMayHaveBody($method)) {
    curl_setopt($curl, CURLOPT_POSTFIELDS, $requestBody);
}

$ok = curl_exec($curl);

if ($ok === false) {
    if (!headers_sent()) {
        http_response_code(502);
        header('Content-Type: text/plain; charset=utf-8');
    }

    echo 'Upstream request failed: ' . curl_error($curl);
}

curl_close($curl);

function buildForwardHeaders(): array
{
    $forwardHeaders = [];

    foreach (getRequestHeadersCompat() as $name => $value) {
        if (shouldDropRequestHeader($name)) {
            continue;
        }

        // Force the correct upstream host.
        if (strcasecmp($name, 'Host') === 0) {
            continue;
        }

        // Let cURL calculate this after CURLOPT_POSTFIELDS.
        if (strcasecmp($name, 'Content-Length') === 0) {
            continue;
        }

        $forwardHeaders[] = $name . ': ' . $value;
    }

    $forwardHeaders[] = 'Host: commons.wikimedia.org';

    return $forwardHeaders;
}

function getRequestHeadersCompat(): array
{
    $headers = [];

    if (function_exists('getallheaders')) {
        $all = getallheaders();

        if (is_array($all)) {
            foreach ($all as $name => $value) {
                if (is_string($name) && is_string($value)) {
                    $headers[$name] = $value;
                }
            }
        }
    }

    foreach ($_SERVER as $key => $value) {
        if (!is_string($value)) {
            continue;
        }

        if (str_starts_with($key, 'HTTP_')) {
            $name = substr($key, 5);
            $name = str_replace('_', '-', strtolower($name));
            $name = implode('-', array_map('ucfirst', explode('-', $name)));

            if (!isset($headers[$name])) {
                $headers[$name] = $value;
            }
        }
    }

    if (isset($_SERVER['CONTENT_TYPE']) && !isset($headers['Content-Type'])) {
        $headers['Content-Type'] = (string) $_SERVER['CONTENT_TYPE'];
    }

    if (isset($_SERVER['CONTENT_LENGTH']) && !isset($headers['Content-Length'])) {
        $headers['Content-Length'] = (string) $_SERVER['CONTENT_LENGTH'];
    }

    // Important for OAuth/Bearer forwarding.
    if (isset($_SERVER['HTTP_AUTHORIZATION']) && !isset($headers['Authorization'])) {
        $headers['Authorization'] = (string) $_SERVER['HTTP_AUTHORIZATION'];
    } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) && !isset($headers['Authorization'])) {
        $headers['Authorization'] = (string) $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }

    return $headers;
}

function requestMayHaveBody(string $method): bool
{
    return !in_array($method, ['GET', 'HEAD'], true);
}

function shouldDropRequestHeader(string $name): bool
{
    $name = strtolower($name);

    return in_array($name, [
        // Your forwarder-only auth header. Never send this to Commons.
        'x-nokib-auth',

        // Hop-by-hop headers.
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',

        // Common IP/proxy-chain revealing headers.
        'x-forwarded-for',
        'x-real-ip',
        'forwarded',
        'x-client-ip',
        'client-ip',
        'true-client-ip',
        'cf-connecting-ip',
        'fastly-client-ip',
        'x-cluster-client-ip',
        'x-original-forwarded-for',
        'x-forwarded',
        'x-forwarded-host',
        'x-forwarded-proto',
        'x-forwarded-server',
        'via',
    ], true);
}

function shouldDropResponseHeader(string $name): bool
{
    $name = strtolower($name);

    return in_array($name, [
        // Hop-by-hop response headers.
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
    ], true);
}