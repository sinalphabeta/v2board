<?php

namespace App\Http\Middleware;

use App\Services\RiskService;
use Closure;
use Illuminate\Support\Facades\RateLimiter;

class RiskApiKey
{
    public function handle($request, Closure $next)
    {
        $provided = (string)$request->header('X-API-Key', '');
        $stored = (string)config('risk.api_key_hash', '');
        if ($provided && $stored && hash_equals($stored, hash('sha256', $provided))) {
            // The valid key has its own quota, so failed attempts from others can't use it up
            if (RateLimiter::tooManyAttempts('risk-api:valid-key', 60)) abort(429, 'Too many requests');
            RateLimiter::hit('risk-api:valid-key', 60);
            return $next($request);
        }
        $key = 'risk-api:failed:' . (new RiskService())->clientIp($request);
        if (RateLimiter::tooManyAttempts($key, 10)) abort(429, 'Too many requests');
        RateLimiter::hit($key, 60);
        abort(401, 'Invalid API key');
    }
}
