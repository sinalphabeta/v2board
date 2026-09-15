<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\RateLimiter;

class RiskApiKey
{
    public function handle($request, Closure $next)
    {
        $key = 'risk-api:' . ($request->server('REMOTE_ADDR') ?: $request->ip() ?: 'unknown');
        if (RateLimiter::tooManyAttempts($key, 60)) abort(429, 'Too many requests');
        RateLimiter::hit($key, 60);
        $provided = (string)$request->header('X-API-Key', '');
        $stored = (string)config('risk.api_key_hash', '');
        if (!$provided || !$stored || !hash_equals($stored, hash('sha256', $provided))) abort(401, 'Invalid API key');
        return $next($request);
    }
}
