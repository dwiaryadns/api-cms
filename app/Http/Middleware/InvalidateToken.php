<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Facades\JWTAuth;

class InvalidateToken
{
    public function handle($request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (\Exception $e) {
            return response()->json(['error' => 'Token is invalid'], 401);
        }
        $response = $next($request);
        JWTAuth::invalidate(JWTAuth::getToken());
        return $response;
    }
}
