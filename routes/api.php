<?php

use App\Http\Controllers\APIController;
use App\Models\UserProfile;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Crypt;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('/get-token', [APIController::class, 'getToken']);
Route::post('/login', [APIController::class, 'login']);

Route::middleware('auth:api')->group(function () {
    Route::get('/list-branches', [APIController::class, 'list_branches']);
    Route::get('/promotions', [APIController::class, 'getPromotion']);
    Route::post('/user-profile-store', [APIController::class, 'user_profile_store']);
});
