<?php

use App\Models\UserProfile;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;

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
Route::post('/user-profile/store', function (Request $request) {
    $validator = Validator::make($request->all(), [
        'username' => 'required',
        'type' => 'required',
    ]);

    if ($validator->fails()) {
        $errors = collect($validator->errors())->map(function ($messages) {
            return $messages[0];
        });
        return response()->json([
            'status' => false,
            'errors' => $errors,
            'message' => 'Failed'
        ], 422);
    }

    $existingUserProfile = UserProfile::where('username', $request->username)->first();

    $addOrUpdate = $request->type;
    try {
        if ($addOrUpdate === 'add') {
            if ($existingUserProfile) {
                return response()->json([
                    'status' => false,
                    'message' => 'Username already exists'
                ], 400);
            }
            $userProfile = UserProfile::create([
                'username' => $request->username,
                'gender' => $request->gender,
                'usia' => $request->usia,
                'group_id' => $request->group_id,
                'policy_no' => $request->policy_no
            ]);
            return response()->json([
                'status' => true,
                'message' => 'Added User Profile Successfully',
                'data' => $userProfile
            ], 200);
        } else {
            if (!$existingUserProfile) {
                return response()->json([
                    'status' => false,
                    'message' => 'Profile not found'
                ], 404);
            }
            $existingUserProfile->update([
                'gender' => $request->gender,
                'usia' => $request->usia,
                'group_id' => $request->group_id,
                'policy_no' => $request->policy_no
            ]);
            return response()->json([
                'status' => true,
                'message' => 'Updated User Profile Successfully',
                'data' => $existingUserProfile
            ], 200);
        }
    } catch (\Throwable $th) {
        return response()->json([
            'status' => false,
            'message' => $th->getMessage(),
        ]);
    }
});

Route::get('/list-branches', function () {
    try {
        $listBranches = DB::table('list_branches')->get();
        return response()->json([
            'status' => true,
            'message' => 'Success Get List Branch',
            'data' => $listBranches,
        ]);
    } catch (\Exception $e) {
        return response()->json([
            'status' => false,
            'message' => 'Failed to Get List Branch',
            'error' => $e->getMessage(),
        ], 500);
    }
});
