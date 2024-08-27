<?php

namespace App\Http\Controllers;

use App\Models\UserProfile;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Facades\JWTFactory;

class APIController extends Controller
{

    public function getPromotion()
    {
        $promotion = DB::table('promotions')->get();
        $jsonData = json_encode($promotion);
        $data = $this->encryptAESCryptoJS($jsonData, env('PRIVATE_KEY_API'));
        $decrypt = $this->decryptAESCryptoJS($data, env('PRIVATE_KEY_API'));
        return response()->json([
            'success' => true,
            'message' => 'Success Get Promotion',
            'data' => $data,
        ]);
    }
    public function list_branches()
    {
        $listBranches = DB::table('list_branches')->get();
        $jsonData = json_encode($listBranches);
        $data = $this->encryptAESCryptoJS($jsonData, env('PRIVATE_KEY_API'));
        $decrypt = $this->decryptAESCryptoJS($data, env('PRIVATE_KEY_API'));
        return response()->json([
            'success' => true,
            'message' => 'Success Get List Branch',
            'data' => $data,
        ]);
    }


    public function user_profile_store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'type' => 'required',
        ]);

        if ($validator->fails()) {
            $errors = collect($validator->errors())->map(function ($messages) {
                return $messages[0];
            });
            return response()->json([
                'success' => false,
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
                        'success' => false,
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

                $jsonData = json_encode($userProfile);
                $data = $this->encryptAESCryptoJS($jsonData, env('PRIVATE_KEY_API'));
                $decrypt = $this->decryptAESCryptoJS($data, env('PRIVATE_KEY_API'));

                return response()->json([
                    'success' => true,
                    'message' => 'Added User Profile Successfully',
                    'data' => $data,
                    'decrypt' => $decrypt
                ], 200);
            } else {
                if (!$existingUserProfile) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Profile not found'
                    ], 404);
                }
                $existingUserProfile->update([
                    'gender' => $request->gender,
                    'usia' => $request->usia,
                    'group_id' => $request->group_id,
                    'policy_no' => $request->policy_no
                ]);

                $jsonData = json_encode($existingUserProfile);
                $data = $this->encryptAESCryptoJS($jsonData, env('PRIVATE_KEY_API'));
                $decrypt = $this->decryptAESCryptoJS($data, env('PRIVATE_KEY_API'));

                return response()->json([
                    'success' => true,
                    'message' => 'Updated User Profile Successfully',
                    'data' => $data,
                    'decrypt' => $decrypt
                ], 200);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'success' => false,
                'message' => $th->getMessage(),
            ]);
        }
    }

    public function getToken(Request $request)
    {
        $credentials = $request->only('email', 'password');
        $user = DB::table('users')->where('email', $credentials['email'])
            ->where('role', 'api-user')
            ->first();
        if (!$user || !Hash::check($credentials['password'], $user->password)) {
            return response()->json(['success' => false, 'message' => 'Unauthorized'], 401);
        }
        if ($request->secret_key != env('SECRET_KEY_API')) {
            return response()->json(['success' => false, 'message' => 'Invalid secret key'], 403);
        }

        $payload = JWTAuth::factory()->customClaims([
            'sub' => $user->id,
            'iat' => now()->timestamp,
            'exp' => now()->addMinutes(60)->timestamp,
        ])->make();

        $token = JWTAuth::encode($payload)->get();

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => 60 * 60,
        ]);
    }


    public function encryptAESCryptoJS($plainText, $passphrase)
    {
        try {
            $salt = $this->genRandomWithNonZero(8);
            list($key, $iv) = $this->deriveKeyAndIV($passphrase, $salt);

            $encrypted = openssl_encrypt($plainText, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            $encryptedBytesWithSalt = "Salted__" . $salt . $encrypted;

            return base64_encode($encryptedBytesWithSalt);
        } catch (Exception $e) {
            throw $e;
        }
    }

    public function decryptAESCryptoJS($encrypted, $passphrase)
    {
        try {
            $encryptedBytesWithSalt = base64_decode($encrypted);

            $salt = substr($encryptedBytesWithSalt, 8, 8);
            $encryptedBytes = substr($encryptedBytesWithSalt, 16);

            list($key, $iv) = $this->deriveKeyAndIV($passphrase, $salt);

            $decrypted = openssl_decrypt($encryptedBytes, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            return $decrypted;
        } catch (Exception $e) {
            throw $e;
        }
    }

    public function deriveKeyAndIV($passphrase, $salt)
    {
        $password = $passphrase;
        $concatenatedHashes = '';
        $currentHash = '';
        $enoughBytesForKey = false;

        while (!$enoughBytesForKey) {
            if (!empty($currentHash)) {
                $preHash = $currentHash . $password . $salt;
            } else {
                $preHash = $password . $salt;
            }

            $currentHash = md5($preHash, true);
            $concatenatedHashes .= $currentHash;

            if (strlen($concatenatedHashes) >= 48) {
                $enoughBytesForKey = true;
            }
        }

        $keyBytes = substr($concatenatedHashes, 0, 32);
        $ivBytes = substr($concatenatedHashes, 32, 16);

        return array($keyBytes, $ivBytes);
    }

    public function genRandomWithNonZero($seedLength)
    {
        $uint8list = '';
        for ($i = 0; $i < $seedLength; $i++) {
            $uint8list .= chr(random_int(1, 245));
        }
        return $uint8list;
    }
}
