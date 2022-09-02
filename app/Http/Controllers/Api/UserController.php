<?php

namespace App\Http\Controllers\Api;

use App\Models\UserDetail;
use App\Models\UserChannel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;
use App\Models\User;

class UserController extends Controller
{
    public function checkUser(Request $request)
    {
        $user_serial = $request->user_serial;
        $category = $request->category;
        if (empty($user_serial || empty($category))) {
            return response()->json([
                'status' => false,
                'message' => 'Parameter in valid'
            ], 500);
        }
        $auth = $request->header('Authorization');
        if ($auth != config('setting.secret_key')) {
            return response()->json([
                'status' => false,
                'message' => 'Authorization in valid'
            ], 500);
        }

        $user = UserChannel::leftJoin('users', 'user_serial', '=' , 'users.serial')
                ->where('user_serial', $user_serial)->where('category', $category)
                ->where('status', 1)->where('users.is_active', 1)->first(['serial', 'token']);

        if (! $user) {
            return response()->json([
                'status' => false,
                'message' => 'user not found'
            ], 500);
        }

        $data = [
            'serial' => $user->serial,
            'token' => $user->token
        ];

        // encrypt data
        $privateKey 	= $user_serial; // user serial
        $secretKey 		= config('app.secret_key_user'); // secret key
        $encryptMethod  = "AES-256-CBC";
        $string 		= json_encode($data); // value
        $key            = hash('sha256', $privateKey);
        $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
        $result = openssl_encrypt($string, $encryptMethod, $key, 0, $ivalue);
        $output = base64_encode($result);

        // decrypt data
        // $privateKey 	= $user_serial; // user define key
        // $secretKey 		= config('app.secret_key'); // user define secret key
        // $encryptMethod  = "AES-256-CBC";
        // $stringEncrypt  = $output; // user encrypt value
        // $key    = hash('sha256', $privateKey);
        // $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
        // $result = openssl_decrypt(base64_decode($stringEncrypt), $encryptMethod, $key, 0, $ivalue);

        return response()->json([
            'status' => true,
            'message' => 'success check user',
            'data' => $output
        ], 200);
    }
    public function userDetail(Request $request)
    {
        $token = $request->header('Authorization');
        $user = User::where('token', $token)->where('is_active', 1)->first();
        if (! $token || ! $user) {
            return response()->json([
                'status' => false,
                'message' => 'Token in valid'
            ], 500);
        }

        $detailUser = UserDetail::where('user_serial', $user->serial)->first(['user_serial', 'saldo', 'bonus', 'level']);
        if (! $detailUser) {
            return response()->json([
                'status' => false,
                'message' => 'Detail user not found'
            ], 500);
        }

        $data = [
            'user_serial' => $detailUser->user_serial,
            'saldo' => $detailUser->saldo,
            'bonus' => $detailUser->bonus,
            'level' => $detailUser->level,
        ];

        // encrypt data
        $privateKey 	= $detailUser->user_serial; // user serial
        $secretKey 		= config('app.secret_key_user'); // secret key
        $encryptMethod  = "AES-256-CBC";
        $string 		= json_encode($data); // value
        $key            = hash('sha256', $privateKey);
        $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
        $result = openssl_encrypt($string, $encryptMethod, $key, 0, $ivalue);
        $output = base64_encode($result);

        // decrypt data
        // $privateKey 	= $detailUser->user_serial; // user define key
        // $secretKey 		= config('app.secret_key'); // user define secret key
        // $encryptMethod  = "AES-256-CBC";
        // $stringEncrypt  = $output; // user encrypt value
        // $key    = hash('sha256', $privateKey);
        // $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
        // $result = openssl_decrypt(base64_decode($stringEncrypt), $encryptMethod, $key, 0, $ivalue);

        return response()->json([
            'status' => true,
            'message' => 'success detail user',
            'data' => $output
        ], 200);
    }
    public function updateSaldo(Request $request)
    {
        $param = $request->param;
        $nominal = (int) $request->nominal;
        $array = ['plus', 'minus'];
        if (! $nominal || ! $param || $nominal <= 0 || !in_array($param, $array)) {
            return response()->json([
                'status' => false,
                'message' => 'Parameter in valid'
            ], 500);
        }
        $token = $request->header('Authorization');
        $user = User::where('token', $token)->where('is_active', 1)->first();
        if (! $token || ! $user) {
            return response()->json([
                'status' => false,
                'message' => 'Token in valid'
            ], 500);
        }

        try {
            DB::beginTransaction();

            $detailUser = UserDetail::where('user_serial', $user->serial)->first();
            if (! $detailUser) {
                throw new \Exception('user not found');
            }
            if ($param == 'plus') {
                $detailUser->saldo += $nominal;
            } else {
                $detailUser->saldo -= $detailUser->saldo - $nominal;
            }
            if ($detailUser->saldo < 0) {
                throw new \Exception('saldo limit');
            }
            if ($nominal > config("setting.level.$detailUser->level") || $detailUser->saldo > config("setting.level.$detailUser->level")) {
                throw new \Exception('nominal limit');
            }
            if (!$detailUser->save()) {
                throw new \Exception('failed update saldo');
            }

            DB::commit();

            $data = [
                'user_serial' => $detailUser->user_serial,
                'saldo' => $detailUser->saldo,
                'bonus' => $detailUser->bonus,
                'level' => $detailUser->level,
            ];
            // encrypt data
            $privateKey 	= $detailUser->user_serial; // user serial
            $secretKey 		= config('app.secret_key_user'); // secret key
            $encryptMethod  = "AES-256-CBC";
            $string 		= json_encode($data); // value
            $key            = hash('sha256', $privateKey);
            $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
            $result = openssl_encrypt($string, $encryptMethod, $key, 0, $ivalue);
            $output = base64_encode($result);

            // decrypt data
            // $privateKey 	= $detailUser->user_serial; // user define key
            // $secretKey 		= config('app.secret_key'); // user define secret key
            // $encryptMethod  = "AES-256-CBC";
            // $stringEncrypt  = $output; // user encrypt value
            // $key    = hash('sha256', $privateKey);
            // $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
            // $result = openssl_decrypt(base64_decode($stringEncrypt), $encryptMethod, $key, 0, $ivalue);

            return response()->json([
                'status' => true,
                'message' => 'success',
                'data' => $output
            ], 200);

        } catch (\Exception$e) {
            DB::rollback();
            Log::error($e);
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ], 500);
        }     
    }
    public function updateLevel(Request $request)
    {
        $level = $request->level;
        $array = ['bronze', 'silver', 'gold', 'diamond', 'admin'];
        if (! $level || ! in_array($level, $array)) {
            return response()->json([
                'status' => false,
                'message' => 'Parameter in valid'
            ], 500);
        }
        $token = $request->header('Authorization');
        $user = User::where('token', $token)->where('is_active', 1)->first();
        if (! $token || ! $user) {
            return response()->json([
                'status' => false,
                'message' => 'Token in valid'
            ], 500);
        }

        try {
            DB::beginTransaction();

            $detailUser = UserDetail::where('user_serial', $user->serial)->first();
            if (! $detailUser) {
                throw new \Exception('user not found');
            }
            $detailUser->level = $level;
            if (!$detailUser->save()) {
                throw new \Exception('failed update saldo');
            }

            DB::commit();

            $data = [
                'user_serial' => $detailUser->user_serial,
                'saldo' => $detailUser->saldo,
                'bonus' => $detailUser->bonus,
                'level' => $detailUser->level,
            ];
            // encrypt data
            $privateKey 	= $detailUser->user_serial; // user serial
            $secretKey 		= config('app.secret_key_user'); // secret key
            $encryptMethod  = "AES-256-CBC";
            $string 		= json_encode($data); // value
            $key            = hash('sha256', $privateKey);
            $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
            $result = openssl_encrypt($string, $encryptMethod, $key, 0, $ivalue);
            $output = base64_encode($result);

            // decrypt data
            // $privateKey 	= $detailUser->user_serial; // user define key
            // $secretKey 		= config('app.secret_key'); // user define secret key
            // $encryptMethod  = "AES-256-CBC";
            // $stringEncrypt  = $output; // user encrypt value
            // $key    = hash('sha256', $privateKey);
            // $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
            // $result = openssl_decrypt(base64_decode($stringEncrypt), $encryptMethod, $key, 0, $ivalue);

            return response()->json([
                'status' => true,
                'message' => 'success',
                'data' => $output
            ], 200);

        } catch (\Exception$e) {
            DB::rollback();
            Log::error($e);
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ], 500);
        }     
    }
}
