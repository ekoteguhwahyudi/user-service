<?php

namespace App\Http\Controllers\Api;

use App\Models\UserDetail;
use App\Models\UserChannel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\Controller;

class UserController extends Controller
{
    public function userDetail(Request $request)
    {
        $user_serial = $request->user_serial;
        $category = $request->category;
        $signature = $request->header('signature');
        $token = $request->header('Authorization');
        if ($token != config('setting.secret_key')) {
            return response()->json([
                'status' => false,
                'message' => 'Authorization in valid'
            ]);
        }

        $privateKey 	= $user_serial; // user define key
        $secretKey 		= config('setting.secret_key'); // user define secret key
        $encryptMethod  = "AES-256-CBC";
        $stringEncrypt  = $signature; // user encrypt value
        $key    = hash('sha256', $privateKey);
        $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
        $output = openssl_decrypt(base64_decode($stringEncrypt), $encryptMethod, $key, 0, $ivalue);

        if ($output != 'loket_pulsa') {
            return response()->json([
                'status' => false,
                'message' => 'signature in valid'
            ]);
        }

        $user = UserChannel::leftJoin('user_detail', 'serial', '=' , 'user_detail.user_serial')->where('category', $category)->where('user_serial', $user_serial)->where('status', 1)
                ->first(['description', 'user_detail.saldo', 'user_detail.bonus', 'user_detail.level', 'status', 'serial', 'category']);
        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'user not found'
            ]);
        }
        return response()->json([
            'status' => true,
            'message' => 'success',
            'data' => $user
        ]);
    }
    public function updateSaldo(Request $request)
    {
        $user_serial = $request->user_serial;
        $category = $request->category;
        $param = $request->param;
        $nominal = (int) $request->nominal;
        $signature = $request->header('signature');
        $token = $request->header('Authorization');
        if ($token != config('setting.secret_key')) {
            return response()->json([
                'status' => false,
                'message' => 'Authorization in valid'
            ]);
        }

        $privateKey 	= $user_serial; // user define key
        $secretKey 		= config('setting.secret_key'); // user define secret key
        $encryptMethod  = "AES-256-CBC";
        $stringEncrypt  = $signature; // user encrypt value
        $key    = hash('sha256', $privateKey);
        $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
        $output = openssl_decrypt(base64_decode($stringEncrypt), $encryptMethod, $key, 0, $ivalue);

        if ($output != 'loket_pulsa') {
            return response()->json([
                'status' => false,
                'message' => 'signature in valid'
            ]);
        }

        $array = ['plus', 'minus'];
        if (!$nominal || !$param || $nominal <= 0 || !in_array($param, $array)) {
            return response()->json([
                'status' => false,
                'message' => 'parameter in valid'
            ]);
        }

        $channel = UserChannel::leftJoin('user_detail', 'serial', '=' , 'user_detail.user_serial')->where('category', $category)->where('user_serial', $user_serial)->where('status', 1)
                ->first(['description', 'user_detail.saldo', 'user_detail.bonus', 'user_detail.level', 'status', 'serial', 'category']);
        if (!$channel) {
            return response()->json([
                'status' => false,
                'message' => 'user not found'
            ]);
        }
        try {
            DB::beginTransaction();

            $user = UserDetail::where('user_serial', $channel->serial)->first();
            if (!$user) {
                throw new \Exception('user not found');
            }
            if ($param == 'plus') {
                $user->saldo = $user->saldo + $nominal;
            } else {
                $user->saldo = $user->saldo - $nominal;
            }
            if ($user->saldo < 0) {
                throw new \Exception('saldo limit');
            }
            if ($nominal > config("setting.level.$user->level") || $user->saldo > config("setting.level.$user->level")) {
                throw new \Exception('nominal limit');
            }
            if (!$user->save()) {
                throw new \Exception('failed update saldo');
            }

            DB::commit();
            return response()->json([
                'status' => true,
                'message' => 'success',
                'data' => [
                    'user_serial' => $user->user_serial,
                    'saldo' => $user->saldo,
                    'bonus' => $user->bonus,
                    'level' => $user->level,
                ]
            ]);

        } catch (\Exception$e) {
            DB::rollback();
            Log::error($e);
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ]);
        }     
    }
    public function updateLevel(Request $request)
    {
        $user_serial = $request->user_serial;
        $category = $request->category;
        $level = $request->level;
        $signature = $request->header('signature');
        $token = $request->header('Authorization');
        if ($token != config('setting.secret_key')) {
            return response()->json([
                'status' => false,
                'message' => 'Authorization in valid'
            ]);
        }

        $privateKey 	= $user_serial; // user define key
        $secretKey 		= config('setting.secret_key'); // user define secret key
        $encryptMethod  = "AES-256-CBC";
        $stringEncrypt  = $signature; // user encrypt value
        $key    = hash('sha256', $privateKey);
        $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
        $output = openssl_decrypt(base64_decode($stringEncrypt), $encryptMethod, $key, 0, $ivalue);

        if ($output != 'loket_pulsa') {
            return response()->json([
                'status' => false,
                'message' => 'signature in valid'
            ]);
        }

        $array = ['bronze', 'silver', 'gold', 'diamond', 'admin'];
        if (!$level || !in_array($level, $array)) {
            return response()->json([
                'status' => false,
                'message' => 'parameter in valid'
            ]);
        }

        $channel = UserChannel::leftJoin('user_detail', 'serial', '=' , 'user_detail.user_serial')->where('category', $category)->where('user_serial', $user_serial)->where('status', 1)
                ->first(['description', 'user_detail.saldo', 'user_detail.bonus', 'user_detail.level', 'status', 'serial', 'category']);
        if (!$channel) {
            return response()->json([
                'status' => false,
                'message' => 'user not found'
            ]);
        }
        try {
            DB::beginTransaction();

            $user = UserDetail::where('user_serial', $channel->serial)->first();
            if (!$user) {
                throw new \Exception('user not found');
            }
            $user->level = $level;
            if (!$user->save()) {
                throw new \Exception('failed update saldo');
            }

            DB::commit();
            return response()->json([
                'status' => true,
                'message' => 'success',
                'data' => [
                    'user_serial' => $user->user_serial,
                    'saldo' => $user->saldo,
                    'bonus' => $user->bonus,
                    'level' => $user->level,
                ]
            ]);

        } catch (\Exception$e) {
            DB::rollback();
            Log::error($e);
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ]);
        }     
    }
}
