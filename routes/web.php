<?php

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::get('/test', function () {
    $user_serial = 'ABC1234';
    $privateKey 	= $user_serial; // user serial
    $secretKey 		= 'qweasdzxc'; // secret key
    $encryptMethod  = "AES-256-CBC";
    $string 		= 'loket_pulsa'; // value


    $key = hash('sha256', $privateKey);
    $ivalue = substr(hash('sha256', $secretKey), 0, 16); // sha256 is hash_hmac_algo
    $result = openssl_encrypt($string, $encryptMethod, $key, 0, $ivalue);
    $output = base64_encode($result);  // output is a encripted value
    $signature = $output;
    
    $curl = curl_init();

    curl_setopt_array($curl, array(
    CURLOPT_URL => 'https://01ac-103-107-71-209.ngrok.io/api/game',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_CUSTOMREQUEST => 'POST',
    CURLOPT_POSTFIELDS =>'{
        "shortcode" : "xl5",
        "phone" : "081229889541",
        "channel" : "whatsapp",
        "serial" : "ABC1234"
    }',
    CURLOPT_HTTPHEADER => array(
        "Authorization: $secretKey",
        "signature: $signature",
        'Content-Type: application/json'
    ),
    ));

    $response = curl_exec($curl);

    curl_close($curl);
    dd($response);
});
