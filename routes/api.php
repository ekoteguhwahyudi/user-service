<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::group(
    ['prefix' => 'user'],
    function () {
        Route::post('', [UserController::class, 'userDetail'])->name('user');
        Route::post('/saldo', [UserController::class, 'updateSaldo'])->name('user.saldo');
        Route::post('/level', [UserController::class, 'updateLevel'])->name('user.level');
    }
);
