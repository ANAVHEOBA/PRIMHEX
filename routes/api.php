<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\ApiController;

//Register
Route::post("register",[ApiController::class,"register"]);


//login
Route::post("login",[ApiController::class,"login"]);

// Password Reset Request
Route::post("password/reset-request", [ApiController::class, "passwordResetRequest"]);

Route::group([
    "middleware" => ["auth:sanctum"]
],function(){
       //profile
Route::get("profile",[ApiController::class,"profile"]);  

     //logout
     Route::get("logout",[ApiController::class,"logout"]); 

});



/*Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');*/


