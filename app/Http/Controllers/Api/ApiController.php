<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Log;

class ApiController extends Controller
{
    public function register(Request $request)
    {
        try {
            $validateUser = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required',
            ]);

            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            // Hash the password before storing it
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
            ]);

            return response()->json([
                'status' => true,
                'message' => 'User created successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500); // Added HTTP status code 500 for internal server error
        }
    }

    // Login section
    public function login(Request $request)
    {
        try {
            $validateUser = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required',
            ]);

            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            // Attempt to authenticate
            if (!Auth::attempt($request->only(['email', 'password']))) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email & password do not match our records.',
                ], 401);
            }

            // Retrieve the authenticated user
            $user = User::where('email', $request->email)->first();
            return response()->json([
                'status' => true,
                'message' => 'User logged in successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500); // Added HTTP status code 500 for internal server error
        }
    }

    // Profile information
    public function profile()
    {
        $userData = auth()->user();
        return response()->json([
            'status' => true,
            'message' => 'Profile Information',
            'data' => $userData,
            'id' => $userData->id
        ], 200);
    }

    // Logout section
    public function logout()
    {
        // Check if the user is authenticated
        if (auth()->check()) {
            // Delete all tokens for the authenticated user
            auth()->user()->tokens()->delete();

            return response()->json([
                'status' => true,
                'message' => 'User logged out successfully',
                'data' => [],
            ], 200);
        }

        return response()->json([
            'status' => false,
            'message' => 'User not authenticated',
            'data' => [],
        ], 401);
    }

     // Password Reset Request
     public function passwordResetRequest(Request $request)
     {
         try {
             $validateUser = Validator::make($request->all(), [
                 'email' => 'required|email',
             ]);
 
             if ($validateUser->fails()) {
                 return response()->json([
                     'status' => false,
                     'message' => 'Validation error',
                     'errors' => $validateUser->errors()
                 ], 401);
             }
 
             // Send the password reset link
             $status = Password::sendResetLink($request->only('email'));
 
             if ($status === Password::RESET_LINK_SENT) {
                 return response()->json([
                     'status' => true,
                     'message' => 'Password reset link sent to your email address.',
                 ], 200);
             } else {
                 return response()->json([
                     'status' => false,
                     'message' => 'Unable to send reset link. Please check your email address.',
                 ], 500);
             }
         } catch (\Throwable $th) {
             Log::error('Password reset request error: ' . $th->getMessage());
             return response()->json([
                 'status' => false,
                 'message' => 'An error occurred while processing your request.',
             ], 500);
         }
     }
}
