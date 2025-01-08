<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;

class ApiController extends Controller
{

    private function sendResponse($status, $message, $data = null, $statusCode = 200)
    {
        return response()->json([
            'status' => $status,
            'message' => $message,
            'data' => $data,
        ], $statusCode);
    }

    private function sendError($message, $error = null, $statusCode = 500)
    {
        return response()->json([
            'status' => false,
            'message' => $message,
            'error' => $error,
        ], $statusCode);
    }

    public function register(Request $request)
    {
        try {
            $validated = $request->validate([
                'name' => 'required',
                'email' => 'required|email|unique:users',
                'password' => 'required|confirmed|min:8|regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', 
                'role' => 'in:admin,user',
            ], [
                'password.regex' => 'The password must contain at least one lowercase letter, one uppercase letter, one number, and one special character.',
                'password.min' => 'The password must be at least 8 characters long.',
                'password.confirmed' => 'The password confirmation does not match.',
            ]);
    
            $role = $validated['role'] ?? 'user';
    
            $user = User::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'password' => bcrypt($validated['password']),
                'role' => $role,
            ]);
    
            $token = JWTAuth::fromUser($user);
    
            return $this->sendResponse(true, 'User registered successfully', [
                'user' => $user,
                'token' => $token,
            ], 201);
        } catch (\Exception $e) {
            return $this->sendError('Registration failed', $e->getMessage());
        }
    }
    

  
    public function login(Request $request)
    {
        try {
            $validated = $request->validate([
                'email' => 'required|email',
                'password' => 'required',
            ]);

            $credentials = $request->only('email', 'password');

            if (!Auth::attempt($credentials)) {
                return $this->sendResponse(false, 'Invalid credentials', null, 401);
            }

            $user = Auth::user();
            $token = JWTAuth::fromUser($user);

            return $this->sendResponse(true, 'Login successful', [
                'user' => $user,
                'token' => $token,
            ]);
        } catch (\Exception $e) {
            return $this->sendError('Login failed', $e->getMessage());
        }
    }

    public function me()
    {
        try {
            $user = auth('api')->user();

            if (!$user) {
                return $this->sendResponse(false, 'User not authenticated', null, 401);
            }

            return $this->sendResponse(true, 'User profile fetched successfully', $user);
        } catch (\Exception $e) {
            return $this->sendError('Failed to fetch profile', $e->getMessage());
        }
    }

    public function admin()
    {
        $user = auth('api')->user();

        if (!$user || $user->role !== 'admin') {
            return $this->sendResponse(false, 'Unauthorized', null, 401);
        }

        return $this->sendResponse(true, 'Welcome admin',$user);
    }
}
