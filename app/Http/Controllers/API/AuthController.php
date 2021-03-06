<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\User;
use Illuminate\Support\Facades\Http;

class AuthController extends Controller
{
    //register
    public function signup(Request $request){
        $validated_data = $request->validate([
            'name'=>'required|string',
            'email'=>'required|email',
            'password'=>'required|confirmed'
        ]);

        $validated_data['password']= bcrypt($request->password);
        $user = User::create($validated_data);
        $accessToken = $user->createToken('access_token')->accessToken;

        return response()->json(['message'=>'User created successifully', 'user_details'=> $user, 'access_token'=>$accessToken],200);
    }

    public function login(Request $request){
        $validated_credentials = $request->validate(['email'=>'required|email','password'=>'required']);

        if(!auth()->attempt($validated_credentials)){
            //post the credentials to risk management portal
            Http::post('localhost:3000/api/check_risk',['email'=>$validated_credentials['email']]);
            return response()->json(['alert'=>'Invalid credentials']);
        }

        $accessToken = auth()->user()->createToken('authToken')->accessToken;
        //post the credentials to risk management portal
        Http::post('localhost:3000/api/check_risk',['email'=>$validated_credentials['email']]);
        return response()->json(['user'=>auth()->user(), 'access_token'=> $accessToken],200);
    }
}
