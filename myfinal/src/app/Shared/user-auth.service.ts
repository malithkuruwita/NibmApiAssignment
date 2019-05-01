import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, Subject } from 'rxjs';
@Injectable({
  providedIn: 'root'
})
export class UserAuthService {


  selectedUser: User;

  private _registerUrl = "http://localhost:3000/user/register"
  private _loginUrl = "http://localhost:3000/user/login"
  private _resetUrl = "http://localhost:3000/user/resetpassword"
  private _confirmResetUrl = "http://localhost:3000/user/reset"
  private _googleAuth = "http://localhost:3000/user/oauth/google"

  private subject = new Subject<any>();

  constructor(private http: HttpClient, private _router: Router) { }

  registerUser(user){
      return this.http.post<any>(this._registerUrl, user)
  }

  loginUser(user){
    return this.http.post<any>(this._loginUrl, user)
  }

  ResetUser(user){
    return this.http.post<any>(this._resetUrl, user)
  }

  ConfirmReset(user){
    return this.http.post<any>(this._confirmResetUrl, user)
  }

  GoogleSignin(token){
    return this.http.post<any>(this._googleAuth, { access_token: token })
  }

  loggedIn(){
    return !!localStorage.getItem('token')
  }

  getToken(){
    return localStorage.getItem('token')
  }

  //get username when user reload the browser
  getUsername(){
    return localStorage.getItem('username')
  }

  logoutUser(){
    localStorage.removeItem('token')
    localStorage.removeItem('email')
    localStorage.removeItem('username')
    localStorage.removeItem('account_type')
    this.sendReload('My Account')
    this._router.navigate(['/deals'])
  }


  //sending data to reload header component
  sendReload(username: String){
    this.subject.next( {username: username} );
  }
  //reloading hub
  getReload(): Observable<any>{
    return this.subject.asObservable();
  }


}


class User{
  method:String;
  local:{
    username:String;
    email:String;
    password:String;
  }
}