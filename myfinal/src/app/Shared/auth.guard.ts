import { Injectable } from '@angular/core';
import { CanActivate, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { UserAuthService } from '../Shared/user-auth.service';
@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(private _authService: UserAuthService, private _router: Router){}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean{
    if(this._authService.loggedIn()){
      return true
    }else{
      this._router.navigate(['/login'], { queryParams: { returnUrl: state.url }})
      return false
    }
  }


}
