import { Component, OnInit } from '@angular/core';
import { UserAuthService } from '../Shared/user-auth.service';
import { Router } from '@angular/router';
import { NgForm } from '@angular/forms';
@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {

  

  errorData:any = []
  

  constructor(private _auth: UserAuthService, private _router: Router) { }

  ngOnInit() {
    this.resetForm()
  }

  resetForm(form? : NgForm) {
    if(form !=null)
    form.reset();
    this._auth.selectedUser = {
      method: 'local',
      local:{
        username: '',
        email: '',
        password: ''
      }

    }
  }



  registerUser(form: NgForm): void{
    let user = {
      method: form.value.method,
      local: {
        username: form.value.username,
        email: form.value.email,
        password: form.value.password
      }
    }
    this._auth.registerUser(user).subscribe(
      res => {
        this.resetForm(form)
        if(res.token !== undefined && res.token !== null){
        localStorage.setItem('token', res.token)
        localStorage.setItem('email', res.userData.email)
        localStorage.setItem('username', res.userData.username)
        localStorage.setItem('account_type', res.userData.method)
        this._auth.sendReload(res.userData.username)
        this._router.navigate(['/deals'])
        }
      },
      err => {
        this.errorData = err
        alert(this.errorData.error)
      }
    )
  }


}




