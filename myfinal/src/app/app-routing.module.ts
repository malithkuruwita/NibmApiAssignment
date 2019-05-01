import { NgModule } from "@angular/core";
import { Routes, RouterModule } from "@angular/router";
import { BestdealsComponent } from "./bestdeals/bestdeals.component";
import { DealsComponent } from "./deals/deals.component";
import { LoginComponent } from "./login/login.component";
import { RegisterComponent } from "./register/register.component";
import { ResetpasswordComponent } from "./resetpassword/resetpassword.component";
import { ShoppingCartComponent } from "./shopping-cart/shopping-cart.component";
import { AuthGuard } from "./Shared/auth.guard";

const routes: Routes = [
  {
    path: "",
    redirectTo: "/deals",
    pathMatch: "full"
  },
  {
    path: "deals",
    component: DealsComponent
  },
  {
    path: "best-deals",
    component: BestdealsComponent,
    canActivate: [AuthGuard]
  },
  {
    path: "login",
    component: LoginComponent
  },
  {
    path: "register",
    component: RegisterComponent
  },
  {
    path: "resetpassword/:id",
    component: ResetpasswordComponent
  },
  {
    path: "shopping-cart",
    component: ShoppingCartComponent
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
