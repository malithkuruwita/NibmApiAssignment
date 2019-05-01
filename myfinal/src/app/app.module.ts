import { BrowserModule } from "@angular/platform-browser";
import { NgModule } from "@angular/core";
import { HttpClientModule, HTTP_INTERCEPTORS } from "@angular/common/http";
import { AppRoutingModule } from "./app-routing.module";
import { AppComponent } from "./app.component";
import { FormsModule } from "@angular/forms";
import { HeaderComponent } from "./header/header.component";
import { RegisterComponent } from "./register/register.component";
import { LoginComponent } from "./login/login.component";
import { BestdealsComponent } from "./bestdeals/bestdeals.component";
import { DealsComponent } from "./deals/deals.component";

import { TokenInterceptorService } from "./Shared/token-interceptor.service";
import { ResetpasswordComponent } from "./resetpassword/resetpassword.component";

import { SocialLoginModule, AuthServiceConfig } from "angular-6-social-login";
import { getAuthServiceConfigs } from "./socialloginConfig";
import { FooterComponent } from "./footer/footer.component";
import { ShoppingCartComponent } from './shopping-cart/shopping-cart.component';

@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    RegisterComponent,
    LoginComponent,
    BestdealsComponent,
    DealsComponent,
    ResetpasswordComponent,
    FooterComponent,
    ShoppingCartComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    FormsModule,
    SocialLoginModule
  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: TokenInterceptorService,
      multi: true
    },
    { provide: AuthServiceConfig, useFactory: getAuthServiceConfigs }
  ],
  bootstrap: [AppComponent]
})
export class AppModule {}
