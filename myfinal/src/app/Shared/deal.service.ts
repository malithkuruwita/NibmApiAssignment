import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
@Injectable({
  providedIn: 'root'
})
export class DealService {

  private _eventsUrl = "http://localhost:3000/user/events";
  private _specialUrl = "http://localhost:3000/user/special";

  constructor(private http: HttpClient) { }

  getEvents(){
    return this.http.get<any>(this._eventsUrl)
  }

  getSpecialevents(){
    return this.http.get<any>(this._specialUrl)
  }


}
