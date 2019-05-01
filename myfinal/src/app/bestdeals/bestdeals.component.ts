import { Component, OnInit } from '@angular/core';
import { DealService } from '../Shared/deal.service';
import { Router } from '@angular/router';
import { HttpErrorResponse } from '@angular/common/http';
@Component({
  selector: 'app-bestdeals',
  templateUrl: './bestdeals.component.html',
  styleUrls: ['./bestdeals.component.css']
})
export class BestdealsComponent implements OnInit {

  specialEvents = []

  constructor(private _dealService: DealService, private _router: Router) { }

  ngOnInit() {
    this._dealService.getSpecialevents().subscribe(
      res => this.specialEvents = res,
      err => {
        if(err instanceof HttpErrorResponse){
          if(err.status === 401){
            this._router.navigate(['/login'])
          }
        }
      }
    )
  }

}
