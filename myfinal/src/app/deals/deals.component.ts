import { Component, OnInit } from "@angular/core";
import { DealService } from "../Shared/deal.service";
import * as $ from "jquery";
declare var $: any;
@Component({
  selector: "app-deals",
  templateUrl: "./deals.component.html",
  styleUrls: ["./deals.component.css"]
})
export class DealsComponent implements OnInit {
  url = "assets/js/modelsupport.js";
  events = [];
  events1 = [];
  loadAPI: Promise<any>;
  constructor(private _dealService: DealService) {}

  ngOnInit() {
    $("body").addClass("df");

    this.loadAPI = new Promise(resolve => {
      console.log("resolving promise...");
      this.loadScript();
    });

    this._dealService
      .getEvents()
      .subscribe(res => (this.events = res), err => console.log(err));
    this._dealService
      .getSpecialevents()
      .subscribe(res => (this.events1 = res), err => console.log(err));
  }

  public loadScript() {
    console.log("preparing to load...");
    let node = document.createElement("script");
    node.src = this.url;
    node.type = "text/javascript";
    node.async = true;
    node.charset = "utf-8";
    document.getElementsByTagName("head")[0].appendChild(node);
  }
}
