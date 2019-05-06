const mongoose = require('mongoose')


const Schema = mongoose.Schema;
const detailSchema = new Schema({
    orderId:{type: Schema.Types.ObjectId, ref: 'header'},
    itemId:{ type: String },
    price:{ type: Number },
    quantity:{ type: Number },
    lineTotal:{ type: Number }
});

module.exports = mongoose.model("detail", detailSchema, "detail");