const mongoose = require('mongoose')

const Schema = mongoose.Schema;
const headerSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'users'},
    orderDate: { type: Date },
    subTotal: {type: Number},
    totalItems: {type: Number}
});

module.exports = mongoose.model("header", headerSchema, "header");