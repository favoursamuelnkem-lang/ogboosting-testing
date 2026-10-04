const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },

    providerOrderId: {
      type: String,
      required: true
    },

    serviceId: {
      type: String,
      required: true
    },

    serviceName: {
      type: String,
      required: true
    },

    platform: {
      type: String,
      required: true
    },

    link: {
      type: String,
      required: true
    },

    quantity: {
      type: Number,
      required: true
    },

    amount: {
      type: Number,
      required: true
    },

    status: {
      type: String,
      default: "Pending"
    },

    remains: {
      type: Number,
      default: 0
    },

    startCount: {
      type: Number,
      default: 0
    },

    providerCharge: {
      type: Number,
      default: 0
    },

    refundProcessed: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("Order", orderSchema);