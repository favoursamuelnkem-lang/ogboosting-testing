const mongoose = require("mongoose");

const transactionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },

    txRef: {
      type: String,
      required: true,
      unique: true
    },

    type: {
      type: String,
      required: true
    },

    amount: {
      type: Number,
      required: true
    },

    currency: {
      type: String,
      default: "NGN"
    },

    status: {
      type: String,
      default: "pending"
    },

    flutterwaveId: {
      type: String
    }

  },
  {
    timestamps: true
  }
);

module.exports =
  mongoose.model("Transaction", transactionSchema);