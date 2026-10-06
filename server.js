const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Resend } = require("resend");

const User = require("./models/User");
const Transaction = require("./models/Transaction");
const Order = require("./models/Order");
const ServicePrice = require("./models/ServicePrice");
const AdminLog = require("./models/AdminLog");
const Coupon = require("./models/Coupon");
const Announcement = require("./models/Announcement");
const Withdrawal = require("./models/Withdrawal");
const fs = require("fs");
const path = require("path");
const protect = require("./middleware/authMiddleware");
const adminProtect = require("./middleware/adminMiddleware");
const axios = require("axios");

dotenv.config();
const resend = new Resend(process.env.RESEND_API_KEY);

// ==========================================
// WELCOME-BACK EMAIL
// ==========================================
async function sendWelcomeBackEmail(user) {
  if (!process.env.RESEND_API_KEY) {
    console.warn("RESEND_API_KEY is not configured; welcome email skipped.");
    return;
  }

  const { data, error } = await resend.emails.send({
    from: "OG Boosting <support@getogsms.com>",
    replyTo: "supportogboosting@gmail.com",
    to: [user.email],
    subject: "Welcome back to OG Boosting",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:32px;background:#f6f8fa;color:#172033;">
        <div style="background:#ffffff;border-radius:18px;padding:30px;border:1px solid #eaecf0;">
          <div style="font-size:24px;font-weight:800;color:#0B4F63;margin-bottom:6px;">OG<span style="color:#F97316;">Boost</span></div>
          <p style="font-size:14px;color:#667085;margin-top:0;">Social Growth</p>
          <h2 style="font-size:24px;margin:28px 0 10px;color:#101828;">Welcome back, ${String(user.fullName || "there").replace(/[<>]/g, "")}!</h2>
          <p style="font-size:15px;line-height:1.7;color:#475467;">
            You have successfully signed in to your OG Boosting account. Your wallet, orders and boosting services are ready for you.
          </p>
          <div style="margin:26px 0;padding:16px;border-radius:12px;background:#f8fafc;border:1px solid #eaecf0;">
            <strong style="color:#0B4F63;">Account email:</strong> ${String(user.email).replace(/[<>]/g, "")}
          </div>
          <p style="font-size:13px;line-height:1.6;color:#98a2b3;">If this sign-in was not you, please change your password and contact OG Boosting Support.</p>
          <p style="font-size:14px;color:#475467;margin-top:28px;">— OG Boosting Support</p>
        </div>
      </div>
    `
  });

  if (error) {
    throw error;
  }

  console.log("Welcome-back email sent:", data?.id || "ok");
}

const app = express();


// ===============================
// MIDDLEWARE
// ===============================

app.use(cors());

app.use(express.json());


// ===============================
// MONGODB
// ===============================

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((error) => {
    console.error("MongoDB connection failed:");
    console.error(error.message);
  });


// ===============================
// TEST ROUTE
// ===============================

app.get("/", (req, res) => {

  res.json({
    message: "OG Boosting server is running"
  });

});


// ===============================
// REGISTER
// ===============================

app.post("/api/auth/register", async (req, res) => {

  try {

    const {
      fullName,
      email,
      password
    } = req.body;


    // CHECK REQUIRED FIELDS

    if (!fullName || !email || !password) {

      return res.status(400).json({
        success: false,
        message: "Full name, email and password are required."
      });

    }


    // CHECK PASSWORD LENGTH

    if (password.length < 8) {

      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters."
      });

    }


    // NORMALIZE EMAIL

    const normalizedEmail =
      email.trim().toLowerCase();


    // CHECK EXISTING USER

    const existingUser =
      await User.findOne({
        email: normalizedEmail
      });


    if (existingUser) {

      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });

    }


    // HASH PASSWORD

    const hashedPassword =
      await bcrypt.hash(password, 12);


    // CREATE USER

    const user = await User.create({

      fullName: fullName.trim(),

      email: normalizedEmail,

      password: hashedPassword,

      balance: 0

    });


    // SUCCESS

    res.status(201).json({

      success: true,

      message: "Account created successfully.",

      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        balance: user.balance
      }

    });


  } catch (error) {

    console.error("Registration error:", error);

    res.status(500).json({

      success: false,

      message: "Something went wrong while creating your account."

    });

  }

});


// ===============================
// LOGIN
// ===============================

const jwt = require("jsonwebtoken");

app.post("/api/auth/login", async (req, res) => {

  try {

    const { email, password } = req.body;


    // CHECK REQUIRED FIELDS

    if (!email || !password) {

      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });

    }


    // NORMALIZE EMAIL

    const normalizedEmail =
      email.trim().toLowerCase();


    // FIND USER

    const user = await User.findOne({
      email: normalizedEmail
    });


    if (!user) {

      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });

    }


    // CHECK PASSWORD

    if (user.active === false) {
      return res.status(403).json({ success: false, message: "This account is suspended." });
    }

    const passwordMatch =
      await bcrypt.compare(password, user.password);


    if (!passwordMatch) {

      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });

    }


    // CREATE JWT

    const token = jwt.sign(
      {
        userId: user._id
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );


    // Send a welcome-back email after every successful sign-in.
    // Email delivery must never prevent a valid login.
    try {
      await sendWelcomeBackEmail(user);
    } catch (emailError) {
      console.error("Welcome-back email error:", emailError);
    }

    // SUCCESS

    res.json({

      success: true,

      message: "Login successful.",

      token,

      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        balance: user.balance
      }

    });


  } catch (error) {

    console.error("Login error:", error);

    res.status(500).json({

      success: false,

      message: "Something went wrong while logging in."

    });

  }

});

// ===============================
// FORGOT PASSWORD
// ===============================
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({
      email: normalizedEmail
    });

    // Always return the same response so people cannot
    // discover which emails have accounts.
    if (!user) {
      return res.json({
        message: "If an account exists with that email, a reset link has been sent."
      });
    }

    // Generate secure random token
    const rawToken = crypto.randomBytes(32).toString("hex");

    // Store only the hashed token in MongoDB
    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    // Token expires in 30 minutes
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 30 * 60 * 1000);

    await user.save();

// Create password reset link
const resetLink =
  `${process.env.FRONTEND_URL}/reset-password.html?token=${rawToken}`;

// Send password reset email
// Send password reset email
const { data, error } = await resend.emails.send({
  from: "OG Boosting <support@getogsms.com>",
  replyTo: "supportogboosting@gmail.com",
  to: [normalizedEmail],
  subject: "Reset Your OG Boosting Password",
  html: `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 30px;">
      
      <h2 style="color: #F97316;">
        OG Boosting
      </h2>

      <p>Hello,</p>

      <p>
        We received a request to reset your OG Boosting password.
      </p>

      <p>
        Click the button below to create a new password:
      </p>

      <div style="margin: 30px 0;">
        <a
          href="${resetLink}"
          style="
            display: inline-block;
            background: #F97316;
            color: white;
            text-decoration: none;
            padding: 14px 24px;
            border-radius: 8px;
            font-weight: bold;
          "
        >
          Reset Password
        </a>
      </div>

      <p>
        This link will expire in <strong>30 minutes</strong>.
      </p>

      <p>
        If you did not request a password reset, you can safely ignore this email.
      </p>

      <p>
        — OG Boosting Support
      </p>

    </div>
  `
});

if (error) {
  console.error("Resend email error:", error);

  return res.status(500).json({
    message: "Unable to send reset email. Please try again later."
  });
}

console.log("Password reset email sent:", data.id);

return res.json({
  message: "If an account exists with that email, a reset link has been sent."
});

} catch (error) {
  console.error("Forgot password error:", error);

  res.status(500).json({
    message: "Something went wrong. Please try again."
  });
}
});



// ===============================
// RESET PASSWORD
// ===============================
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({
        message: "Reset token and password are required."
      });
    }

    // Validate password
    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters."
      });
    }

    if (!/[A-Za-z]/.test(password)) {
      return res.status(400).json({
        message: "Password must contain at least one letter."
      });
    }

    if (!/[0-9]/.test(password)) {
      return res.status(400).json({
        message: "Password must contain at least one number."
      });
    }

    // Hash the token from the reset link
    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // Find user with valid, non-expired token
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: {
        $gt: new Date()
      }
    });

    if (!user) {
      return res.status(400).json({
        message: "Reset link is invalid or has expired."
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Update password
    user.password = hashedPassword;

    // Remove reset token so it cannot be used again
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await user.save();

    return res.json({
      message: "Password reset successfully."
    });

  } catch (error) {
    console.error("Reset password error:", error);

    res.status(500).json({
      message: "Something went wrong. Please try again."
    });
  }
});



// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

function authenticateToken(req, res, next) {

  const authHeader = req.headers.authorization;

  const token =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : null;

  if (!token) {

    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });

  }

  jwt.verify(
    token,
    process.env.JWT_SECRET,
    (error, decoded) => {

      if (error) {

        return res.status(403).json({
          success: false,
          message: "Invalid or expired token."
        });

      }

      req.userId = decoded.userId;

      next();

    }
  );

}




// ==========================================
// GET CURRENT USER
// ==========================================
app.get(
  "/api/auth/me",
  authenticateToken,
  async (req, res) => {
    try {

      const user =
        await User.findById(req.userId)
          .select("-password");


      if (!user) {

        return res.status(404).json({

          success: false,

          message: "User not found."

        });

      }


      res.json({

        success: true,

        user: {

          id: user._id,

          fullName: user.fullName,

          email: user.email,

          balance: user.balance

        }

      });


    } catch (error) {

      console.error(
        "Get current user error:",
        error
      );


      res.status(500).json({

        success: false,

        message: "Server error."

      });

    }

  }
);


app.get("/get-user", protect, async (req, res) => {

  try {

    const user = await User.findById(req.userId)
      .select("-password");

    if (!user) {

      return res.status(404).json({
        success: false,
        message: "User not found"
      });

    }

    res.json({
      success: true,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        balance: user.balance
      }
    });

  } catch (error) {

    console.error("Get user error:", error);

    res.status(500).json({
      success: false,
      message: "Server error"
    });

  }

});


// ==========================================
// FLUTTERWAVE - CREATE PAYMENT
// ==========================================
// ==========================================
// FLUTTERWAVE - CREATE PAYMENT
// ==========================================

app.post(
  "/api/wallet/fund",
  protect,
  async (req, res) => {

    try {

      const { amount } = req.body;

      const paymentAmount = Number(amount);

      if (!paymentAmount || paymentAmount < 100) {

        return res.status(400).json({
          success: false,
          message: "Minimum funding amount is ₦100."
        });

      }

      const user = await User.findById(req.userId);

      if (!user) {

        return res.status(404).json({
          success: false,
          message: "User not found."
        });

      }

      // UNIQUE PAYMENT REFERENCE

      const txRef =
        `OGBOOST-${Date.now()}-${user._id}`;


      // SAVE PENDING TRANSACTION

      await Transaction.create({

        userId: user._id,

        txRef: txRef,

        type: "deposit",

        amount: paymentAmount,

        currency: "NGN",

        status: "pending"

      });


      // CREATE FLUTTERWAVE PAYMENT

      const response = await axios.post(

        "https://api.flutterwave.com/v3/payments",

        {

          tx_ref: txRef,

          amount: paymentAmount,

          currency: "NGN",

          redirect_url:
            `${process.env.FRONTEND_URL}/payment-success.html`,

          customer: {

            email: user.email,

            name: user.fullName

          },

          customizations: {

            title: "OG Boost Wallet",

            description:
              "Fund your OG Boost wallet"

          },

          meta: {

            userId:
              user._id.toString(),

            txRef: txRef

          }

        },

        {

          headers: {

            Authorization:
              `Bearer ${process.env.FLW_SECRET_KEY}`,

            "Content-Type":
              "application/json"

          }

        }

      );


      res.json({

        success: true,

        paymentLink:
          response.data.data.link,

        txRef: txRef

      });


    } catch (error) {

      console.error(

        "Flutterwave payment error:",

        error.response?.data ||
        error.message

      );


      res.status(500).json({

        success: false,

        message:
          "Unable to initialize payment."

      });

    }

  }
);


// ==========================================
// VERIFY FLUTTERWAVE PAYMENT
// ==========================================

app.get(
  "/api/wallet/verify",
  protect,
  async (req, res) => {

    try {

      const {
        transaction_id,
        tx_ref
      } = req.query;


      if (!transaction_id || !tx_ref) {

        return res.status(400).json({

          success: false,

          message:
            "Missing transaction information."

        });

      }


      // FIND OUR TRANSACTION

      const transaction =
        await Transaction.findOne({

          txRef: tx_ref,

          userId: req.userId

        });


      if (!transaction) {

        return res.status(404).json({

          success: false,

          message:
            "Transaction not found."

        });

      }


      // PREVENT DOUBLE CREDIT

      if (
        transaction.status ===
        "successful"
      ) {

        return res.json({

          success: true,

          message:
            "Payment already processed."

        });

      }


      // ASK FLUTTERWAVE FOR THE REAL STATUS

      const response =
        await axios.get(

          `https://api.flutterwave.com/v3/transactions/${transaction_id}/verify`,

          {

            headers: {

              Authorization:
                `Bearer ${process.env.FLW_SECRET_KEY}`,

              "Content-Type":
                "application/json"

            }

          }

        );


      const payment =
        response.data.data;


      // VERIFY EVERYTHING

      if (

        payment.status !==
        "successful"

        ||

        payment.currency !==
        "NGN"

        ||

        payment.tx_ref !==
        transaction.txRef

        ||

        Number(payment.amount) <
        Number(transaction.amount)

      ) {

        transaction.status =
          "failed";

        await transaction.save();


        return res.status(400).json({

          success: false,

          message:
            "Payment verification failed."

        });

      }


      // FIND USER

      const user =
        await User.findById(
          transaction.userId
        );


      if (!user) {

        return res.status(404).json({

          success: false,

          message:
            "User not found."

        });

      }


      // CREDIT WALLET

      user.balance =
        Number(user.balance || 0) +
        Number(transaction.amount);


      await user.save();


      // UPDATE TRANSACTION

      transaction.status =
        "successful";

      transaction.flutterwaveId =
        String(payment.id);

      await transaction.save();


      // SUCCESS

      res.json({

        success: true,

        message:
          "Wallet funded successfully.",

        balance:
          user.balance,

        amount:
          transaction.amount

      });


    } catch (error) {

      console.error(

        "Payment verification error:",

        error.response?.data ||
        error.message

      );


      res.status(500).json({

        success: false,

        message:
          "Unable to verify payment."

      });

    }

  }
);

// ==========================================
// GET TRANSACTION HISTORY
// ==========================================

app.get(
  "/api/wallet/transactions",
  protect,
  async (req, res) => {

    try {

      const transactions = await Transaction.find({
        userId: req.userId
      })
        .sort({ createdAt: -1 })
        .limit(50);

      res.json({
        success: true,
        transactions
      });

    } catch (error) {

      console.error(
        "Transaction history error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Unable to load transactions."
      });

    }

  }
);


// ==========================================
// WALLET SUMMARY
// ==========================================

app.get(
  "/api/wallet/summary",
  protect,
  async (req, res) => {

    try {

      const transactions = await Transaction.find({
        userId: req.userId
      });

      let totalDeposited = 0;
      let totalSpent = 0;

      transactions.forEach(transaction => {

        if (
          transaction.status === "successful"
        ) {

          if (
            transaction.type === "deposit"
          ) {

            totalDeposited +=
              Number(transaction.amount || 0);

          }

          if (
            transaction.type === "order" ||
            transaction.type === "purchase"
          ) {

            totalSpent +=
              Number(transaction.amount || 0);

          }

        }

      });

      res.json({

        success: true,

        summary: {

          totalDeposited,
          totalSpent,
          transactionCount:
            transactions.length

        }

      });

    } catch (error) {

      console.error(
        "Wallet summary error:",
        error
      );

      res.status(500).json({

        success: false,

        message:
          "Unable to load wallet summary."

      });

    }

  }
);


// ==========================================
// OWLET API - TEST CONNECTION
// ==========================================

app.get("/api/owlet/services", async (req, res) => {

  try {

    const response = await axios.post(
      process.env.OWLET_API_URL,
      {
        key: process.env.OWLET_API_KEY,
        action: "services"
      },
      {
        headers: {
          "Content-Type": "application/json"
        }
      }
    );

    console.log("OWLET SERVICES:", response.data);

    res.json({
      success: true,
      services: response.data
    });

  } catch (error) {

    console.error(
      "Owlet API error:",
      error.response?.data || error.message
    );

    res.status(500).json({
      success: false,
      message: "Unable to connect to Owlet.",
      error: error.response?.data || error.message
    });

  }

});


// ==========================================
// OG BOOSTING - GET SELECTED SERVICES
// ==========================================
// ==========================================
// GET SERVICES WITH OUR OWN SELLING PRICES
// ==========================================

app.get("/api/services", async (req, res) => {
  try {
    const response = await axios.post(
      process.env.OWLET_API_URL,
      { key: process.env.OWLET_API_KEY, action: "services" },
      { headers: { "Content-Type": "application/json" } }
    );

    const owletServices = Array.isArray(response.data) ? response.data : [];
    const overrides = await ServicePrice.find({}).lean();
    const priceMap = new Map(overrides.map(item => [String(item.serviceId), item]));
    const defaultMarkup = 68.35;

    const services = owletServices.slice(0, 50).map(service => {
      const serviceId = String(service.service);
      const providerRate = Number(service.rate || 0);
      const saved = priceMap.get(serviceId);
      const defaultSellingRate = providerRate + (providerRate * defaultMarkup / 100);
      if (saved && saved.enabled === false) return null;
      const sellingRate = saved ? Number(saved.sellingRate) : defaultSellingRate;

      return {
        service: serviceId,
        name: saved?.displayName || service.name,
        type: service.type,
        category: saved?.category || service.category,
        description: saved?.description || "",
        price: sellingRate,
        min: saved?.minOverride ?? service.min,
        max: saved?.maxOverride ?? service.max,
        refill: service.refill,
        dripfeed: service.dripfeed
      };
    }).filter(Boolean);

    res.json({ success: true, services });
  } catch (error) {
    console.error("Failed to load Owlet services:", error.response?.data || error.message);
    res.status(500).json({ success: false, message: "Unable to load services." });
  }
});



// ==========================================
// CREATE BOOST ORDER
// ==========================================

app.post(
  "/api/orders",
  protect,
  async (req, res) => {

    try {

     const {
  serviceId,
  platform,
  link,
  quantity
} = req.body;


      // ==========================================
      // VALIDATE INPUT
      // ==========================================

      if (!serviceId || !link || !quantity) {

        return res.status(400).json({
          success: false,
          message: "Service, link and quantity are required."
        });

      }


      const selectedQuantity = Number(quantity);


      if (
        !Number.isInteger(selectedQuantity) ||
        selectedQuantity < 1
      ) {

        return res.status(400).json({
          success: false,
          message: "Invalid quantity."
        });

      }


      // ==========================================
      // GET USER
      // ==========================================

      const user =
        await User.findById(req.userId);


      if (!user) {

        return res.status(404).json({
          success: false,
          message: "User not found."
        });

      }


      // ==========================================
      // GET SERVICES FROM OWLET
      // ==========================================

      const servicesResponse =
        await axios.post(
          process.env.OWLET_API_URL,
          {
            key: process.env.OWLET_API_KEY,
            action: "services"
          },
          {
            headers: {
              "Content-Type": "application/json"
            }
          }
        );


      const owletServices =
        servicesResponse.data;


      // ==========================================
      // FIND SELECTED SERVICE
      // ==========================================

      const selectedService =
        owletServices.find(
          service =>
            String(service.service) ===
            String(serviceId)
        );


      if (!selectedService) {

        return res.status(404).json({
          success: false,
          message: "Selected service was not found."
        });

      }

      const serviceOverride = await ServicePrice.findOne({ serviceId: String(selectedService.service) }).lean();
      if (serviceOverride && serviceOverride.enabled === false) {
        return res.status(400).json({ success: false, message: "This service is currently unavailable." });
      }


      // ==========================================
      // CHECK MINIMUM / MAXIMUM
      // ==========================================

      const minimum = Number(serviceOverride?.minOverride ?? selectedService.min ?? 1);

      const maximum = Number(serviceOverride?.maxOverride ?? selectedService.max ?? 999999999);


      if (selectedQuantity < minimum) {

        return res.status(400).json({
          success: false,
          message:
            `Minimum quantity for this service is ${minimum.toLocaleString()}.`
        });

      }


      if (selectedQuantity > maximum) {

        return res.status(400).json({
          success: false,
          message:
            `Maximum quantity for this service is ${maximum.toLocaleString()}.`
        });

      }


      // ==========================================
      // CALCULATE OUR SELLING PRICE
      // ==========================================

      const owletCost = Number(selectedService.rate || 0);
      const savedPrice = await ServicePrice.findOne({
        serviceId: String(selectedService.service)
      }).lean();

      const defaultMarkup = 68.35;
      const sellingRate = savedPrice
        ? Number(savedPrice.sellingRate)
        : owletCost + (owletCost * defaultMarkup / 100);

      const totalPrice = Math.ceil(
        (selectedQuantity / 1000) * sellingRate
      );


// ==========================================
      // CHECK WALLET BALANCE
      // ==========================================

      const currentBalance =
        Number(user.balance || 0);


      if (currentBalance < totalPrice) {

        return res.status(400).json({
          success: false,
          message:
            `Insufficient wallet balance. You need ₦${totalPrice.toLocaleString()} but your balance is ₦${currentBalance.toLocaleString()}.`
        });

      }


      // ==========================================
      // SEND ORDER TO OWLET
      // ==========================================

      const owletResponse =
        await axios.post(
          process.env.OWLET_API_URL,
          {
            key: process.env.OWLET_API_KEY,

            action: "add",

            service: selectedService.service,

            link: link,

            quantity: selectedQuantity
          },
          {
            headers: {
              "Content-Type": "application/json"
            }
          }
        );


      console.log(
        "OWLET ORDER RESPONSE:",
        owletResponse.data
      );


      // ==========================================
      // CHECK OWLET RESPONSE
      // ==========================================

      const owletData =
        owletResponse.data;


      if (
        !owletData ||
        !owletData.order
      ) {

        return res.status(400).json({
          success: false,
          message:
            owletData?.error ||
            "Owlet rejected the order."
        });

      }


      // ==========================================
      // DEDUCT WALLET
      // ==========================================

      user.balance =
        currentBalance -
        totalPrice;


      await user.save();


      // ==========================================
      // SAVE ORDER
      // ==========================================

  const order = await Order.create({

  userId: user._id,

  providerOrderId:
    String(owletData.order),

  serviceId:
    String(selectedService.service),

  serviceName:
    selectedService.name,

  platform:
    platform,

  link:
    link,

  quantity:
    selectedQuantity,

  amount:
    totalPrice,

  status:
    "processing",

  providerCharge:
    Number(selectedService.rate || 0) * (selectedQuantity / 1000)

});
      // ==========================================
      // SAVE TRANSACTION
      // ==========================================

      await Transaction.create({

        userId: user._id,

        txRef:
          `ORDER-${order._id}`,

        type:
          "order",

        amount:
          totalPrice,

        currency:
          "NGN",

        status:
          "successful"

      });


      // ==========================================
      // SUCCESS
      // ==========================================

    res.json({

  success: true,

  message:
    "Boost order placed successfully.",

  order: {

    id: order._id,

    providerOrderId:
      order.providerOrderId,

    service:
      order.serviceName,

    link:
      order.link,

    quantity:
      order.quantity,

    amount:
      order.amount,

    status:
      order.status

  },

  balance:
    user.balance

});


    } catch (error) {

      console.error(
        "Create order error:",
        error.response?.data ||
        error.message
      );


      res.status(500).json({

        success: false,

        message:
          error.response?.data?.error ||
          "Unable to place order."

      });

    }

  }
);









// ==========================================
// GET USER ORDERS
// ==========================================

app.get(
  "/api/orders",
  protect,
  async (req, res) => {

    try {

      const orders = await Order.find({
        userId: req.userId
      })
        .sort({ createdAt: -1 });

      res.json({
        success: true,
        orders
      });

    } catch (error) {

      console.error(
        "Get orders error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Unable to load orders."
      });

    }

  }
);



// ==========================================
// DASHBOARD ORDER SUMMARY
// ==========================================

app.get(
  "/api/orders/summary",
  protect,
  async (req, res) => {

    try {

      const orders = await Order.find({
        userId: req.userId
      });

      const totalOrders = orders.length;

      const pending = orders.filter(
        order =>
          String(order.status || "").toLowerCase() === "pending"
      ).length;

      const completed = orders.filter(
        order =>
          String(order.status || "").toLowerCase() === "completed"
      ).length;

      const totalSpent = orders.reduce(
        (total, order) =>
          total + Number(order.amount || 0),
        0
      );

      res.json({
        success: true,
        summary: {
          totalOrders,
          pending,
          completed,
          totalSpent
        }
      });

    } catch (error) {

      console.error(
        "Dashboard order summary error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Unable to load order summary."
      });

    }

  }
);





// ==========================================
// GET SINGLE ORDER
// ==========================================

app.get(
  "/api/orders/:id",
  protect,
  async (req, res) => {

    try {

      const order = await Order.findOne({
        _id: req.params.id,
        userId: req.userId
      });

      if (!order) {

        return res.status(404).json({
          success: false,
          message: "Order not found."
        });

      }

      res.json({
        success: true,
        order
      });

    } catch (error) {

      console.error(
        "Get single order error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Unable to load order."
      });

    }

  }
);

// ==========================================
// CHECK ORDER STATUS FROM OWLET
// ==========================================

app.get(
  "/api/orders/:id/status",
  protect,
  async (req, res) => {

    try {

      // ==========================================
      // FIND USER'S ORDER
      // ==========================================

      const order = await Order.findOne({
        _id: req.params.id,
        userId: req.userId
      });

      if (!order) {

        return res.status(404).json({
          success: false,
          message: "Order not found."
        });

      }


      // ==========================================
      // ASK OWLET FOR CURRENT STATUS
      // ==========================================

      const owletResponse = await axios.post(
        process.env.OWLET_API_URL,
        {
          key: process.env.OWLET_API_KEY,
          action: "status",
          order: order.providerOrderId
        },
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      );


      console.log(
        "OWLET STATUS RESPONSE:",
        owletResponse.data
      );


      const owletData = owletResponse.data;


      // ==========================================
      // CHECK OWLET ERROR
      // ==========================================

      if (
        !owletData ||
        owletData.error
      ) {

        return res.status(400).json({
          success: false,
          message:
            owletData?.error ||
            "Unable to get order status from Owlet."
        });

      }


      // ==========================================
      // GET STATUS
      // ==========================================

      const providerStatus =
        String(
          owletData.status || ""
        ).trim();


      if (!providerStatus) {

        return res.status(400).json({
          success: false,
          message: "Owlet did not return an order status."
        });

      }


      // ==========================================
      // NORMALIZE STATUS
      // ==========================================

      let newStatus =
        providerStatus.toLowerCase();


      if (
        newStatus === "in progress"
      ) {

        newStatus = "processing";

      }

      else if (
        newStatus === "processing"
      ) {

        newStatus = "processing";

      }

      else if (
        newStatus === "pending"
      ) {

        newStatus = "pending";

      }

      else if (
        newStatus === "completed"
      ) {

        newStatus = "completed";

      }

      else if (
        newStatus === "partial"
      ) {

        newStatus = "partial";

      }

      else if (
        newStatus === "cancelled" ||
        newStatus === "canceled"
      ) {

        newStatus = "cancelled";

      }

      else if (
        newStatus === "refunded"
      ) {

        newStatus = "refunded";

      }


      // ==========================================
      // SAVE OWLET DATA
      // ==========================================

      order.status =
        newStatus;

      order.remains =
        Number(
          owletData.remains || 0
        );

      order.startCount =
        Number(
          owletData.start_count || 0
        );

      order.providerCharge =
        Number(
          owletData.charge || 0
        );


      // ==========================================
      // HANDLE CANCEL / REFUND
      // ==========================================

      if (
        (
          newStatus === "cancelled" ||
          newStatus === "refunded"
        ) &&
        !order.refundProcessed
      ) {

        const user =
          await User.findById(
            order.userId
          );


        if (user) {

          // ======================================
          // REFUND CUSTOMER
          // ======================================

          user.balance =
            Number(user.balance || 0) +
            Number(order.amount || 0);

          await user.save();


          // ======================================
          // RECORD REFUND TRANSACTION
          // ======================================

          await Transaction.create({

            userId:
              order.userId,

            txRef:
              `REFUND-${order._id}`,

            type:
              "refund",

            amount:
              order.amount,

            currency:
              "NGN",

            status:
              "successful"

          });


          // ======================================
          // PREVENT DOUBLE REFUND
          // ======================================

          order.refundProcessed =
            true;

        }

      }


      // ==========================================
      // SAVE ORDER
      // ==========================================

      await order.save();


      // ==========================================
      // RETURN UPDATED ORDER
      // ==========================================

      res.json({

        success: true,

        order: {

          id:
            order._id,

          providerOrderId:
            order.providerOrderId,

          status:
            order.status,

          remains:
            order.remains,

          startCount:
            order.startCount,

          providerCharge:
            order.providerCharge,

          refundProcessed:
            order.refundProcessed

        }

      });


    } catch (error) {

      console.error(
        "Order status error:",
        error.response?.data ||
        error.message
      );


      res.status(500).json({

        success: false,

        message:
          "Unable to update order status."

      });

    }

  }
);




// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    const adminPassword = String(process.env.ADMIN_PASSWORD || "");

    if (!adminEmail || !adminPassword) {
      return res.status(503).json({
        success: false,
        message: "Admin credentials are not configured on the server."
      });
    }

    if (
      String(email || "").trim().toLowerCase() !== adminEmail ||
      String(password || "") !== adminPassword
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid admin email or password."
      });
    }

    const token = jwt.sign(
      {
        admin: true,
        email: adminEmail
      },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      success: true,
      message: "Admin login successful.",
      token,
      admin: {
        email: adminEmail
      }
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to login as admin."
    });
  }
});

app.get("/api/admin/me", adminProtect, (req, res) => {
  res.json({
    success: true,
    admin: {
      email: req.adminEmail
    }
  });
});


// ==========================================
// ADMIN DASHBOARD
// ==========================================

app.get("/api/admin/dashboard", adminProtect, async (req, res) => {
  try {
    const [
      userCount,
      orderCount,
      transactionCount,
      users,
      successfulDeposits,
      successfulOrders,
      pendingOrders,
      completedOrders,
      refundedOrders
    ] = await Promise.all([
      User.countDocuments(),
      Order.countDocuments(),
      Transaction.countDocuments(),
      User.find().select("fullName email balance createdAt").sort({ createdAt: -1 }).limit(8),
      Transaction.aggregate([
        { $match: { type: "deposit", status: "successful" } },
        { $group: { _id: null, total: { $sum: "$amount" } } }
      ]),
      Transaction.aggregate([
        { $match: { type: "order", status: "successful" } },
        { $group: { _id: null, total: { $sum: "$amount" } } }
      ]),
      Order.countDocuments({ status: { $in: ["pending", "processing", "in progress"] } }),
      Order.countDocuments({ status: "completed" }),
      Order.countDocuments({ status: { $in: ["cancelled", "refunded"] } })
    ]);

    const totalWalletBalance = await User.aggregate([
      { $group: { _id: null, total: { $sum: "$balance" } } }
    ]);

    res.json({
      success: true,
      stats: {
        users: userCount,
        orders: orderCount,
        transactions: transactionCount,
        walletBalance: Number(totalWalletBalance[0]?.total || 0),
        deposits: Number(successfulDeposits[0]?.total || 0),
        sales: Number(successfulOrders[0]?.total || 0),
        pendingOrders,
        completedOrders,
        refundedOrders
      },
      recentUsers: users
    });
  } catch (error) {
    console.error("Admin dashboard error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to load admin dashboard."
    });
  }
});


// ==========================================
// ADMIN USERS
// ==========================================

app.get("/api/admin/users", adminProtect, async (req, res) => {
  try {
    const search = String(req.query.search || "").trim();
    const page = Math.max(Number(req.query.page || 1), 1);
    const limit = Math.min(Math.max(Number(req.query.limit || 25), 1), 100);

    const filter = search
      ? {
          $or: [
            { fullName: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } }
          ]
        }
      : {};

    const [users, total] = await Promise.all([
      User.find(filter)
        .select("fullName email balance createdAt")
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      User.countDocuments(filter)
    ]);

    res.json({
      success: true,
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error("Admin users error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to load users."
    });
  }
});


// ==========================================
// ADMIN USER WALLET ADJUSTMENT
// ==========================================

app.post("/api/admin/users/:id/wallet", adminProtect, async (req, res) => {
  try {
    const { action, amount, reason } = req.body;
    const value = Number(amount);
    const note = String(reason || "").trim();

    if (!["credit", "debit"].includes(action) || !Number.isFinite(value) || value <= 0) {
      return res.status(400).json({
        success: false,
        message: "Provide a valid wallet action and positive amount."
      });
    }

    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    if (!note) {
      return res.status(400).json({
        success: false,
        message: "Please provide a reason for this wallet adjustment."
      });
    }

    if (action === "debit" && Number(user.balance || 0) < value) {
      return res.status(400).json({
        success: false,
        message: "User does not have enough wallet balance."
      });
    }

    const previousBalance = Number(user.balance || 0);
    user.balance =
      action === "credit"
        ? previousBalance + value
        : previousBalance - value;

    await user.save();

    await Transaction.create({
      userId: user._id,
      txRef: `ADMIN-${action.toUpperCase()}-${user._id}-${Date.now()}`,
      type: action === "credit" ? "admin_credit" : "admin_debit",
      amount: value,
      currency: "NGN",
      status: "successful"
    });

    await adminLog(
      req,
      action === "credit" ? "Credited user wallet" : "Debited user wallet",
      "user",
      user._id,
      `Email=${user.email}; Amount=NGN ${value.toLocaleString()}; Previous=NGN ${previousBalance.toLocaleString()}; New=NGN ${Number(user.balance).toLocaleString()}; Reason=${note}`
    );

    res.json({
      success: true,
      message: `Wallet ${action}ed successfully.`,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        balance: user.balance
      },
      reason: String(reason || "").trim()
    });
  } catch (error) {
    console.error("Admin wallet adjustment error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to update user wallet."
    });
  }
});


// ==========================================
// ADMIN ORDERS
// ==========================================

app.get("/api/admin/orders", adminProtect, async (req, res) => {
  try {
    const search = String(req.query.search || "").trim();
    const status = String(req.query.status || "").trim().toLowerCase();
    const page = Math.max(Number(req.query.page || 1), 1);
    const limit = Math.min(Math.max(Number(req.query.limit || 25), 1), 100);

    const filter = {};

    if (status) {
      filter.status = status;
    }

    if (search) {
      const matchingUsers = await User.find({
        $or: [
          { fullName: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } }
        ]
      }).select("_id");

      filter.$or = [
        { providerOrderId: { $regex: search, $options: "i" } },
        { serviceName: { $regex: search, $options: "i" } },
        { link: { $regex: search, $options: "i" } },
        { userId: { $in: matchingUsers.map(u => u._id) } }
      ];
    }

    const [orders, total] = await Promise.all([
      Order.find(filter)
        .populate("userId", "fullName email balance")
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      Order.countDocuments(filter)
    ]);

    res.json({
      success: true,
      orders,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error("Admin orders error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to load orders."
    });
  }
});


// ==========================================
// ADMIN TRANSACTIONS
// ==========================================

app.get("/api/admin/transactions", adminProtect, async (req, res) => {
  try {
    const page = Math.max(Number(req.query.page || 1), 1);
    const limit = Math.min(Math.max(Number(req.query.limit || 25), 1), 100);

    const [transactions, total] = await Promise.all([
      Transaction.find()
        .populate("userId", "fullName email")
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      Transaction.countDocuments()
    ]);

    res.json({
      success: true,
      transactions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error("Admin transactions error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to load transactions."
    });
  }
});


// ==========================================
// ADMIN PROVIDER
// ==========================================

app.get("/api/admin/provider", adminProtect, async (req, res) => {
  try {
    const [balanceResponse, servicesResponse] = await Promise.all([
      axios.post(
        process.env.OWLET_API_URL,
        {
          key: process.env.OWLET_API_KEY,
          action: "balance"
        },
        { headers: { "Content-Type": "application/json" } }
      ),
      axios.post(
        process.env.OWLET_API_URL,
        {
          key: process.env.OWLET_API_KEY,
          action: "services"
        },
        { headers: { "Content-Type": "application/json" } }
      )
    ]);

    const rawServices = Array.isArray(servicesResponse.data)
      ? servicesResponse.data
      : [];

    const savedPrices = await ServicePrice.find({}).lean();
    const priceMap = new Map(savedPrices.map(item => [String(item.serviceId), item]));
    const MARKUP_PERCENT = 68.35;

    const services = rawServices.slice(0, 100).map(service => {
      const providerRate = Number(service.rate || 0);
      const saved = priceMap.get(String(service.service));
      const defaultSelling = providerRate + (providerRate * MARKUP_PERCENT / 100);
      return {
        service: service.service,
        name: saved?.displayName || service.name,
        category: saved?.category || service.category,
        type: service.type,
        providerRate,
        sellingRate: saved ? Number(saved.sellingRate) : defaultSelling,
        enabled: saved?.enabled !== false,
        min: saved?.minOverride ?? service.min,
        max: saved?.maxOverride ?? service.max,
        refill: service.refill,
        dripfeed: service.dripfeed
      };
    });

    res.json({
      success: true,
      balance: balanceResponse.data,
      services
    });
  } catch (error) {
    console.error(
      "Admin provider error:",
      error.response?.data || error.message
    );
    res.status(500).json({
      success: false,
      message: "Unable to load provider information.",
      error: error.response?.data || undefined
    });
  }
});

// ==========================================
// ADMIN - SERVICE PRICE MANAGEMENT
// ==========================================

app.get("/api/admin/prices", adminProtect, async (req, res) => {
  try {
    const response = await axios.post(
      process.env.OWLET_API_URL,
      { key: process.env.OWLET_API_KEY, action: "services" },
      { headers: { "Content-Type": "application/json" } }
    );

    const owletServices = Array.isArray(response.data) ? response.data : [];
    const savedPrices = await ServicePrice.find({}).lean();
    const priceMap = new Map(savedPrices.map(item => [String(item.serviceId), item]));
    const defaultMarkup = 68.35;

    const services = owletServices.slice(0, 100).map(service => {
      const id = String(service.service);
      const providerRate = Number(service.rate || 0);
      const saved = priceMap.get(id);
      const defaultSellingRate = providerRate + (providerRate * defaultMarkup / 100);

      return {
        serviceId: id,
        name: service.name,
        category: service.category || "Other",
        providerRate,
        sellingRate: saved ? Number(saved.sellingRate) : defaultSellingRate,
        customized: Boolean(saved),
        min: service.min,
        max: service.max
      };
    });

    res.json({ success: true, services });
  } catch (error) {
    console.error("Admin prices error:", error.response?.data || error.message);
    res.status(500).json({ success: false, message: "Unable to load service prices." });
  }
});

app.put("/api/admin/prices/:serviceId", adminProtect, async (req, res) => {
  try {
    const serviceId = String(req.params.serviceId);
    const sellingRate = Number(req.body.sellingRate);

    if (!Number.isFinite(sellingRate) || sellingRate < 0) {
      return res.status(400).json({ success: false, message: "Enter a valid selling price." });
    }

    const response = await axios.post(
      process.env.OWLET_API_URL,
      { key: process.env.OWLET_API_KEY, action: "services" },
      { headers: { "Content-Type": "application/json" } }
    );

    const service = (Array.isArray(response.data) ? response.data : [])
      .find(item => String(item.service) === serviceId);

    if (!service) {
      return res.status(404).json({ success: false, message: "Provider service not found." });
    }

    const saved = await ServicePrice.findOneAndUpdate(
      { serviceId },
      {
        serviceId,
        name: service.name || "",
        category: service.category || "",
        providerRate: Number(service.rate || 0),
        sellingRate,
        updatedBy: req.admin?.email || "admin"
      },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    res.json({ success: true, message: "Selling price updated successfully.", price: saved });
  } catch (error) {
    console.error("Update service price error:", error.response?.data || error.message);
    res.status(500).json({ success: false, message: "Unable to update selling price." });
  }
});

app.delete("/api/admin/prices/:serviceId", adminProtect, async (req, res) => {
  try {
    await ServicePrice.deleteOne({ serviceId: String(req.params.serviceId) });
    res.json({ success: true, message: "Custom price removed. The default markup will be used again." });
  } catch (error) {
    console.error("Reset service price error:", error.message);
    res.status(500).json({ success: false, message: "Unable to reset service price." });
  }
});


// ==========================================
// ADMIN - HELPERS / LOGS
// ==========================================
async function adminLog(req, action, targetType = "", targetId = "", details = "") {
  try { await AdminLog.create({ adminEmail: req.adminEmail || req.admin?.email || "admin", action, targetType, targetId: String(targetId || ""), details }); } catch (e) { console.error("Admin log error:", e.message); }
}

app.get("/api/admin/activity", adminProtect, async (req, res) => {
  try {
    const logs = await AdminLog.find({}).sort({ createdAt: -1 }).limit(200);
    res.json({ success: true, logs });
  } catch (e) { res.status(500).json({ success:false, message:"Unable to load activity logs." }); }
});

// ==========================================
// ADMIN - SERVICE MANAGEMENT
// ==========================================
app.get("/api/admin/services", adminProtect, async (req, res) => {
  try {
    const response = await axios.post(process.env.OWLET_API_URL, { key:process.env.OWLET_API_KEY, action:"services" }, { headers:{"Content-Type":"application/json"} });
    const raw = Array.isArray(response.data) ? response.data : [];
    const saved = await ServicePrice.find({}).lean();
    const map = new Map(saved.map(x => [String(x.serviceId), x]));
    const services = raw.slice(0, 200).map(x => {
      const o = map.get(String(x.service));
      return { serviceId:String(x.service), name:x.name, category:x.category || "Other", providerRate:Number(x.rate||0), min:x.min, max:x.max, enabled:o?.enabled !== false, displayName:o?.displayName || x.name, description:o?.description || "", minOverride:o?.minOverride ?? null, maxOverride:o?.maxOverride ?? null };
    });
    res.json({ success:true, services });
  } catch(e) { res.status(500).json({success:false,message:"Unable to load services."}); }
});
app.put("/api/admin/services/:serviceId", adminProtect, async (req,res) => {
  try {
    const serviceId=String(req.params.serviceId); const body=req.body||{};
    const response=await axios.post(process.env.OWLET_API_URL,{key:process.env.OWLET_API_KEY,action:"services"},{headers:{"Content-Type":"application/json"}});
    const service=(Array.isArray(response.data)?response.data:[]).find(x=>String(x.service)===serviceId);
    if(!service) return res.status(404).json({success:false,message:"Provider service not found."});
    const saved=await ServicePrice.findOneAndUpdate({serviceId},{serviceId,name:service.name||"",category:service.category||"",providerRate:Number(service.rate||0),sellingRate:Number(body.sellingRate ?? (Number(service.rate||0)*1.6835)),enabled:body.enabled!==false,displayName:String(body.displayName||service.name||""),description:String(body.description||""),minOverride:body.minOverride===""||body.minOverride==null?null:Number(body.minOverride),maxOverride:body.maxOverride===""||body.maxOverride==null?null:Number(body.maxOverride),updatedBy:req.adminEmail||"admin"},{new:true,upsert:true,setDefaultsOnInsert:true});
    await adminLog(req,"Updated service","service",serviceId,`Enabled=${saved.enabled}; display=${saved.displayName}`);
    res.json({success:true,message:"Service updated successfully.",service:saved});
  } catch(e){res.status(500).json({success:false,message:"Unable to update service."});}
});

// ==========================================
// ADMIN - USER MANAGEMENT
// ==========================================
app.patch("/api/admin/users/:id/status", adminProtect, async (req,res)=>{
  try { const user=await User.findByIdAndUpdate(req.params.id,{active:req.body.active!==false},{new:true}).select("fullName email balance active createdAt"); if(!user)return res.status(404).json({success:false,message:"User not found."}); await adminLog(req,user.active?"Activated user":"Suspended user","user",user._id,user.email); res.json({success:true,user}); }
  catch(e){res.status(500).json({success:false,message:"Unable to update user status."});}
});
app.get("/api/admin/users/:id", adminProtect, async (req,res)=>{
  try { const user=await User.findById(req.params.id).select("-password -resetPasswordToken -resetPasswordExpires"); if(!user)return res.status(404).json({success:false,message:"User not found."}); const orders=await Order.find({userId:user._id}).sort({createdAt:-1}).limit(50); const transactions=await Transaction.find({userId:user._id}).sort({createdAt:-1}).limit(50); res.json({success:true,user,orders,transactions}); }
  catch(e){res.status(500).json({success:false,message:"Unable to load user details."});}
});

// ==========================================
// ADMIN - ORDER CONTROL
// ==========================================
app.patch("/api/admin/orders/:id", adminProtect, async (req,res)=>{
  try {
    const order=await Order.findById(req.params.id); if(!order)return res.status(404).json({success:false,message:"Order not found."});
    const status=String(req.body.status||order.status).toLowerCase();
    if (!["pending","processing","completed","partial","cancelled","refunded"].includes(status)) return res.status(400).json({success:false,message:"Invalid order status."});
    if ((status==="cancelled"||status==="refunded") && !order.refundProcessed) {
      const user=await User.findById(order.userId); if(user){ user.balance=Number(user.balance||0)+Number(order.amount||0); await user.save(); await Transaction.create({userId:user._id,txRef:`ADMIN-REFUND-${order._id}-${Date.now()}`,type:"refund",amount:order.amount,currency:"NGN",status:"successful"}); order.refundProcessed=true; }
    }
    order.status=status; await order.save(); await adminLog(req,"Updated order status","order",order._id,`Status=${status}`); res.json({success:true,message:"Order updated.",order});
  } catch(e){res.status(500).json({success:false,message:"Unable to update order."});}
});

// ==========================================
// ADMIN - DEPOSITS / WITHDRAWALS
// ==========================================
app.get("/api/admin/deposits", adminProtect, async (req,res)=>{
  try { const transactions=await Transaction.find({type:"deposit"}).populate("userId","fullName email").sort({createdAt:-1}).limit(200); res.json({success:true,transactions}); }
  catch(e){res.status(500).json({success:false,message:"Unable to load deposits."});}
});
app.get("/api/admin/withdrawals", adminProtect, async (req,res)=>{
  try { const withdrawals=await Withdrawal.find({}).populate("userId","fullName email").sort({createdAt:-1}).limit(200); res.json({success:true,withdrawals}); }
  catch(e){res.status(500).json({success:false,message:"Unable to load withdrawals."});}
});
app.patch("/api/admin/withdrawals/:id", adminProtect, async (req,res)=>{
  try { const w=await Withdrawal.findById(req.params.id); if(!w)return res.status(404).json({success:false,message:"Withdrawal not found."}); const next=String(req.body.status||""); if(!["pending","approved","rejected"].includes(next))return res.status(400).json({success:false,message:"Invalid withdrawal status."}); w.status=next; w.note=String(req.body.note||w.note||""); await w.save(); await adminLog(req,`Withdrawal ${next}`,"withdrawal",w._id,w.note); res.json({success:true,withdrawal:w}); }
  catch(e){res.status(500).json({success:false,message:"Unable to update withdrawal."});}
});

// ==========================================
// ADMIN - COUPONS
// ==========================================
app.get("/api/admin/coupons", adminProtect, async (req,res)=>{ try{res.json({success:true,coupons:await Coupon.find({}).sort({createdAt:-1})});}catch(e){res.status(500).json({success:false,message:"Unable to load coupons."});} });
app.post("/api/admin/coupons", adminProtect, async (req,res)=>{ try{const b=req.body||{}; const coupon=await Coupon.create({code:String(b.code||"").trim().toUpperCase(),type:b.type||"percent",value:Number(b.value||0),minOrder:Number(b.minOrder||0),maxDiscount:Number(b.maxDiscount||0),usageLimit:Number(b.usageLimit||0),expiresAt:b.expiresAt||null,active:b.active!==false}); await adminLog(req,"Created coupon","coupon",coupon._id,coupon.code); res.json({success:true,coupon});}catch(e){res.status(400).json({success:false,message:e.code===11000?"Coupon code already exists.":"Unable to create coupon."});} });
app.patch("/api/admin/coupons/:id", adminProtect, async (req,res)=>{ try{const allowed=["code","type","value","minOrder","maxDiscount","usageLimit","expiresAt","active"];const update={};for(const k of allowed)if(req.body[k]!==undefined)update[k]=k==="code"?String(req.body[k]).toUpperCase():req.body[k];const c=await Coupon.findByIdAndUpdate(req.params.id,update,{new:true});if(!c)return res.status(404).json({success:false,message:"Coupon not found."});await adminLog(req,"Updated coupon","coupon",c._id,c.code);res.json({success:true,coupon:c});}catch(e){res.status(400).json({success:false,message:"Unable to update coupon."});} });
app.delete("/api/admin/coupons/:id", adminProtect, async (req,res)=>{try{await Coupon.findByIdAndDelete(req.params.id);await adminLog(req,"Deleted coupon","coupon",req.params.id);res.json({success:true,message:"Coupon deleted."});}catch(e){res.status(500).json({success:false,message:"Unable to delete coupon."});}});

// ==========================================
// ADMIN - ANNOUNCEMENTS
// ==========================================
app.get("/api/admin/announcements", adminProtect, async(req,res)=>{try{res.json({success:true,announcements:await Announcement.find({}).sort({createdAt:-1})});}catch(e){res.status(500).json({success:false,message:"Unable to load announcements."});}});
app.post("/api/admin/announcements", adminProtect, async(req,res)=>{try{const a=await Announcement.create(req.body);await adminLog(req,"Created announcement","announcement",a._id,a.title);res.json({success:true,announcement:a});}catch(e){res.status(400).json({success:false,message:"Unable to create announcement."});}});
app.patch("/api/admin/announcements/:id", adminProtect, async(req,res)=>{try{const a=await Announcement.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!a)return res.status(404).json({success:false,message:"Announcement not found."});await adminLog(req,"Updated announcement","announcement",a._id,a.title);res.json({success:true,announcement:a});}catch(e){res.status(400).json({success:false,message:"Unable to update announcement."});}});
app.delete("/api/admin/announcements/:id", adminProtect, async(req,res)=>{try{await Announcement.findByIdAndDelete(req.params.id);await adminLog(req,"Deleted announcement","announcement",req.params.id);res.json({success:true,message:"Announcement deleted."});}catch(e){res.status(500).json({success:false,message:"Unable to delete announcement."});}});
app.get("/api/announcements", async(req,res)=>{try{const now=new Date();const announcements=await Announcement.find({active:true,$or:[{expiresAt:null},{expiresAt:{$gt:now}}]}).sort({createdAt:-1}).limit(10);res.json({success:true,announcements});}catch(e){res.status(500).json({success:false,message:"Unable to load announcements."});}});

// ==========================================
// ADMIN - SETTINGS
// ==========================================
app.get("/api/admin/settings", adminProtect, async(req,res)=>{res.json({success:true,settings:{websiteName:process.env.WEBSITE_NAME||"OG Boosting",supportEmail:process.env.SUPPORT_EMAIL||"",whatsapp:process.env.SUPPORT_WHATSAPP||"",currency:"NGN",maintenanceMode:process.env.MAINTENANCE_MODE==="true",registrationEnabled:process.env.REGISTRATION_ENABLED!=="false",defaultMarkup:68.35}});});
app.put("/api/admin/settings", adminProtect, async(req,res)=>{try{const envPath=path.join(__dirname,".env");let env=fs.existsSync(envPath)?fs.readFileSync(envPath,"utf8"):"";const fields={WEBSITE_NAME:req.body.websiteName,SUPPORT_EMAIL:req.body.supportEmail,SUPPORT_WHATSAPP:req.body.whatsapp,MAINTENANCE_MODE:req.body.maintenanceMode?"true":"false",REGISTRATION_ENABLED:req.body.registrationEnabled===false?"false":"true"};for(const [k,v] of Object.entries(fields)){const line=`${k}=${String(v??"").replace(/\n/g,"")}`;const re=new RegExp(`^${k}=.*$`,`m`);env=re.test(env)?env.replace(re,line):env+`\n${line}`;}fs.writeFileSync(envPath,env);for(const[k,v]of Object.entries(fields))process.env[k]=v;await adminLog(req,"Updated website settings","settings","",Object.keys(fields).join(","));res.json({success:true,message:"Settings saved."});}catch(e){res.status(500).json({success:false,message:"Unable to save settings."});}});

// ==========================================
// ADMIN - CHANGE PASSWORD / SECURITY
// ==========================================
app.post("/api/admin/change-password", adminProtect, async(req,res)=>{try{const current=String(req.body.currentPassword||"");const next=String(req.body.newPassword||"");if(current!==String(process.env.ADMIN_PASSWORD||""))return res.status(401).json({success:false,message:"Current password is incorrect."});if(next.length<8)return res.status(400).json({success:false,message:"New password must be at least 8 characters."});const envPath=path.join(__dirname,".env");let env=fs.existsSync(envPath)?fs.readFileSync(envPath,"utf8"):"";const re=/^ADMIN_PASSWORD=.*$/m;env=re.test(env)?env.replace(re,`ADMIN_PASSWORD=${next}`):env+`\nADMIN_PASSWORD=${next}`;fs.writeFileSync(envPath,env);process.env.ADMIN_PASSWORD=next;await adminLog(req,"Changed admin password");res.json({success:true,message:"Admin password changed. Please log in again."});}catch(e){res.status(500).json({success:false,message:"Unable to change admin password."});}});

// ==========================================
// ADMIN - REVENUE / PROFIT
// ==========================================
app.get("/api/admin/revenue", adminProtect, async(req,res)=>{try{const orders=await Order.find({}).lean();const sales=orders.reduce((a,o)=>a+Number(o.amount||0),0);const provider=orders.reduce((a,o)=>a+Number(o.providerCharge||0),0);const completed=orders.filter(o=>String(o.status).toLowerCase()==="completed");res.json({success:true,summary:{sales,providerCost:provider,profit:sales-provider,completedOrders:completed.length},orders:orders.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).slice(0,200)});}catch(e){res.status(500).json({success:false,message:"Unable to load revenue report."});}});


// ===============================
// SERVER
// ===============================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {

  console.log(
    `OG Boosting server running on http://localhost:${PORT}`
  );

});