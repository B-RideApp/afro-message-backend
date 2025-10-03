import express from "express";
import fetch from "node-fetch";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cors from "cors";

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 OTP requests per windowMs
  message: {
    error: "Too many OTP requests, please try again later",
    retryAfter: "15 minutes"
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json({ limit: '10mb' }));

// Simple API key authentication
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const validApiKey = process.env.BRIDE_API_KEY;
  
  if (!validApiKey) {
    console.error('❌ BRIDE_API_KEY not configured');
    return res.status(500).json({ error: "Server configuration error" });
  }
  
  if (!apiKey || apiKey !== validApiKey) {
    console.warn('⚠️ Unauthorized API access attempt');
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  next();
};

// Health check (no auth required)
app.get("/", (req, res) => {
  res.json({
    status: "healthy",
    message: "B-RIDE AfroMessage Backend is running 🚀",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Health check with auth (for monitoring)
app.get("/health", validateApiKey, (req, res) => {
  const afroToken = process.env.AFROMESSAGE_TOKEN;
  const afroId = process.env.AFROMESSAGE_IDENTIFIER_ID;
  
  res.json({
    status: "healthy",
    credentials: {
      afromessage_token: afroToken ? "configured" : "missing",
      afromessage_identifier: afroId ? "configured" : "missing"
    },
    timestamp: new Date().toISOString()
  });
});

// OTP endpoint with security
app.post("/send-otp", otpLimiter, validateApiKey, async (req, res) => {
  const { phone, otp } = req.body;

  // Input validation
  if (!phone || !otp) {
    return res.status(400).json({ 
      error: "Phone and OTP are required",
      details: {
        phone: !phone ? "Phone number is required" : null,
        otp: !otp ? "OTP is required" : null
      }
    });
  }

  // Validate phone format (basic validation)
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;
  if (!phoneRegex.test(phone)) {
    return res.status(400).json({ 
      error: "Invalid phone number format",
      details: "Phone should be in international format (+1234567890)"
    });
  }

  // Validate OTP format
  if (!/^\d{4,8}$/.test(otp)) {
    return res.status(400).json({ 
      error: "Invalid OTP format",
      details: "OTP should be 4-8 digits"
    });
  }

  // Check environment variables
  const afroToken = process.env.AFROMESSAGE_TOKEN;
  const afroId = process.env.AFROMESSAGE_IDENTIFIER_ID;
  
  if (!afroToken || !afroId) {
    console.error('❌ Missing AfroMessage credentials');
    return res.status(500).json({ 
      error: "Server configuration error",
      details: "AfroMessage credentials not configured"
    });
  }

  try {
    console.log(`📱 Sending OTP to ${phone.substring(0, 4)}****`);
    
    const response = await fetch("https://api.afromessage.com/send", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${afroToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        identifier: afroId,
        to: phone,
        message: `Your B-RIDE verification code is ${otp}. This code expires in 10 minutes.`
      })
    });

    const result = await response.json();
    
    if (!response.ok) {
      console.error('❌ AfroMessage API error:', result);
      return res.status(response.status).json({
        error: "Failed to send OTP",
        details: result.message || "AfroMessage service error"
      });
    }

    console.log(`✅ OTP sent successfully to ${phone.substring(0, 4)}****`);
    
    // Return success without exposing sensitive data
    res.json({
      success: true,
      message: "OTP sent successfully",
      messageId: result.messageId || result.id,
      timestamp: new Date().toISOString()
    });
    
  } catch (err) {
    console.error('❌ Error sending OTP:', err);
    res.status(500).json({ 
      error: "Failed to send OTP",
      details: "Internal server error"
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({
    error: "Internal server error",
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path,
    method: req.method
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 B-RIDE Backend running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔑 API Key configured: ${process.env.BRIDE_API_KEY ? 'Yes' : 'No'}`);
  console.log(`📱 AfroMessage configured: ${process.env.AFROMESSAGE_TOKEN ? 'Yes' : 'No'}`);
});
