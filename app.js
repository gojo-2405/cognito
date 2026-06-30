require("dotenv").config();

const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const morgan = require("morgan");
const { Issuer, generators } = require("openid-client");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true when running behind HTTPS
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

app.use(helmet());
app.use(morgan("dev"));

app.use(express.static("public"));

let client;

// Initialize Cognito OIDC Client
async function initializeClient() {
  try {
    const issuer = await Issuer.discover(
      `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.USER_POOL_ID}`
    );

    client = new issuer.Client({
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      redirect_uris: [process.env.CALLBACK_URL],
      response_types: ["code"]
    });

    console.log("✅ Cognito Client Initialized");
  } catch (err) {
    console.error("❌ Failed to initialize Cognito Client");
    console.error(err);
    process.exit(1);
  }
}

initializeClient();

// Middleware
function isAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/");
  }
  next();
}

// Health Check (ECS ALB)
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "UP",
    service: "cognito-demo"
  });
});

// Home
app.get("/", (req, res) => {
  res.render("home", {
    user: req.session.user || null
  });
});

// Login
app.get("/login", (req, res) => {
  const nonce = generators.nonce();
  const state = generators.state();

  req.session.nonce = nonce;
  req.session.state = state;

  const authorizationUrl = client.authorizationUrl({
    scope: "openid email profile",
    response_mode: "query",
    response_type: "code",
    state,
    nonce
  });

  res.redirect(authorizationUrl);
});

// Signup
app.get("/signup", (req, res) => {
  const signupUrl =
    `${process.env.COGNITO_DOMAIN}/signup` +
    `?client_id=${process.env.CLIENT_ID}` +
    `&response_type=code` +
    `&scope=openid+email+profile` +
    `&redirect_uri=${encodeURIComponent(process.env.CALLBACK_URL)}`;

  res.redirect(signupUrl);
});

// Callback
app.get("/callback", async (req, res) => {
  try {
    const params = client.callbackParams(req);

    const tokenSet = await client.callback(
      process.env.CALLBACK_URL,
      params,
      {
        nonce: req.session.nonce,
        state: req.session.state
      }
    );

    const userInfo = await client.userinfo(tokenSet.access_token);

    req.session.user = userInfo;
    req.session.tokens = {
      access_token: tokenSet.access_token,
      id_token: tokenSet.id_token,
      refresh_token: tokenSet.refresh_token
    };

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.render("error", {
      message: err.message
    });
  }
});

// Dashboard
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.render("dashboard", {
    user: req.session.user,
    tokens: req.session.tokens
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    const logoutUrl =
      `${process.env.COGNITO_DOMAIN}/logout` +
      `?client_id=${process.env.CLIENT_ID}` +
      `&logout_uri=${encodeURIComponent(process.env.LOGOUT_URL)}`;

    res.redirect(logoutUrl);
  });
});

// 404
app.use((req, res) => {
  res.status(404).render("error", {
    message: "Page Not Found"
  });
});

// Start Server
app.listen(PORT, () => {
  console.log("====================================");
  console.log(`🚀 Server Running on Port ${PORT}`);
  console.log(`🌍 http://localhost:${PORT}`);
  console.log("====================================");
});
