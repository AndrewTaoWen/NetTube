import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../error.js";
import jwt from "jsonwebtoken";
import { getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";

const credentialsValid = (name, password) =>
  typeof name === "string" && name.length > 0 && name.length <= 150 &&
  typeof password === "string" && password.length >= 8 && Buffer.byteLength(password) <= 72;

const sendSession = (res, user) => {
  const token = jwt.sign({ id: String(user._id) }, process.env.JWT, { algorithm: "HS256", expiresIn: "1h" });
  const { password, ...profile } = user._doc;
  return res.cookie("access_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 60 * 60 * 1000,
  }).status(200).json(profile);
};

export const signup = async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};
    if (!credentialsValid(name, password) || typeof email !== "string" || email.length > 254 || !email.includes("@")) {
      return next(createError(400, "Valid name, email, and password (8–72 bytes) are required."));
    }
    const hash = await bcrypt.hash(password, 10);
    // Never accept account flags or subscription fields from the caller.
    await new User({ name, email, password: hash }).save();
    return res.status(201).send("User has been created!");
  } catch (err) { next(err); }
};

export const signin = async (req, res, next) => {
  try {
    const { name, password } = req.body || {};
    if (!credentialsValid(name, password)) return next(createError(401, "Invalid credentials."));
    const user = await User.findOne({ name });
    if (!user?.password || !(await bcrypt.compare(password, user.password))) {
      return next(createError(401, "Invalid credentials."));
    }
    return sendSession(res, user);
  } catch (err) { next(err); }
};

export const googleAuth = async (req, res, next) => {
  const idToken = req.body?.idToken;
  if (typeof idToken !== "string" || !idToken || idToken.length > 10000) {
    return next(createError(401, "A verified Firebase ID token is required."));
  }
  if (!process.env.FIREBASE_PROJECT_ID) return next(createError(503, "Google sign-in is not configured."));
  let claims;
  try {
    const app = getApps()[0] || initializeApp({ projectId: process.env.FIREBASE_PROJECT_ID });
    claims = await getAuth(app).verifyIdToken(idToken);
    if (!claims.email_verified || !claims.email || claims.firebase?.sign_in_provider !== "google.com") {
      return next(createError(401, "A verified Google identity is required."));
    }
  } catch { return next(createError(401, "Invalid identity token.")); }
  try {
    let user = await User.findOne({ email: claims.email });
    // Linking password accounts requires reauthentication by their owner.
    if (user && (!user.fromGoogle || user.firebaseUid !== claims.uid)) {
      return next(createError(403, "Sign in with the original account method before linking Google."));
    }
    if (!user) {
      user = await new User({ name: claims.name || claims.uid, email: claims.email,
        img: claims.picture, fromGoogle: true, firebaseUid: claims.uid }).save();
    }
    return sendSession(res, user);
  } catch (err) { next(err); }
};
