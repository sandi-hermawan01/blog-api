import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import "dotenv/config";
import { nanoid } from "nanoid";
import admin from "firebase-admin";
import { getAuth } from "firebase-admin/auth";
import aws from "aws-sdk";
import rateLimit from "express-rate-limit";

// mongoose data schemas.

import User from "../Schema/User.js";
import Blog from "../Schema/Blog.js";
import Notification from "../Schema/Notification.js";
import Comment from "../Schema/Comment.js";

const server = express();
const PORT = process.env.PORT || 3003;
const slatRounds = 10; // slat rounds for bcryptjs

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: true,
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

// initializing the firebaserun

import serviceAccount from "../blog-publisher-v2.json" assert { type: "json" };

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// middlewares
server.use(express.json()); // enable JSON sharing
server.use(cors());
server.use(limiter);

server.get("/", (req, res) => {
  res.json("Welcome, this is Home Api");
});

// AWS setup

server.listen(PORT, () => {
  console.log("listening on port -> " + PORT);
});
