// index.js
import { PrismaClient } from "@prisma/client";
import express from "express";
import { authRoutes } from "./routes/MainAuth.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import { postsRoutes } from "./routes/MainPosts.js";
const app = express();
const prisma = new PrismaClient();

app.use(
	cors({
		origin: "http://localhost:5173",
		credentials: true,
	}),
);

app.use(express.json());
app.use(cookieParser("yourSecretHere"));
app.use("/", authRoutes);
app.use("/",postsRoutes)
app.listen(3000);
