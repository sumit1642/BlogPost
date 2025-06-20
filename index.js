// index.js
import { PrismaClient } from "@prisma/client";
import express from "express";
import { authRoutes } from "./routes/MainAuth.js";
import { postsRoutes } from "./routes/MainPosts.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const prisma = new PrismaClient();

app.use(
	cors({
		origin: process.env.FRONTEND_URL || "http://localhost:5173",
		credentials: true,
	}),
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET || "yourSecretHere"));

app.use("/api/auth", authRoutes);
app.use("/api", postsRoutes);

// *, specifies that if there are no routes      
app.use("*", (req, res) => {
	res.status(404).json({
		status: "error",
		message: "Route not found",
		code: 404,
	});
});

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});

const gracefulShutdown = async (signal) => {
	console.log(`Received ${signal}. Shutting down gracefully...`);

	server.close(() => {
		console.log("HTTP server closed.");
	});

	await prisma.$disconnect();
	console.log("Database connection closed.");

	process.exit(0);
};

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

process.on("unhandledRejection", (reason, promise) => {
	console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

process.on("uncaughtException", (error) => {
	console.error("Uncaught Exception:", error);
	process.exit(1);
});
