// index.js
import { PrismaClient } from "@prisma/client";
import express from "express";
import { authRoutes } from "./routes/MainAuth.js";
import { postsRoutes } from "./routes/MainPosts.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const app = express();
const prisma = new PrismaClient();

// Middleware setup
app.use(
	cors({
		origin: process.env.FRONTEND_URL || "http://localhost:5173",
		credentials: true,
	}),
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET || "yourSecretHere"));

// Routes setup
app.use("/api/auth", authRoutes);
app.use("/api", postsRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
	res.status(200).json({
		status: "success",
		message: "Server is running",
		timestamp: new Date().toISOString(),
	});
});

// Global error handler
app.use((err, req, res, next) => {
	console.error("Unhandled error:", err);
	res.status(500).json({
		status: "error",
		message: "Internal server error",
		code: 500,
	});
});

// 404 handler
app.use("*", (req, res) => {
	res.status(404).json({
		status: "error",
		message: "Route not found",
		code: 404,
	});
});

const PORT = process.env.PORT || 3000;

// Start server
const server = app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
	console.log(`Received ${signal}. Shutting down gracefully...`);

	// Close server
	server.close(() => {
		console.log("HTTP server closed.");
	});

	// Disconnect Prisma
	await prisma.$disconnect();
	console.log("Database connection closed.");

	process.exit(0);
};

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
	console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
	console.error("Uncaught Exception:", error);
	process.exit(1);
});
