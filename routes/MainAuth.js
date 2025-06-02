// routes/MainAuth.js
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import express from "express";
import {
	validateRegisterInput,
	checkIfUserExists,
	validateLoginInput,
	getUserByEmail,
} from "../middlewares/MainAuthMiddlewares.js";

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const authRoutes = express.Router();

// JWT secrets from environment or fallback
const JWT_SECRET = process.env.JWT_SECRET || "jwtsupersecretkey";
const REFRESH_TOKEN_SECRET =
	process.env.REFRESH_TOKEN_SECRET || "refreshTokenSecretKey";

// Enhanced registration route with transaction
authRoutes.post(
	"/register",
	validateRegisterInput,
	checkIfUserExists,
	async (req, res) => {
		try {
			const { name, email, password, bio } = req.body;

			// Hash password with higher salt rounds for better security
			const hashedPassword = await bcrypt.hash(password, 12);

			// Use transaction for atomicity
			const newUser = await prisma.$transaction(async (tx) => {
				const user = await tx.user.create({
					data: {
						name,
						email,
						password: hashedPassword,
						profile: bio
							? { create: { bio: bio.trim() } }
							: undefined,
					},
					include: {
						profile: true,
					},
				});

				// Remove password from response
				const { password: _, ...userWithoutPassword } = user;
				return userWithoutPassword;
			});

			return res.status(201).json({
				status: "success",
				message: "User registered successfully",
				data: { user: newUser },
			});
		} catch (error) {
			console.error("Registration error:", error);

			// Handle Prisma unique constraint violations
			if (error.code === "P2002") {
				return res.status(409).json({
					status: "error",
					message: "User with that email already exists",
					code: 409,
				});
			}

			return res.status(500).json({
				status: "error",
				message: "Internal server error",
				code: 500,
			});
		}
	},
);

// Enhanced login route with proper session management
authRoutes.post(
	"/login",
	validateLoginInput,
	getUserByEmail,
	async (req, res) => {
		try {
			const { password } = req.body;
			const user = req.foundUser;

			// Verify password with timing attack protection
			const validPassword = await bcrypt.compare(password, user.password);
			if (!validPassword) {
				return res.status(401).json({
					status: "error",
					message: "Invalid email or password",
					code: 401,
				});
			}

			// Clean up existing refresh tokens for this user
			await prisma.refreshToken.deleteMany({
				where: {
					userId: user.id,
					// Also clean up expired tokens
					OR: [{ expiresAt: { lt: new Date() } }],
				},
			});

			// Generate tokens with appropriate expiration
			const accessToken = jwt.sign(
				{ user_ID: user.id, email: user.email },
				JWT_SECRET,
				{ expiresIn: "15m" },
			);

			const refreshToken = jwt.sign(
				{ user_ID: user.id },
				REFRESH_TOKEN_SECRET,
				{ expiresIn: "30d" },
			);

			// Store refresh token in database
			const expiresAt = new Date();
			expiresAt.setDate(expiresAt.getDate() + 30);

			await prisma.refreshToken.create({
				data: {
					token: refreshToken,
					userId: user.id,
					expiresAt,
				},
			});

			// Set secure cookies
			const isProduction = process.env.NODE_ENV === "production";

			res.cookie("token", accessToken, {
				httpOnly: true,
				secure: isProduction,
				signed: true,
				maxAge: 15 * 60 * 1000, // 15 minutes
				sameSite: "lax",
			});

			res.cookie("refreshToken", refreshToken, {
				httpOnly: true,
				secure: isProduction,
				signed: true,
				maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
				sameSite: "lax",
			});

			// Remove password from user object for response
			const { password: _, ...userWithoutPassword } = user;

			return res.status(200).json({
				status: "success",
				message: "Logged in successfully",
				data: {
					user: userWithoutPassword,
					accessToken,
					refreshToken,
				},
			});
		} catch (error) {
			console.error("Login error:", error);
			return res.status(500).json({
				status: "error",
				message: "Internal server error",
				code: 500,
			});
		}
	},
);

// Enhanced refresh token route with security checks
authRoutes.post("/refresh-token", async (req, res) => {
	try {
		const oldRefreshToken = req.signedCookies.refreshToken;

		if (!oldRefreshToken) {
			return res.status(401).json({
				status: "error",
				message: "No refresh token provided",
				code: 401,
			});
		}

		// Verify JWT signature
		let payload;
		try {
			payload = jwt.verify(oldRefreshToken, REFRESH_TOKEN_SECRET);
		} catch (jwtError) {
			return res.status(403).json({
				status: "error",
				message: "Invalid refresh token",
				code: 403,
			});
		}

		// Check token in database and verify expiration
		const storedToken = await prisma.refreshToken.findUnique({
			where: { token: oldRefreshToken },
			include: {
				user: {
					select: { id: true, email: true, name: true },
				},
			},
		});

		if (!storedToken || new Date() > storedToken.expiresAt) {
			// Clean up expired or invalid tokens
			if (storedToken) {
				await prisma.refreshToken.delete({
					where: { token: oldRefreshToken },
				});
			}

			return res.status(403).json({
				status: "error",
				message: "Refresh token expired or invalid",
				code: 403,
			});
		}

		// Generate new tokens
		const newAccessToken = jwt.sign(
			{ user_ID: payload.user_ID, email: storedToken.user.email },
			JWT_SECRET,
			{ expiresIn: "15m" },
		);

		const newRefreshToken = jwt.sign(
			{ user_ID: payload.user_ID },
			REFRESH_TOKEN_SECRET,
			{ expiresIn: "30d" },
		);

		// Atomic token replacement
		await prisma.$transaction(async (tx) => {
			// Remove old token
			await tx.refreshToken.delete({
				where: { token: oldRefreshToken },
			});

			// Create new token
			const expiresAt = new Date();
			expiresAt.setDate(expiresAt.getDate() + 30);

			await tx.refreshToken.create({
				data: {
					token: newRefreshToken,
					userId: payload.user_ID,
					expiresAt,
				},
			});
		});

		// Set new cookies
		const isProduction = process.env.NODE_ENV === "production";

		res.cookie("token", newAccessToken, {
			httpOnly: true,
			secure: isProduction,
			signed: true,
			maxAge: 15 * 60 * 1000, // 15 minutes
			sameSite: "lax",
		});

		res.cookie("refreshToken", newRefreshToken, {
			httpOnly: true,
			secure: isProduction,
			signed: true,
			maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
			sameSite: "lax",
		});

		return res.status(200).json({
			status: "success",
			message: "Tokens refreshed successfully",
			data: {
				accessToken: newAccessToken,
				refreshToken: newRefreshToken,
			},
		});
	} catch (error) {
		console.error("Token refresh error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});

// Enhanced logout route with proper cleanup
authRoutes.post("/logout", async (req, res) => {
	try {
		const refreshToken = req.signedCookies.refreshToken;

		if (!refreshToken) {
			// Clear any existing cookies even if no refresh token
			const isProduction = process.env.NODE_ENV === "production";

			res.clearCookie("token", {
				httpOnly: true,
				secure: isProduction,
				sameSite: "lax",
				signed: true,
			});
			res.clearCookie("refreshToken", {
				httpOnly: true,
				secure: isProduction,
				sameSite: "lax",
				signed: true,
			});

			return res.status(200).json({
				status: "success",
				message: "Logged out successfully",
			});
		}

		// Verify and clean up refresh token
		let payload;
		try {
			payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
		} catch (jwtError) {
			// Even if token is invalid, clear cookies
			const isProduction = process.env.NODE_ENV === "production";

			res.clearCookie("token", {
				httpOnly: true,
				secure: isProduction,
				sameSite: "lax",
				signed: true,
			});
			res.clearCookie("refreshToken", {
				httpOnly: true,
				secure: isProduction,
				sameSite: "lax",
				signed: true,
			});

			return res.status(200).json({
				status: "success",
				message: "Logged out successfully",
			});
		}

		// Remove refresh token from database
		await prisma.refreshToken.deleteMany({
			where: {
				OR: [
					{ token: refreshToken },
					{ userId: payload.user_ID, expiresAt: { lt: new Date() } },
				],
			},
		});

		// Clear cookies
		const isProduction = process.env.NODE_ENV === "production";

		res.clearCookie("token", {
			httpOnly: true,
			secure: isProduction,
			sameSite: "lax",
			signed: true,
		});
		res.clearCookie("refreshToken", {
			httpOnly: true,
			secure: isProduction,
			sameSite: "lax",
			signed: true,
		});

		return res.status(200).json({
			status: "success",
			message: "User logged out successfully",
		});
	} catch (error) {
		console.error("Logout error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});

// Route to get current user info
authRoutes.get("/me", async (req, res) => {
	try {
		const token = req.signedCookies.token;

		if (!token) {
			return res.status(401).json({
				status: "error",
				message: "Not authenticated",
				code: 401,
			});
		}

		const decoded = jwt.verify(token, JWT_SECRET);
		const user = await prisma.user.findUnique({
			where: { id: decoded.user_ID },
			select: {
				id: true,
				email: true,
				name: true,
				profile: true,
				createdAt: true,
			},
		});

		if (!user) {
			return res.status(404).json({
				status: "error",
				message: "User not found",
				code: 404,
			});
		}

		return res.status(200).json({
			status: "success",
			message: "User information retrieved",
			data: { user },
		});
	} catch (error) {
		if (
			error.name === "JsonWebTokenError" ||
			error.name === "TokenExpiredError"
		) {
			return res.status(401).json({
				status: "error",
				message: "Invalid or expired token",
				code: 401,
			});
		}

		console.error("Get user error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});
