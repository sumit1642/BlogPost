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

const JWT_SECRET = process.env.JWT_SECRET || "jwtsupersecretkey";

authRoutes.post(
	"/register",
	validateRegisterInput,
	checkIfUserExists,
	async (req, res) => {
		try {
			const { name, email, password } = req.body;

			const hashedPassword = await bcrypt.hash(password, 10);

			const newUser = await prisma.user.create({
				data: {
					name,
					email,
					password: hashedPassword,
				},
			});

			// Very important, when sending another request , always remove the sensitive fields like password as it contains password hash and its a hash not encrypted so it is not safe.
			const userWithoutPassword = {
				id: newUser.id,
				name: newUser.name,
				email: newUser.email,
			};

			return res.status(201).json({
				status: "success",
				message: "User registered successfully",
				data: { user: userWithoutPassword },
			});
		} catch (error) {
			console.error("Registration error:", error);
			return res.status(500).json({
				status: "error",
				message: "Internal server error",
			});
		}
	},
);

authRoutes.post(
	"/login",
	validateLoginInput,
	getUserByEmail,
	async (req, res) => {
		try {
			const { password } = req.body;
			const user = req.foundUser;

			const validPassword = await bcrypt.compare(password, user.password);
			if (!validPassword) {
				return res.status(401).json({
					status: "error",
					message: "Invalid email or password",
				});
			}

			const token = jwt.sign(
				{ user_ID: user.id, email: user.email },
				JWT_SECRET,
				{ expiresIn: "7d" },
			);

			res.cookie("token", token, {
				httpOnly: true,
				secure: process.env.NODE_ENV === "production",
				signed: true,
				maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
				sameSite: "lax",
			});

			// Very important, when sending another request , always remove the sensitive fields like password as it contains password hash and its a hash not encrypted so it is not safe.
			const userWithoutPassword = {
				id: newUser.id,
				name: newUser.name,
				email: newUser.email,
			};

			return res.status(200).json({
				status: "success",
				message: "Logged in successfully",
				data: { user: userWithoutPassword },
			});
		} catch (error) {
			console.error("Login error:", error);
			return res.status(500).json({
				status: "error",
				message: "Internal server error",
			});
		}
	},
);

authRoutes.post("/logout", (req, res) => {
	res.clearCookie("token", {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
		signed: true,
	});

	return res.status(200).json({
		status: "success",
		message: "Logged out successfully",
	});
});

authRoutes.get("/me", async (req, res) => {
	try {
		const token = req.signedCookies.token;

		if (!token) {
			return res.status(401).json({
				status: "error",
				message: "Not authenticated",
			});
		}

		const decoded = jwt.verify(token, JWT_SECRET);
		const user = await prisma.user.findUnique({
			where: { id: decoded.user_ID },
			select: {
				id: true,
				email: true,
				name: true,
				createdAt: true,
			},
		});

		if (!user) {
			return res.status(404).json({
				status: "error",
				message: "User not found",
			});
		}

		return res.status(200).json({
			status: "success",
			message: "User information retrieved",
			data: { user },
		});
	} catch (error) {
		return res.status(401).json({
			status: "error",
			message: "Invalid or expired token",
		});
	}
});
