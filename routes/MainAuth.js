import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import express from "express";
import { addDays } from "date-fns";
import {
	validateRegisterInput,
	checkIfUserExists,
	validateLoginInput,
	getUserByEmail,
} from "../middlewares/MainAuthMiddlewares.js";

import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export const authRoutes = express.Router();

authRoutes.post(
	"/register",
	validateRegisterInput,
	checkIfUserExists,
	async (req, res) => {
		const { name, email, password, bio } = req.body;
		const hashedPassword = await bcrypt.hash(password, 10);

		const newUser = await prisma.user.create({
			data: {
				name,
				email,
				password: hashedPassword,
				profile: bio ? { create: { bio } } : undefined,
			},
			include: { profile: true },
		});

		return res.status(201).json({
			status: "success",
			message: "User registered",
			data: { user: newUser },
		});
	},
);

authRoutes.post(
	"/login",
	validateLoginInput,
	getUserByEmail,
	async (req, res) => {
		const { password } = req.body;
		const user = req.foundUser;

		const validPassword = await bcrypt.compare(password, user.password);
		if (!validPassword) {
			return res
				.status(401)
				.json({
					status: "error",
					message: "Incorrect password",
					code: 401,
				});
		}

		const accessToken = jwt.sign(
			{ user_ID: user.id },
			"jwtsupersecretkey",
			{ expiresIn: "15m" },
		);
		const refreshToken = jwt.sign(
			{ user_ID: user.id },
			"refreshTokenSecretKey",
			{
				expiresIn: "30d",
			},
		);

		await prisma.refreshToken.create({
			data: {
				token: refreshToken,
				userId: user.id,
				expiresAt: addDays(new Date(), 30),
			},
		});

		res.cookie("token", accessToken, {
			httpOnly: true,
			secure: false,
			signed: true,
			maxAge: 60 * 60 * 1000,
			sameSite: "lax",
		});

		res.cookie("refreshToken", refreshToken, {
			httpOnly: true,
			secure: false,
			signed: true,
			maxAge: 30 * 24 * 60 * 60 * 1000,
			sameSite: "lax",
		});

		return res.status(200).json({
			status: "success",
			message: "Logged in",
		});
	},
);

authRoutes.post("/refreshToken", async (req, res) => {
	const oldRefreshToken = req.signedCookies.refreshToken;
	if (!oldRefreshToken) {
		return res
			.status(401)
			.json({ status: "error", message: "No refresh token", code: 401 });
	}

	let payload;
	try {
		payload = jwt.verify(oldRefreshToken, "refreshTokenSecretKey");
	} catch {
		return res
			.status(403)
			.json({ status: "error", message: "Invalid token", code: 403 });
	}

	const storedToken = await prisma.refreshToken.findUnique({
		where: { token: oldRefreshToken },
	});

	if (!storedToken || new Date() > storedToken.expiresAt) {
		return res
			.status(403)
			.json({
				status: "error",
				message: "Token expired or invalid",
				code: 403,
			});
	}

	await prisma.refreshToken.delete({ where: { token: oldRefreshToken } });

	const newRefreshToken = jwt.sign(
		{ user_ID: payload.user_ID },
		"refreshTokenSecretKey",
		{
			expiresIn: "30d",
		},
	);

	const newAccessToken = jwt.sign(
		{ user_ID: payload.user_ID },
		"jwtsupersecretkey",
		{
			expiresIn: "1h",
		},
	);

	await prisma.refreshToken.create({
		data: {
			token: newRefreshToken,
			userId: payload.user_ID,
			expiresAt: addDays(new Date(), 30),
		},
	});

	res.cookie("token", newAccessToken, {
		httpOnly: true,
		secure: false,
		signed: true,
		maxAge: 60 * 60 * 1000,
		sameSite: "lax",
	});

	res.cookie("refreshToken", newRefreshToken, {
		httpOnly: true,
		secure: false,
		signed: true,
		maxAge: 30 * 24 * 60 * 60 * 1000,
		sameSite: "lax",
	});

	return res.status(200).json({
		status: "success",
		message: "Tokens refreshed",
	});
});

authRoutes.get("/logout", async (req, res) => {
	const signedRefreshToken = req.signedCookies.refreshToken;
	if (!signedRefreshToken) {
		return res
			.status(400)
			.json({ status: "error", message: "Not logged in", code: 400 });
	}

	try {
		jwt.verify(signedRefreshToken, "refreshTokenSecretKey");
		await prisma.refreshToken.delete({
			where: { token: signedRefreshToken },
		});
	} catch {
		// token invalid or expired
	}

	res.clearCookie("token", {
		httpOnly: true,
		secure: false,
		signed: true,
		sameSite: "lax",
	});
	res.clearCookie("refreshToken", {
		httpOnly: true,
		secure: false,
		signed: true,
		sameSite: "lax",
	});

	return res.status(200).json({ status: "success", message: "Logged out" });
});
