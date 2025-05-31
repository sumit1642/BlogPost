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

export const routes = express.Router();

routes.post(
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
		return res.status(201).json({ msg: "User registered", user: newUser });
	},
);

routes.post("/login", validateLoginInput, getUserByEmail, async (req, res) => {
	const { password } = req.body;
	const user = req.foundUser;

	const validPassword = await bcrypt.compare(password, user.password);
	if (!validPassword) {
		return res.status(401).json({ message: "Password is incorrect" });
	}

	// Delete old refresh tokens for this user before creating a new one
	await prisma.refreshToken.deleteMany({ where: { userId: user.id } });

	const accessToken = jwt.sign({ user_ID: user.id }, "jwtsupersecretkey", {
		expiresIn: "5s",
	});

	const refreshToken = jwt.sign(
		{ user_ID: user.id },
		"refreshTokenSecretKey",
		{ expiresIn: "30d" },
	);

	await prisma.refreshToken.create({
		data: {
			token: refreshToken,
			userId: user.id,
			expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
		},
	});

	res.cookie("token", accessToken, {
		httpOnly: true,
		secure: true,
		signed: true,
		maxAge: 60 * 60 * 1000,
	});

	res.cookie("refreshToken", refreshToken, {
		httpOnly: true,
		secure: true,
		signed: true,
		maxAge: 30 * 24 * 60 * 60 * 1000,
	});

	return res.status(201).json({
		msg: "Logged in",
		accessToken: accessToken,
		refreshToken: refreshToken,
	});
});

routes.post("/refreshToken", async (req, res) => {
	const oldRefreshToken = req.signedCookies.refreshToken;
	if (!oldRefreshToken) {
		return res.status(401).json({ message: "No refresh token provided" });
	}

	const payload = jwt.verify(oldRefreshToken, "refreshTokenSecretKey");

	if (!payload) {
		return res.status(403).json({ message: "Invalid refresh token" });
	}

	const storedToken = await prisma.refreshToken.findUnique({
		where: { token: oldRefreshToken },
	});

	if (!storedToken || new Date() > storedToken.expiresAt) {
		return res
			.status(403)
			.json({ message: "Refresh token expired or invalid" });
	}

	// Delete old refresh token (rotation)
	await prisma.refreshToken.delete({ where: { token: oldRefreshToken } });

	const newRefreshToken = jwt.sign(
		{ user_ID: payload.user_ID },
		"refreshTokenSecretKey",
		{ expiresIn: "30d" },
	);

	const newAccessToken = jwt.sign(
		{ user_ID: payload.user_ID },
		"jwtsupersecretkey",
		{ expiresIn: "1h" },
	);

	await prisma.refreshToken.create({
		data: {
			token: newRefreshToken,
			userId: payload.user_ID,
			expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
		},
	});

	res.cookie("token", newAccessToken, {
		httpOnly: true,
		secure: true,
		signed: true,
		maxAge: 60 * 60 * 1000,
	});

	res.cookie("refreshToken", newRefreshToken, {
		httpOnly: true,
		secure: true,
		signed: true,
		maxAge: 30 * 24 * 60 * 60 * 1000,
	});

	return res.status(200).json({
		msg: "Tokens refreshed",
		accessToken: newAccessToken,
		refreshToken: newRefreshToken,
	});
});

routes.get("/logout", async (req, res) => {
	const verifyStoredRefreshToken = req.signedCookies.refreshToken;
	if (!verifyStoredRefreshToken) {
		return res.status(400).json({ message: "No user is logged in" });
	}

	const payload = jwt.verify(
		verifyStoredRefreshToken,
		"refreshTokenSecretKey",
	);
	if (!payload || !payload.user_ID) {
		res.clearCookie("token");
		res.clearCookie("refreshToken");
		return res.status(403).json({ message: "Invalid token" });
	}

	// Validate token exists in DB to prevent fake token logout
	const storedToken = await prisma.refreshToken.findUnique({
		where: { token: oldRefreshToken },
	});

	if (!storedToken || new Date() > storedToken.expiresAt) {
		res.clearCookie("token");
		res.clearCookie("refreshToken");
		return res.status(403).json({ message: "Expired or invalid token" });
	}

	// Invalidate token
	await prisma.refreshToken.deleteMany({
		where: { token: oldRefreshToken },
	});

	res.clearCookie("token");
	res.clearCookie("refreshToken");

	return res.status(200).json({ message: "User logged out successfully" });
});
