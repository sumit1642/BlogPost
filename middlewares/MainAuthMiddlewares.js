// middlewares/MainAuthMiddlewares.js
import { PrismaClient } from "@prisma/client";
import validator from "validator";

const prisma = new PrismaClient();

export const validateRegisterInput = (req, res, next) => {
	const { name, email, password } = req.body;

	// Check for required fields
	if (!name || !email || !password) {
		return res.status(400).json({
			status: "error",
			message: "All fields are required (name, email, password)",
			code: 400,
		});
	}

	// Validate email format
	if (!validator.isEmail(email)) {
		return res.status(400).json({
			status: "error",
			message: "Please provide a valid email address",
			code: 400,
		});
	}

	// Validate password strength
	if (password.length < 6) {
		return res.status(400).json({
			status: "error",
			message: "Password must be at least 6 characters long",
			code: 400,
		});
	}

	// Validate name length and format
	if (name.trim().length < 2) {
		return res.status(400).json({
			status: "error",
			message: "Name must be at least 2 characters long",
			code: 400,
		});
	}

	if (name.trim().length > 50) {
		return res.status(400).json({
			status: "error",
			message: "Name cannot exceed 50 characters",
			code: 400,
		});
	}

	// Sanitize inputs
	req.body.name = name.trim();
	req.body.email = email.toLowerCase().trim();

	next();
};

export const checkIfUserExists = async (req, res, next) => {
	try {
		const email = req.body.email;
		const existingUser = await prisma.user.findUnique({
			where: { email },
			select: { id: true, email: true },
		});

		if (existingUser) {
			return res.status(409).json({
				status: "error",
				message: "User with that email already exists",
				code: 409,
			});
		}

		next();
	} catch (error) {
		console.error("Database error in checkIfUserExists:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
};

export const validateLoginInput = (req, res, next) => {
	const { email, password } = req.body;

	if (!email || !password) {
		return res.status(400).json({
			status: "error",
			message: "Both email and password are required",
			code: 400,
		});
	}

	// Validate email format
	if (!validator.isEmail(email)) {
		return res.status(400).json({
			status: "error",
			message: "Please provide a valid email address",
			code: 400,
		});
	}

	// Sanitize email
	req.body.email = email.toLowerCase().trim();

	next();
};

export const getUserByEmail = async (req, res, next) => {
	try {
		const email = req.body.email;
		const user = await prisma.user.findUnique({
			where: { email },
			select: {
				id: true,
				email: true,
				name: true,
				password: true,
				createdAt: true,
			},
		});

		if (!user) {
			return res.status(401).json({
				status: "error",
				message: "Invalid email or password",
				code: 401,
			});
		}

		req.foundUser = user;
		next();
	} catch (error) {
		console.error("Database error in getUserByEmail:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
};
