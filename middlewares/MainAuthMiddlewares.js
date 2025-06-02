// middlewares/MainAuthMiddlewares.js
import Joi from "joi";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// Validation schemas
const registerSchema = Joi.object({
	name: Joi.string().min(2).max(50).required(),
	email: Joi.string().email().required(),
	password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
	email: Joi.string().email().required(),
	password: Joi.string().min(6).required(),
});

// Validate register input
export const validateRegisterInput = (req, res, next) => {
	const { error } = registerSchema.validate(req.body);
	if (error) {
		return res.status(400).json({
			status: "error",
			message: error.details[0].message,
		});
	}
	next();
};

// Validate login input
export const validateLoginInput = (req, res, next) => {
	const { error } = loginSchema.validate(req.body);
	if (error) {
		return res.status(400).json({
			status: "error",
			message: error.details[0].message,
		});
	}
	next();
};

// Check if user already exists
export const checkIfUserExists = async (req, res, next) => {
	try {
		const { email } = req.body;
		const existingUser = await prisma.user.findUnique({
			where: { email },
		});

		if (existingUser) {
			return res.status(409).json({
				status: "error",
				message: "User with this email already exists",
			});
		}
		next();
	} catch (error) {
		console.error("Check user exists error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
};

// Get user by email
export const getUserByEmail = async (req, res, next) => {
	try {
		const { email } = req.body;
		const user = await prisma.user.findUnique({
			where: { email },
		});

		if (!user) {
			return res.status(401).json({
				status: "error",
				message: "Invalid email or password",
			});
		}

		req.foundUser = user;
		next();
	} catch (error) {
		console.error("Get user by email error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
};
