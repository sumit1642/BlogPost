// middlewares/MainAuthMiddlewares.js
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const validateRegisterInput = (req, res, next) => {
	const { name, email, password } = req.body;
	if (!name || !email || !password) {
		return res.status(400).json({
			status: "error",
			message: "All fields are required",
			code: 400,
		});
	}
	next();
};

export const checkIfUserExists = async (req, res, next) => {
	const email = req.body.email;
	const existingUser = await prisma.user.findUnique({ where: { email } });
	if (existingUser) {
		return res.status(409).json({
			status: "error",
			message: "User with that email already exists",
			code: 409,
		});
	}
	next();
};

export const validateLoginInput = (req, res, next) => {
	const { email, password } = req.body;
	if (!email || !password) {
		return res.status(400).json({
			status: "error",
			message: "All fields are required",
			code: 400,
		});
	}
	next();
};

export const getUserByEmail = async (req, res, next) => {
	const email = req.body.email;
	const user = await prisma.user.findUnique({ where: { email } });

	if (!user) {
		return res.status(401).json({
			status: "error",
			message: "User doesn't exist",
			code: 401,
		});
	}

	req.foundUser = user;
	next();
};
