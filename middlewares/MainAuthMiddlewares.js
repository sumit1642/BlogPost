// middlewares/MainAuthMiddlewares.js
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const validateRegisterInput = (req, res, next) => {
	const { name, email, password } = req.body;
	if (!name || !email || !password) {
		return res.status(404).json({
			msg: "You piece of shit, fill all the fields with your b**b's milk",
		});
	}
	next();
};

export const checkIfUserExists = async (req, res, next) => {
	const email = req.body.email;
	const existingUser = await prisma.user.findUnique({ where: { email } });
	if (existingUser) {
		return res
			.status(404)
			.json({ error: "User with that email already exists" });
	}
	next();
};

export const validateLoginInput = (req, res, next) => {
	const { email, password } = req.body;
	if (!email || !password) {
		return res.status(400).json({ error: "All fields are required" });
	}
	next();
};

export const getUserByEmail = async (req, res, next) => {
	const email = req.body.email;
	const user = await prisma.user.findUnique({ where: { email } });

	if (!user) {
		return res.status(401).json({ error: "User doesn't exist" });
	}

	req.foundUser = user; // attach for next middleware/handler
	next();
};
