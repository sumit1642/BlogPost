import jwt from "jsonwebtoken";
import Joi from "joi";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || "jwtsupersecretkey";

const postSchema = Joi.object({
	title: Joi.string().min(1).max(50).required(),
	content: Joi.string().max(191).allow("").optional(),
});

const idSchema = Joi.object({
	id: Joi.number().integer().positive().required(),
});

export const verifyAuth = async (req, res, next) => {
	try {
		const token = req.signedCookies.token;

		if (!token) {
			return res.status(401).json({
				status: "error",
				message: "Access token required",
			});
		}

		const decoded = jwt.verify(token, JWT_SECRET);

		const user = await prisma.user.findUnique({
			where: { id: decoded.user_ID },
		});

		if (!user) {
			return res.status(401).json({
				status: "error",
				message: "User not found",
			});
		}

		req.user = decoded;
		next();
	} catch (error) {
		if (error.name === "JsonWebTokenError") {
			return res.status(401).json({
				status: "error",
				message: "Invalid token",
			});
		}
		if (error.name === "TokenExpiredError") {
			return res.status(401).json({
				status: "error",
				message: "Token expired",
			});
		}
		console.error("Auth verification error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
};

export const validatePostInput = (req, res, next) => {
	const { error } = postSchema.validate(req.body);
	if (error) {
		return res.status(400).json({
			status: "error",
			message: error.details[0].message,
		});
	}
	next();
};

export const validateIdParam = (req, res, next) => {
	const id = parseInt(req.params.id);
	const { error } = idSchema.validate({ id });

	if (error || isNaN(id)) {
		return res.status(400).json({
			status: "error",
			message: "Invalid post ID",
		});
	}

	req.params.id = id;
	next();
};

export const checkPostOwnership = async (req, res, next) => {
	try {
		const postId = req.params.id;
		const userId = req.user.user_ID;

		const post = await prisma.post.findUnique({
			where: { id: postId },
		});

		if (!post) {
			return res.status(404).json({
				status: "error",
				message: "Post not found",
			});
		}

		if (post.authorId !== userId) {
			return res.status(403).json({
				status: "error",
				message: "Access denied. You can only modify your own posts",
			});
		}

		next();
	} catch (error) {
		console.error("Check post ownership error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
};
