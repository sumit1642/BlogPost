// middlewares/MainPostsMiddlewares.js
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// Simple auth middleware
export const verifyAuth = (req, res, next) => {
	const token = req.signedCookies.token;

	if (!token) {
		return res.status(401).json({
			status: "error",
			message: "Authentication required",
		});
	}

	try {
		const decoded = jwt.verify(
			token,
			process.env.JWT_SECRET || "jwtsupersecretkey",
		);
		req.user = decoded;
		next();
	} catch (error) {
		return res.status(401).json({
			status: "error",
			message: "Invalid or expired token",
		});
	}
};

// Simple post validation
export const validatePostInput = (req, res, next) => {
	const { title, content } = req.body;

	if (!title || !content) {
		return res.status(400).json({
			status: "error",
			message: "Title and content are required",
		});
	}

	if (title.trim().length < 3) {
		return res.status(400).json({
			status: "error",
			message: "Title must be at least 3 characters long",
		});
	}

	if (content.trim().length < 10) {
		return res.status(400).json({
			status: "error",
			message: "Content must be at least 10 characters long",
		});
	}

	// Clean inputs
	req.body.title = title.trim();
	req.body.content = content.trim();

	next();
};

// Simple ID validation
export const validateIdParam = (req, res, next) => {
	const id = parseInt(req.params.id);

	if (isNaN(id) || id <= 0) {
		return res.status(400).json({
			status: "error",
			message: "Invalid post ID",
		});
	}

	req.params.id = id;
	next();
};

// Check if user owns the post
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
				message: "You are not authorized to perform this action",
			});
		}

		req.post = post;
		next();
	} catch (error) {
		console.error("Post ownership check error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
};
