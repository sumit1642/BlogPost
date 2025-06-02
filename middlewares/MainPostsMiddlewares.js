// middlewares/MainPostsMiddlewares.js
import jwt from "jsonwebtoken";
import Joi from "joi";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// Enhanced auth middleware with proper error handling
export const verifyAuth = async (req, res, next) => {
	try {
		const token = req.signedCookies.token;

		if (!token) {
			return res.status(401).json({
				status: "error",
				message: "Authentication required",
				code: 401,
			});
		}

		let decoded;
		try {
			decoded = jwt.verify(
				token,
				process.env.JWT_SECRET || "jwtsupersecretkey",
			);
		} catch (jwtError) {
			// Token is invalid or expired, try to refresh it
			const refreshToken = req.signedCookies.refreshToken;

			if (!refreshToken) {
				return res.status(401).json({
					status: "error",
					message: "Authentication required",
					code: 401,
				});
			}

			try {
				const refreshDecoded = jwt.verify(
					refreshToken,
					process.env.REFRESH_TOKEN_SECRET || "refreshTokenSecretKey",
				);

				// Check if refresh token exists in database
				const storedToken = await prisma.refreshToken.findUnique({
					where: { token: refreshToken },
					include: {
						user: { select: { id: true, email: true, name: true } },
					},
				});

				if (!storedToken || new Date() > storedToken.expiresAt) {
					return res.status(403).json({
						status: "error",
						message: "Session expired, please login again",
						code: 403,
					});
				}

				// Generate new access token
				const newAccessToken = jwt.sign(
					{ user_ID: refreshDecoded.user_ID },
					process.env.JWT_SECRET || "jwtsupersecretkey",
					{ expiresIn: "15m" },
				);

				// Set new access token cookie
				res.cookie("token", newAccessToken, {
					httpOnly: true,
					secure: process.env.NODE_ENV === "production",
					signed: true,
					maxAge: 15 * 60 * 1000, // 15 minutes
					sameSite: "lax",
				});

				req.user = { user_ID: refreshDecoded.user_ID };
				return next();
			} catch (refreshError) {
				return res.status(403).json({
					status: "error",
					message: "Invalid session, please login again",
					code: 403,
				});
			}
		}

		if (decoded) {
			// Verify user still exists in database
			const user = await prisma.user.findUnique({
				where: { id: decoded.user_ID },
				select: { id: true, email: true, name: true },
			});

			if (!user) {
				return res.status(401).json({
					status: "error",
					message: "User account no longer exists",
					code: 401,
				});
			}

			req.user = decoded;
			return next();
		}
	} catch (error) {
		console.error("Auth middleware error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
};

// Validation schemas with enhanced rules
const postSchema = Joi.object({
	title: Joi.string()
		.trim()
		.min(3)
		.max(100)
		.pattern(/^[a-zA-Z0-9\s\-_.,!?'":;()\[\]]+$/)
		.required()
		.messages({
			"string.pattern.base": "Title contains invalid characters",
			"string.min": "Title must be at least 3 characters long",
			"string.max": "Title cannot exceed 100 characters",
			"any.required": "Title is required",
		}),
	content: Joi.string().trim().min(10).max(5000).required().messages({
		"string.min": "Content must be at least 10 characters long",
		"string.max": "Content cannot exceed 5000 characters",
		"any.required": "Content is required",
	}),
	published: Joi.boolean().optional().default(false),
});

const idParamSchema = Joi.object({
	id: Joi.string()
		.pattern(/^\d+$/)
		.custom((value, helpers) => {
			const num = parseInt(value);
			if (num <= 0 || num > 2147483647) {
				return helpers.error("number.invalid");
			}
			return num;
		})
		.required()
		.messages({
			"string.pattern.base": "Invalid post ID format",
			"number.invalid": "Post ID must be a positive integer",
		}),
});

// Middleware for validating post body
export const validatePostInput = (req, res, next) => {
	const { error, value } = postSchema.validate(req.body);

	if (error) {
		return res.status(400).json({
			status: "error",
			message: error.details[0].message,
			code: 400,
		});
	}

	// Sanitize and set validated values
	req.body = value;
	next();
};

// Middleware for validating :id param
export const validateIdParam = (req, res, next) => {
	const { error, value } = idParamSchema.validate(req.params);

	if (error) {
		return res.status(400).json({
			status: "error",
			message: "Invalid post ID",
			code: 400,
		});
	}

	// Convert to integer and set back to params
	req.params.id = value.id;
	next();
};

// Middleware to check post ownership
export const checkPostOwnership = async (req, res, next) => {
	try {
		const postId = parseInt(req.params.id);
		const userId = req.user.user_ID;

		const post = await prisma.post.findUnique({
			where: { id: postId },
			select: { id: true, authorId: true, title: true, published: true },
		});

		if (!post) {
			return res.status(404).json({
				status: "error",
				message: "Post not found",
				code: 404,
			});
		}

		if (post.authorId !== userId) {
			return res.status(403).json({
				status: "error",
				message: "You are not authorized to perform this action",
				code: 403,
			});
		}

		req.post = post;
		next();
	} catch (error) {
		console.error("Post ownership check error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
};
