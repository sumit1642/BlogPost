import jwt from "jsonwebtoken";
import Joi from "joi";

// Auth middleware, unchanged
export const verifyAuth = (req, res, next) => {
	const token = req.signedCookies.token;
	if (!token)
		return res
			.status(401)
			.json({ status: "error", message: "Not authenticated", code: 401 });

	try {
		const decoded = jwt.verify(token, "jwtsupersecretkey");
		req.user = decoded;
		next();
	} catch {
		return res
			.status(403)
			.json({
				status: "error",
				message: "Invalid or expired token",
				code: 403,
			});
	}
};

// Validation schemas
const postSchema = Joi.object({
	title: Joi.string().trim().min(3).max(100).required(),
	content: Joi.string().trim().min(10).max(1000).required(),
});

const idParamSchema = Joi.object({
	id: Joi.number().integer().positive().required(),
});

// Middleware for validating post body
export const validatePostInput = (req, res, next) => {
	const { error } = postSchema.validate(req.body);
	if (error) {
		return res.status(400).json({
			status: "error",
			message: error.details[0].message,
			code: 400,
		});
	}
	next();
};

// Middleware for validating :id param
export const validateIdParam = (req, res, next) => {
	const { error } = idParamSchema.validate(req.params);
	if (error) {
		return res.status(400).json({
			status: "error",
			message: "Invalid post ID",
			code: 400,
		});
	}
	next();
};
