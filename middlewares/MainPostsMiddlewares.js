// AuthAPI/middlewares/MainPostsMiddlewares.js
import jwt from "jsonwebtoken";

export const verifyAuth = (req, res, next) => {
	const token = req.signedCookies.token;

	if (!token) {
		return res.status(401).json({
			status: "error",
			message: "Not authenticated",
			code: 401,
		});
	}

	try {
		const decoded = jwt.verify(token, "jwtsupersecretkey");
		req.user = decoded; // You get user_ID here
		next();
	} catch (err) {
		return res.status(403).json({
			status: "error",
			message: "Invalid or expired token",
			code: 403,
		});
	}
};
