import { PrismaClient } from "@prisma/client";
import express from "express";
import {
	verifyAuth,
	validatePostInput,
	validateIdParam,
} from "../middlewares/MainPostsMiddlewares.js";

const prisma = new PrismaClient();
export const postsRoutes = express.Router();

postsRoutes.get("/posts", async (req, res) => {
	const posts = await prisma.post.findMany({
		orderBy: { createdAt: "desc" },
		include: { author: { select: { name: true } } },
	});

	return res
		.status(200)
		.json({ status: "success", message: "All posts fetched", data: posts });
});

postsRoutes.get("/my-posts", verifyAuth, async (req, res) => {
	const posts = await prisma.post.findMany({
		where: { authorId: req.user.user_ID },
		orderBy: { createdAt: "desc" },
	});

	return res
		.status(200)
		.json({ status: "success", message: "My posts fetched", data: posts });
});

postsRoutes.post("/posts", verifyAuth, validatePostInput, async (req, res) => {
	const { title, content } = req.body;
	const newPost = await prisma.post.create({
		data: { title, content, authorId: req.user.user_ID },
	});

	return res
		.status(201)
		.json({
			status: "success",
			message: "Post created successfully",
			data: newPost,
		});
});

postsRoutes.put(
	"/posts/:id",
	verifyAuth,
	validateIdParam,
	validatePostInput,
	async (req, res) => {
		const { id } = req.params;

		const post = await prisma.post.findUnique({
			where: { id: parseInt(id) },
		});
		if (!post || post.authorId !== req.user.user_ID) {
			return res
				.status(403)
				.json({
					status: "error",
					message: "Not authorized or post not found",
					code: 403,
				});
		}

		const { title, content } = req.body;
		const updatedPost = await prisma.post.update({
			where: { id: parseInt(id) },
			data: { title, content },
		});

		return res
			.status(200)
			.json({
				status: "success",
				message: "Post updated",
				data: updatedPost,
			});
	},
);

postsRoutes.delete(
	"/posts/:id",
	verifyAuth,
	validateIdParam,
	async (req, res) => {
		const { id } = req.params;

		const post = await prisma.post.findUnique({
			where: { id: parseInt(id) },
		});
		if (!post || post.authorId !== req.user.user_ID) {
			return res
				.status(403)
				.json({
					status: "error",
					message: "Not authorized or post not found",
					code: 403,
				});
		}

		await prisma.post.delete({ where: { id: parseInt(id) } });

		return res
			.status(200)
			.json({ status: "success", message: "Post deleted" });
	},
);
