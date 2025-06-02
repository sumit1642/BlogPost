// routes/MainPosts.js
import { PrismaClient } from "@prisma/client";
import express from "express";
import {
	verifyAuth,
	validatePostInput,
	validateIdParam,
	checkPostOwnership,
} from "../middlewares/MainPostsMiddlewares.js";

const prisma = new PrismaClient();
export const postsRoutes = express.Router();

// Get all posts (public - for home page)
postsRoutes.get("/posts", async (req, res) => {
	try {
		const posts = await prisma.post.findMany({
			orderBy: { createdAt: "desc" },
			select: {
				id: true,
				title: true,
				content: true,
				createdAt: true,
				updatedAt: true,
				author: {
					select: { id: true, name: true },
				},
			},
		});

		return res.status(200).json({
			status: "success",
			message: "Posts retrieved successfully",
			data: { posts },
		});
	} catch (error) {
		console.error("Get posts error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
});

// Get single post by ID (public)
postsRoutes.get("/posts/:id", validateIdParam, async (req, res) => {
	try {
		const postId = req.params.id;

		const post = await prisma.post.findUnique({
			where: { id: postId },
			select: {
				id: true,
				title: true,
				content: true,
				createdAt: true,
				updatedAt: true,
				author: {
					select: {
						id: true,
						name: true,
						email: true,
					},
				},
			},
		});

		if (!post) {
			return res.status(404).json({
				status: "error",
				message: "Post not found",
			});
		}

		return res.status(200).json({
			status: "success",
			message: "Post retrieved successfully",
			data: { post },
		});
	} catch (error) {
		console.error("Get single post error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
});

// Get current user's posts (protected)
postsRoutes.get("/my-posts", verifyAuth, async (req, res) => {
	try {
		const posts = await prisma.post.findMany({
			where: { authorId: req.user.user_ID },
			orderBy: { createdAt: "desc" },
			select: {
				id: true,
				title: true,
				content: true,
				createdAt: true,
				updatedAt: true,
			},
		});

		return res.status(200).json({
			status: "success",
			message: "User posts retrieved successfully",
			data: { posts },
		});
	} catch (error) {
		console.error("Get user posts error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
});

// Create new post (protected)
postsRoutes.post("/posts", verifyAuth, validatePostInput, async (req, res) => {
	try {
		const { title, content } = req.body;

		const newPost = await prisma.post.create({
			data: {
				title,
				content,
				authorId: req.user.user_ID,
			},
			select: {
				id: true,
				title: true,
				content: true,
				createdAt: true,
				updatedAt: true,
				author: {
					select: { id: true, name: true },
				},
			},
		});

		return res.status(201).json({
			status: "success",
			message: "Post created successfully",
			data: { post: newPost },
		});
	} catch (error) {
		console.error("Create post error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
		});
	}
});

// Update post (protected)
postsRoutes.put(
	"/posts/:id",
	verifyAuth,
	validateIdParam,
	validatePostInput,
	checkPostOwnership,
	async (req, res) => {
		try {
			const postId = req.params.id;
			const { title, content } = req.body;

			const updatedPost = await prisma.post.update({
				where: { id: postId },
				data: {
					title,
					content,
					updatedAt: new Date(),
				},
				select: {
					id: true,
					title: true,
					content: true,
					createdAt: true,
					updatedAt: true,
					author: {
						select: { id: true, name: true },
					},
				},
			});

			return res.status(200).json({
				status: "success",
				message: "Post updated successfully",
				data: { post: updatedPost },
			});
		} catch (error) {
			console.error("Update post error:", error);
			return res.status(500).json({
				status: "error",
				message: "Internal server error",
			});
		}
	},
);

// Delete post (protected)
postsRoutes.delete(
	"/posts/:id",
	verifyAuth,
	validateIdParam,
	checkPostOwnership,
	async (req, res) => {
		try {
			const postId = req.params.id;

			await prisma.post.delete({
				where: { id: postId },
			});

			return res.status(200).json({
				status: "success",
				message: "Post deleted successfully",
			});
		} catch (error) {
			console.error("Delete post error:", error);
			return res.status(500).json({
				status: "error",
				message: "Internal server error",
			});
		}
	},
);
