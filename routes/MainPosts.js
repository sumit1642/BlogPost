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

// Get all posts (public endpoint with pagination and filtering)
postsRoutes.get("/posts", async (req, res) => {
	try {
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50); // Max 50 posts per page
		const skip = (page - 1) * limit;
		const published = req.query.published === "true" ? true : undefined;

		// Build where clause for filtering
		const whereClause = {
			...(published !== undefined && { published }),
		};

		// Get posts with pagination
		const [posts, totalCount] = await prisma.$transaction([
			prisma.post.findMany({
				where: whereClause,
				orderBy: { createdAt: "desc" },
				skip,
				take: limit,
				include: {
					author: {
						select: { id: true, name: true },
					},
				},
			}),
			prisma.post.count({ where: whereClause }),
		]);

		const totalPages = Math.ceil(totalCount / limit);

		return res.status(200).json({
			status: "success",
			message: "Posts retrieved successfully",
			data: {
				posts,
				pagination: {
					currentPage: page,
					totalPages,
					totalCount,
					hasNextPage: page < totalPages,
					hasPreviousPage: page > 1,
				},
			},
		});
	} catch (error) {
		console.error("Get posts error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});

// Get single post by ID (public endpoint)
postsRoutes.get("/posts/:id", validateIdParam, async (req, res) => {
	try {
		const postId = parseInt(req.params.id);

		const post = await prisma.post.findUnique({
			where: { id: postId },
			include: {
				author: {
					select: { id: true, name: true, email: true },
				},
			},
		});

		if (!post) {
			return res.status(404).json({
				status: "error",
				message: "Post not found",
				code: 404,
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
			code: 500,
		});
	}
});

// Get current user's posts (protected endpoint)
postsRoutes.get("/my-posts", verifyAuth, async (req, res) => {
	try {
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const skip = (page - 1) * limit;
		const published = req.query.published;

		// Build where clause
		const whereClause = {
			authorId: req.user.user_ID,
			...(published === "true" && { published: true }),
			...(published === "false" && { published: false }),
		};

		const [posts, totalCount] = await prisma.$transaction([
			prisma.post.findMany({
				where: whereClause,
				orderBy: { createdAt: "desc" },
				skip,
				take: limit,
			}),
			prisma.post.count({ where: whereClause }),
		]);

		const totalPages = Math.ceil(totalCount / limit);

		return res.status(200).json({
			status: "success",
			message: "User posts retrieved successfully",
			data: {
				posts,
				pagination: {
					currentPage: page,
					totalPages,
					totalCount,
					hasNextPage: page < totalPages,
					hasPreviousPage: page > 1,
				},
			},
		});
	} catch (error) {
		console.error("Get user posts error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});

// Create new post (protected endpoint)
postsRoutes.post("/posts", verifyAuth, validatePostInput, async (req, res) => {
	try {
		const { title, content } = req.body;
		const published = req.body.published === true;

		// Check for duplicate title for this user
		const existingPost = await prisma.post.findFirst({
			where: {
				title: title.trim(),
				authorId: req.user.user_ID,
			},
		});

		if (existingPost) {
			return res.status(409).json({
				status: "error",
				message: "You already have a post with this title",
				code: 409,
			});
		}

		const newPost = await prisma.post.create({
			data: {
				title: title.trim(),
				content: content.trim(),
				published,
				authorId: req.user.user_ID,
			},
			include: {
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

		// Handle Prisma unique constraint violations
		if (error.code === "P2002") {
			return res.status(409).json({
				status: "error",
				message: "A post with this title already exists",
				code: 409,
			});
		}

		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});

// Update post (protected endpoint with ownership check)
postsRoutes.put(
	"/posts/:id",
	verifyAuth,
	validateIdParam,
	validatePostInput,
	checkPostOwnership,
	async (req, res) => {
		try {
			const postId = parseInt(req.params.id);
			const { title, content } = req.body;
			const published = req.body.published === true;

			// Check for duplicate title (excluding current post)
			const existingPost = await prisma.post.findFirst({
				where: {
					title: title.trim(),
					authorId: req.user.user_ID,
					NOT: { id: postId },
				},
			});

			if (existingPost) {
				return res.status(409).json({
					status: "error",
					message: "You already have another post with this title",
					code: 409,
				});
			}

			const updatedPost = await prisma.post.update({
				where: { id: postId },
				data: {
					title: title.trim(),
					content: content.trim(),
					published,
					updatedAt: new Date(),
				},
				include: {
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

			// Handle Prisma unique constraint violations
			if (error.code === "P2002") {
				return res.status(409).json({
					status: "error",
					message: "A post with this title already exists",
					code: 409,
				});
			}

			return res.status(500).json({
				status: "error",
				message: "Internal server error",
				code: 500,
			});
		}
	},
);

// Toggle post published status (protected endpoint with ownership check)
postsRoutes.patch(
	"/posts/:id/toggle-publish",
	verifyAuth,
	validateIdParam,
	checkPostOwnership,
	async (req, res) => {
		try {
			const postId = parseInt(req.params.id);

			const updatedPost = await prisma.post.update({
				where: { id: postId },
				data: {
					published: !req.post.published,
					updatedAt: new Date(),
				},
				include: {
					author: {
						select: { id: true, name: true },
					},
				},
			});

			return res.status(200).json({
				status: "success",
				message: `Post ${
					updatedPost.published ? "published" : "unpublished"
				} successfully`,
				data: { post: updatedPost },
			});
		} catch (error) {
			console.error("Toggle publish error:", error);
			return res.status(500).json({
				status: "error",
				message: "Internal server error",
				code: 500,
			});
		}
	},
);

// Delete post (protected endpoint with ownership check)
postsRoutes.delete(
	"/posts/:id",
	verifyAuth,
	validateIdParam,
	checkPostOwnership,
	async (req, res) => {
		try {
			const postId = parseInt(req.params.id);

			await prisma.post.delete({
				where: { id: postId },
			});

			return res.status(200).json({
				status: "success",
				message: "Post deleted successfully",
			});
		} catch (error) {
			console.error("Delete post error:", error);

			// Handle case where post might have been deleted by another request
			if (error.code === "P2025") {
				return res.status(404).json({
					status: "error",
					message: "Post not found or already deleted",
					code: 404,
				});
			}

			return res.status(500).json({
				status: "error",
				message: "Internal server error",
				code: 500,
			});
		}
	},
);

// Get posts by specific author (public endpoint)
postsRoutes.get("/authors/:id/posts", validateIdParam, async (req, res) => {
	try {
		const authorId = parseInt(req.params.id);
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const skip = (page - 1) * limit;

		// Check if author exists
		const author = await prisma.user.findUnique({
			where: { id: authorId },
			select: { id: true, name: true },
		});

		if (!author) {
			return res.status(404).json({
				status: "error",
				message: "Author not found",
				code: 404,
			});
		}

		// Get published posts only for public endpoint
		const [posts, totalCount] = await prisma.$transaction([
			prisma.post.findMany({
				where: {
					authorId,
					published: true,
				},
				orderBy: { createdAt: "desc" },
				skip,
				take: limit,
				include: {
					author: {
						select: { id: true, name: true },
					},
				},
			}),
			prisma.post.count({
				where: {
					authorId,
					published: true,
				},
			}),
		]);

		const totalPages = Math.ceil(totalCount / limit);

		return res.status(200).json({
			status: "success",
			message: "Author posts retrieved successfully",
			data: {
				author,
				posts,
				pagination: {
					currentPage: page,
					totalPages,
					totalCount,
					hasNextPage: page < totalPages,
					hasPreviousPage: page > 1,
				},
			},
		});
	} catch (error) {
		console.error("Get author posts error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});

// Search posts (public endpoint)
postsRoutes.get("/search/posts", async (req, res) => {
	try {
		const query = req.query.q?.toString().trim();
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const skip = (page - 1) * limit;

		if (!query || query.length < 2) {
			return res.status(400).json({
				status: "error",
				message: "Search query must be at least 2 characters long",
				code: 400,
			});
		}

		// Search in title and content (published posts only)
		const [posts, totalCount] = await prisma.$transaction([
			prisma.post.findMany({
				where: {
					published: true,
					OR: [
						{ title: { contains: query, mode: "insensitive" } },
						{ content: { contains: query, mode: "insensitive" } },
					],
				},
				orderBy: { createdAt: "desc" },
				skip,
				take: limit,
				include: {
					author: {
						select: { id: true, name: true },
					},
				},
			}),
			prisma.post.count({
				where: {
					published: true,
					OR: [
						{ title: { contains: query, mode: "insensitive" } },
						{ content: { contains: query, mode: "insensitive" } },
					],
				},
			}),
		]);

		const totalPages = Math.ceil(totalCount / limit);

		return res.status(200).json({
			status: "success",
			message: "Search results retrieved successfully",
			data: {
				query,
				posts,
				pagination: {
					currentPage: page,
					totalPages,
					totalCount,
					hasNextPage: page < totalPages,
					hasPreviousPage: page > 1,
				},
			},
		});
	} catch (error) {
		console.error("Search posts error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});
