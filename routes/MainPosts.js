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

// Get all posts (public endpoint with enhanced pagination and filtering)
postsRoutes.get("/posts", async (req, res) => {
	try {
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const skip = (page - 1) * limit;
		const published = req.query.published === "true" ? true : undefined;
		const sortBy = req.query.sortBy || "createdAt";
		const sortOrder = req.query.sortOrder === "asc" ? "asc" : "desc";

		// Validate sort field
		const validSortFields = ["createdAt", "updatedAt", "title"];
		const orderBy = validSortFields.includes(sortBy)
			? { [sortBy]: sortOrder }
			: { createdAt: "desc" };

		const whereClause = {
			...(published !== undefined && { published }),
		};

		const [posts, totalCount] = await prisma.$transaction([
			prisma.post.findMany({
				where: whereClause,
				orderBy,
				skip,
				take: limit,
				select: {
					id: true,
					title: true,
					content: true,
					published: true,
					createdAt: true,
					updatedAt: true,
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
					limit,
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

// Get single post by ID (public endpoint with view tracking)
postsRoutes.get("/posts/:id", validateIdParam, async (req, res) => {
	try {
		const postId = parseInt(req.params.id);

		const post = await prisma.post.findUnique({
			where: { id: postId },
			select: {
				id: true,
				title: true,
				content: true,
				published: true,
				createdAt: true,
				updatedAt: true,
				author: {
					select: {
						id: true,
						name: true,
						email: true,
						profile: {
							select: { bio: true },
						},
					},
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

		// Only show unpublished posts to their authors
		if (!post.published) {
			const token = req.signedCookies.token;
			if (!token) {
				return res.status(404).json({
					status: "error",
					message: "Post not found",
					code: 404,
				});
			}

			try {
				const jwt = await import("jsonwebtoken");
				const decoded = jwt.default.verify(
					token,
					process.env.JWT_SECRET || "jwtsupersecretkey",
				);
				if (decoded.user_ID !== post.author.id) {
					return res.status(404).json({
						status: "error",
						message: "Post not found",
						code: 404,
					});
				}
			} catch (jwtError) {
				return res.status(404).json({
					status: "error",
					message: "Post not found",
					code: 404,
				});
			}
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

// Get current user's posts (protected endpoint with enhanced filtering)
postsRoutes.get("/my-posts", verifyAuth, async (req, res) => {
	try {
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const skip = (page - 1) * limit;
		const published = req.query.published;
		const sortBy = req.query.sortBy || "createdAt";
		const sortOrder = req.query.sortOrder === "asc" ? "asc" : "desc";

		const validSortFields = [
			"createdAt",
			"updatedAt",
			"title",
			"published",
		];
		const orderBy = validSortFields.includes(sortBy)
			? { [sortBy]: sortOrder }
			: { createdAt: "desc" };

		const whereClause = {
			authorId: req.user.user_ID,
			...(published === "true" && { published: true }),
			...(published === "false" && { published: false }),
		};

		const [posts, totalCount, publishedCount, draftCount] =
			await prisma.$transaction([
				prisma.post.findMany({
					where: whereClause,
					orderBy,
					skip,
					take: limit,
					select: {
						id: true,
						title: true,
						content: true,
						published: true,
						createdAt: true,
						updatedAt: true,
					},
				}),
				prisma.post.count({ where: whereClause }),
				prisma.post.count({
					where: { authorId: req.user.user_ID, published: true },
				}),
				prisma.post.count({
					where: { authorId: req.user.user_ID, published: false },
				}),
			]);

		const totalPages = Math.ceil(totalCount / limit);

		return res.status(200).json({
			status: "success",
			message: "User posts retrieved successfully",
			data: {
				posts,
				stats: {
					total: publishedCount + draftCount,
					published: publishedCount,
					drafts: draftCount,
				},
				pagination: {
					currentPage: page,
					totalPages,
					totalCount,
					hasNextPage: page < totalPages,
					hasPreviousPage: page > 1,
					limit,
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

// Create new post (protected endpoint with enhanced validation)
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
			select: {
				id: true,
				title: true,
				content: true,
				published: true,
				createdAt: true,
				updatedAt: true,
				author: {
					select: { id: true, name: true },
				},
			},
		});

		return res.status(201).json({
			status: "success",
			message: `Post ${
				published ? "created and published" : "saved as draft"
			} successfully`,
			data: { post: newPost },
		});
	} catch (error) {
		console.error("Create post error:", error);

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
				select: {
					id: true,
					title: true,
					content: true,
					published: true,
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

// Bulk update posts status (protected endpoint)
postsRoutes.patch("/posts/bulk-update", verifyAuth, async (req, res) => {
	try {
		const { postIds, action } = req.body;

		if (!Array.isArray(postIds) || postIds.length === 0) {
			return res.status(400).json({
				status: "error",
				message: "Post IDs array is required",
				code: 400,
			});
		}

		if (!["publish", "unpublish", "delete"].includes(action)) {
			return res.status(400).json({
				status: "error",
				message:
					"Invalid action. Must be 'publish', 'unpublish', or 'delete'",
				code: 400,
			});
		}

		// Verify all posts belong to the user
		const userPosts = await prisma.post.findMany({
			where: {
				id: { in: postIds.map((id) => parseInt(id)) },
				authorId: req.user.user_ID,
			},
			select: { id: true },
		});

		if (userPosts.length !== postIds.length) {
			return res.status(403).json({
				status: "error",
				message: "You can only modify your own posts",
				code: 403,
			});
		}

		let result;
		const validPostIds = userPosts.map((post) => post.id);

		switch (action) {
			case "publish":
				result = await prisma.post.updateMany({
					where: { id: { in: validPostIds } },
					data: { published: true, updatedAt: new Date() },
				});
				break;
			case "unpublish":
				result = await prisma.post.updateMany({
					where: { id: { in: validPostIds } },
					data: { published: false, updatedAt: new Date() },
				});
				break;
			case "delete":
				result = await prisma.post.deleteMany({
					where: { id: { in: validPostIds } },
				});
				break;
		}

		return res.status(200).json({
			status: "success",
			message: `${result.count} posts ${
				action === "delete" ? "deleted" : action + "ed"
			} successfully`,
			data: { affectedCount: result.count },
		});
	} catch (error) {
		console.error("Bulk update error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});

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
				select: {
					id: true,
					title: true,
					content: true,
					published: true,
					createdAt: true,
					updatedAt: true,
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

// Duplicate post (protected endpoint with ownership check)
postsRoutes.post(
	"/posts/:id/duplicate",
	verifyAuth,
	validateIdParam,
	checkPostOwnership,
	async (req, res) => {
		try {
			const originalPost = await prisma.post.findUnique({
				where: { id: parseInt(req.params.id) },
				select: { title: true, content: true },
			});

			if (!originalPost) {
				return res.status(404).json({
					status: "error",
					message: "Post not found",
					code: 404,
				});
			}

			// Generate unique title for duplicate
			let newTitle = `Copy of ${originalPost.title}`;
			let counter = 1;

			while (
				await prisma.post.findFirst({
					where: { title: newTitle, authorId: req.user.user_ID },
				})
			) {
				counter++;
				newTitle = `Copy of ${originalPost.title} (${counter})`;
			}

			const duplicatedPost = await prisma.post.create({
				data: {
					title: newTitle,
					content: originalPost.content,
					published: false,
					authorId: req.user.user_ID,
				},
				select: {
					id: true,
					title: true,
					content: true,
					published: true,
					createdAt: true,
					updatedAt: true,
					author: {
						select: { id: true, name: true },
					},
				},
			});

			return res.status(201).json({
				status: "success",
				message: "Post duplicated successfully",
				data: { post: duplicatedPost },
			});
		} catch (error) {
			console.error("Duplicate post error:", error);
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

// Get posts by specific author (public endpoint with enhanced filtering)
postsRoutes.get("/authors/:id/posts", validateIdParam, async (req, res) => {
	try {
		const authorId = parseInt(req.params.id);
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const skip = (page - 1) * limit;
		const sortBy = req.query.sortBy || "createdAt";
		const sortOrder = req.query.sortOrder === "asc" ? "asc" : "desc";

		const validSortFields = ["createdAt", "updatedAt", "title"];
		const orderBy = validSortFields.includes(sortBy)
			? { [sortBy]: sortOrder }
			: { createdAt: "desc" };

		// Check if author exists
		const author = await prisma.user.findUnique({
			where: { id: authorId },
			select: {
				id: true,
				name: true,
				profile: {
					select: { bio: true },
				},
			},
		});

		if (!author) {
			return res.status(404).json({
				status: "error",
				message: "Author not found",
				code: 404,
			});
		}

		const [posts, totalCount] = await prisma.$transaction([
			prisma.post.findMany({
				where: {
					authorId,
					published: true,
				},
				orderBy,
				skip,
				take: limit,
				select: {
					id: true,
					title: true,
					content: true,
					published: true,
					createdAt: true,
					updatedAt: true,
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
					limit,
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

// Enhanced search posts (public endpoint with advanced filtering)
postsRoutes.get("/search/posts", async (req, res) => {
	try {
		const query = req.query.q?.toString().trim();
		const page = parseInt(req.query.page) || 1;
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const skip = (page - 1) * limit;
		const authorId = req.query.authorId
			? parseInt(req.query.authorId)
			: undefined;
		const sortBy = req.query.sortBy || "createdAt";
		const sortOrder = req.query.sortOrder === "asc" ? "asc" : "desc";

		if (!query || query.length < 2) {
			return res.status(400).json({
				status: "error",
				message: "Search query must be at least 2 characters long",
				code: 400,
			});
		}

		const validSortFields = ["createdAt", "updatedAt", "title"];
		const orderBy = validSortFields.includes(sortBy)
			? { [sortBy]: sortOrder }
			: { createdAt: "desc" };

		const whereClause = {
			published: true,
			OR: [
				{ title: { contains: query, mode: "insensitive" } },
				{ content: { contains: query, mode: "insensitive" } },
			],
			...(authorId && { authorId }),
		};

		const [posts, totalCount] = await prisma.$transaction([
			prisma.post.findMany({
				where: whereClause,
				orderBy,
				skip,
				take: limit,
				select: {
					id: true,
					title: true,
					content: true,
					published: true,
					createdAt: true,
					updatedAt: true,
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
					limit,
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

// Get post statistics (protected endpoint)
postsRoutes.get("/stats", verifyAuth, async (req, res) => {
	try {
		const userId = req.user.user_ID;

		const [totalPosts, publishedPosts, draftPosts, recentPosts] =
			await prisma.$transaction([
				prisma.post.count({
					where: { authorId: userId },
				}),
				prisma.post.count({
					where: { authorId: userId, published: true },
				}),
				prisma.post.count({
					where: { authorId: userId, published: false },
				}),
				prisma.post.findMany({
					where: { authorId: userId },
					orderBy: { createdAt: "desc" },
					take: 5,
					select: {
						id: true,
						title: true,
						published: true,
						createdAt: true,
					},
				}),
			]);

		return res.status(200).json({
			status: "success",
			message: "Statistics retrieved successfully",
			data: {
				stats: {
					totalPosts,
					publishedPosts,
					draftPosts,
				},
				recentPosts,
			},
		});
	} catch (error) {
		console.error("Get stats error:", error);
		return res.status(500).json({
			status: "error",
			message: "Internal server error",
			code: 500,
		});
	}
});
