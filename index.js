// index.js
import { PrismaClient } from "@prisma/client";
import express from "express";
import { routes } from "./routes/MainAuth.js";
import cookieParser from "cookie-parser";
const app = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(cookieParser("yourSecretHere"));
app.use("/", routes);
// GET: @ "/" All posts on home route
app.get("/", async (req, res) => {
	const allPosts = await prisma.post.findMany();
	res.status(200).json({ msg: allPosts });
});

app.listen(3000);
