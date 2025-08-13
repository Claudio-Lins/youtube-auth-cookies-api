import { Router } from "express";
import { prisma } from "./prisma.js";
import { compare } from "bcrypt";

const router = Router();

router.post('/login', async (req, res) => {
	const { email, password } = req.body;

	const user = await prisma.user.findFirst({
		where: {
			email
		}
	});

	if (!user) {
		return res.status(401).json({ message: 'Invalid email or password' });
	}

	const isValidPassword = await compare(password, user.password);

	if (!isValidPassword) {
		return res.status(401).json({ message: 'Invalid email or password' });
	}

	// Implement cookie-based authentication

	res.json(user);
});


router.get('/profile', async (req, res) => {
	const user = await prisma.user.findFirst();
	res.json(user);
});

export default router;
