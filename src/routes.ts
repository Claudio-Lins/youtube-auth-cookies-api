import { Router } from "express";
import { prisma } from "./prisma.js";
import { compare } from "bcrypt";
import jwt from "jsonwebtoken";

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

	const token = jwt.sign({ id: user.id }, 'UmaSenhaSuperSecreta', { expiresIn: '1h' });

	res.json({ user, token });
});


router.get('/profile', async (req, res) => {
	const { authorization } = req.headers;

	if (!authorization) {
		return res.status(401).json({ message: 'Unauthorized' });
	}

	const token = authorization.split(' ')[1];

	if (!token) {
		return res.status(401).json({ message: 'Unauthorized' });
	}

	try {
		const decoded = jwt.verify(token, 'UmaSenhaSuperSecreta');

		const user = await prisma.user.findFirst({
			where: {
				id: (decoded as any).id
			}
		});

		if (!user) {
			return res.status(401).json({ message: 'Unauthorized' });
		}
		
		res.json(user);
	} catch (error) {
		return res.status(401).json({ message: 'Unauthorized' });
	}
});

export default router;
