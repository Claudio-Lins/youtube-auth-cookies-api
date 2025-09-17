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

	const isProd = process.env.NODE_ENV === 'production'

	res.cookie('token_youtube', token, {
		httpOnly: true,
		secure: isProd, // true em produção com HTTPS
		sameSite: isProd ? 'none' : 'lax', // 'none' em produção com HTTPS
		maxAge: 60 * 60 * 1000, // 1 hora
		path: '/',
		domain: isProd ? '.seu-dominio.com' : 'localhost' // ajuste conforme necessário
	})

	res.json({ user });
});


router.get('/profile', async (req, res) => {
	const token = req.cookies['token_youtube']

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

router.post('/logout', (req, res) => {
	res.clearCookie('token_youtube')
	res.json({ message: 'Logged out successfully' });
});

export default router;
