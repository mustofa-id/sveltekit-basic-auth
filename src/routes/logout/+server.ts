import { redirect } from '@sveltejs/kit';
import { auth } from '../auth.server.js';

export async function GET() {
	await auth.logout();
	redirect(303, '/login');
}
