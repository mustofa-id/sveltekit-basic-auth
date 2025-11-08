import { redirect } from '@sveltejs/kit';
import { auth } from '../auth.server.js';

export async function GET(event) {
	await auth.logout(event);
	redirect(303, '/login');
}
