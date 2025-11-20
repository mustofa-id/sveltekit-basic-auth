import { fail } from '@sveltejs/kit';
import { auth, requiredUser, sessionDataSource } from '../auth.server.js';

export function load() {
	requiredUser();
	const sessions = sessionDataSource.findAll();
	return { sessions };
}

export const actions = {
	kill: async ({ request }) => {
		const fd = await request.formData();
		const sessionId = fd.get('sessionId')?.toString();
		if (!sessionId) return fail(400, 'session id is required');

		await auth.kill(sessionId);
		return { message: 'OK' };
	}
};
