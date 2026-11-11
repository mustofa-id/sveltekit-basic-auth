import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { auth, requiredUser, sessionDataSource } from '../auth.server.js';

export const load: PageServerLoad = () => {
	requiredUser();
	const sessions = sessionDataSource.findAll();
	return { sessions };
};

export const actions: Actions = {
	kill: async ({ request }) => {
		const fd = await request.formData();
		const sessionId = fd.get('sessionId');
		if (typeof sessionId !== 'string' || !sessionId) {
			return fail(400, 'session id is required');
		}

		await auth.kill(sessionId);
		return { message: 'OK' };
	}
};
