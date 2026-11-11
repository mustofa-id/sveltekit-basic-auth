import { fail } from '@sveltejs/kit';
import { auth, sessionDataSource } from '../auth.server.js';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = () => {
	auth.requireUser();
	const sessions = sessionDataSource.findAll();
	return { sessions };
};

export const actions: Actions = {
	kill: async ({ request }) => {
		auth.requireUser();
		const fd = await request.formData();
		const sessionId = fd.get('sessionId');
		if (typeof sessionId !== 'string' || !sessionId) {
			return fail(400, 'session id is required');
		}

		await auth.kill(sessionId);
		return { message: 'OK' };
	}
};
