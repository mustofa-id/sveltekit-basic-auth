import { fail, redirect } from '@sveltejs/kit';
import { auth, users } from '../auth.server.js';

export function load({ locals }) {
	if (locals.session?.id) redirect(303, `/`);
	return {};
}

export const actions = {
	default: async ({ request }) => {
		const fd = await request.formData();
		const username = fd.get('username')?.toString();
		const password = fd.get('password')?.toString();
		if (!username || !password) {
			return fail(400, { message: `Username and password are required` });
		}

		const user = users.find((u) => u.username == username);
		if (!user?.id) return fail(403, { message: `Invalid username or password` });

		const passwordValid = await auth.verify(password, user.password);
		if (!passwordValid) return fail(403, { message: `Invalid username or password` });

		await auth.login(user.id);
		redirect(303, '/');
	}
};
