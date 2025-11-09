/** usage example */

import { getRequestEvent } from '$app/server';
import { BasicAuth, type AuthSession, type SessionDataSource } from '$lib/index.js';
import { redirect } from '@sveltejs/kit';

export interface User {
	id: string;
	fullName: string;
	username: string;
	password: string;
}

const sessions = new Map<string, AuthSession<User>>();

const inMemoryDataSource: SessionDataSource<User> = {
	save(session) {
		sessions.set(session.id, session);
	},
	find(id) {
		return sessions.get(id) || null;
	},
	update(id, expiresAt) {
		const curr = sessions.get(id)!;
		curr.expiresAt = expiresAt;
		sessions.set(id, curr);
	},
	delete(id) {
		sessions.delete(id);
	}
};

export const auth = new BasicAuth(inMemoryDataSource);

export const users: User[] = [];

users.push({
	id: '81fa185f6a5343c4',
	fullName: 'Admin',
	username: 'admin',
	password: await auth.hash('Admin2025')
});

export function requiredUser() {
	const { locals, route } = getRequestEvent();
	if (!locals.session?.user && typeof route.id == 'string' && route.id != '/login') {
		// make sure to check current route to prevent redirect loop
		redirect(303, '/login');
	}
	return locals.session?.user;
}
