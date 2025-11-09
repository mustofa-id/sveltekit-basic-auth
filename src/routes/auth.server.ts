/** usage example */

import { getRequestEvent } from '$app/server';
import {
	BasicAuth,
	type AuthSession,
	type SaveAuthSession,
	type SessionDataSource
} from '$lib/index.js';
import { redirect } from '@sveltejs/kit';

export interface User {
	id: string;
	fullName: string;
	username: string;
	password: string;
}

export type UserSession = AuthSession<User>;

export const users: User[] = [];

const sessions = new Map<string, SaveAuthSession<User>>();

const inMemoryDataSource: SessionDataSource<User> = {
	save(session) {
		sessions.set(session.id, session);
	},
	find(id) {
		const session = sessions.get(id);
		if (!session) return null;
		return {
			id: session.id,
			user: users.find((u) => u.id == session.userId)!,
			expiresAt: session.expiresAt
		};
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
