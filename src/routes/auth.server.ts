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

class InMemorySessionDataSource implements SessionDataSource {
	private store = new Map<string, AuthSession>();

	save(session: AuthSession) {
		this.store.set(session.id, session);
	}

	find(id: string) {
		return this.store.get(id) || null;
	}

	update(session: Omit<AuthSession, 'userId'>) {
		const current = this.store.get(session.id)!;
		current.expiresAt = session.expiresAt;
		this.store.set(session.id, current);
	}

	delete(id: AuthSession['id']) {
		this.store.delete(id);
	}
}

export const auth = new BasicAuth(new InMemorySessionDataSource());
export const users: User[] = [];

users.push({
	id: '81fa185f6a5343c4',
	fullName: 'Admin',
	username: 'admin',
	password: await auth.hash('admin2025')
});

export function requiredUser() {
	const event = getRequestEvent();
	const session = event.locals.session;
	const routeId = event.route.id;
	if (!session && typeof routeId == 'string' && routeId != '/login') {
		// make sure to check current route to prevent redirect loop
		redirect(303, '/login');
	}
	return users.find((u) => u.id == session?.userId);
}
