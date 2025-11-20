/** usage example */

import { getRequestEvent } from '$app/server';
import { BasicAuth, SQLiteSessionDataSource, type AuthSession } from '$lib/index.js';
import { redirect } from '@sveltejs/kit';

export interface User {
	id: string;
	fullName: string;
	username: string;
	password: string;
}

export type UserSession = AuthSession<User>;

export const users: User[] = [];

/**
 * This example uses a built-in data source. You can create your
 * own data source by implementing `SessionDataSource` interface:
 *
 * ```ts
 * class MySessionDataSource implements SessionDataSource { ... }
 * // or
 * const mySessionDataSource: SessionDataSource = { ... }
 * ```
 */
export const sessionDataSource = new SQLiteSessionDataSource<User>({
	getUser(id) {
		return users.find((u) => u.id == id)!;
	}
});

export const auth = new BasicAuth(sessionDataSource);

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
