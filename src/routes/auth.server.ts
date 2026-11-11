/** usage example */

import { BasicAuth, SQLiteSessionDataSource, type AuthSession } from '#lib/index.js';

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
