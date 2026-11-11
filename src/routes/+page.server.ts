import { auth } from './auth.server.js';

export function load() {
	const user = auth.requireUser();
	return { user };
}
