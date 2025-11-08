import { requiredUser } from './auth.server.js';

export function load() {
	const user = requiredUser();
	return { user };
}
