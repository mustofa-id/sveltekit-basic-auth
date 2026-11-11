import crypto from 'node:crypto';
import { describe, it, expect, vi, afterEach } from 'vite-plus/test';
import { isRedirect, type RequestEvent } from '@sveltejs/kit';
import { getRequestEvent } from '$app/server';

import { BasicAuth, SQLiteSessionDataSource, generateSessionId } from './index.js';

vi.mock('$app/server', () => ({
	getRequestEvent: vi.fn()
}));

type MockUser = { id: string; name: string };

type MockSession = {
	id: string;
	user: MockUser;
	expiresAt: Date;
};

afterEach(() => {
	vi.clearAllMocks();
});

class MockCookies {
	store = new Map<string, { value: string; options?: Record<string, unknown> }>();
	lastSet: { name: string; value: string; options?: Record<string, unknown> } | null = null;
	lastDeleted: { name: string; options?: Record<string, unknown> } | null = null;

	get(name: string) {
		return this.store.get(name)?.value;
	}

	set(name: string, value: string, options?: Record<string, unknown>) {
		this.store.set(name, { value, options });
		this.lastSet = { name, value, options };
	}

	delete(name: string, options?: Record<string, unknown>) {
		this.store.delete(name);
		this.lastDeleted = { name, options };
	}
}

function createRequestEvent(
	options: { routeId?: string | null; session?: MockSession | null } = {}
): { event: RequestEvent; cookies: MockCookies } {
	const cookies = new MockCookies();
	const event = {
		cookies,
		locals: { session: options.session ?? null },
		route: { id: options.routeId === undefined ? '/sessions' : options.routeId }
	} as unknown as RequestEvent;
	return { event, cookies };
}

function createDataSource() {
	return new SQLiteSessionDataSource<MockUser>({
		path: `file:${crypto.randomUUID()}?mode=memory&cache=shared`,
		getUser: (id) => ({ id, name: `User ${id}` })
	});
}

describe('BasicAuth', () => {
	it('hashes and verifies secrets using scrypt', async () => {
		const auth = new BasicAuth(createDataSource());
		const hashed = await auth.hash('super-secret');

		expect(hashed.startsWith('scrypt$')).toBe(true);
		expect(await auth.verify('super-secret', hashed)).toBe(true);
		expect(await auth.verify('not-the-same', hashed)).toBe(false);
	});

	it('stores sessions and sets cookies during login', async () => {
		const ds = createDataSource();
		const auth = new BasicAuth(ds);
		const { event, cookies } = createRequestEvent();

		vi.mocked(getRequestEvent).mockReturnValue(event);

		await auth.login('user-1');

		const cookie = cookies.lastSet;
		expect(cookie?.name).toBe('sid');
		expect(cookie?.options).toMatchObject({ httpOnly: true, path: '/' });

		const token = cookie?.value ?? '';
		const sessionId = generateSessionId(token);
		const session = ds.find(sessionId);

		expect(session?.user).toEqual({ id: 'user-1', name: 'User user-1' });
		expect(session?.expiresAt.getTime()).toBeGreaterThan(Date.now());
	});

	it('renews sessions nearing expiration through the hook', async () => {
		const ds = createDataSource();
		const auth = new BasicAuth(ds);

		const token = 'soon-expiring';
		const sessionId = generateSessionId(token);

		const originalExpiry = new Date(Date.now() + 5 * 60 * 1000);
		await ds.save({ id: sessionId, userId: 'user-2', expiresAt: originalExpiry });

		const { event, cookies } = createRequestEvent();
		cookies.set('sid', token);

		const resolve = vi.fn().mockResolvedValue('ok');
		const result = await auth.hook({ event, resolve });

		expect(result).toBe('ok');

		const session = ds.find(sessionId);
		expect(session?.expiresAt.getTime()).toBeGreaterThan(originalExpiry.getTime());
		expect(event.locals.session?.id).toBe(sessionId);
		expect(cookies.lastSet?.value).toBe(token);
	});

	it('removes expired sessions and clears cookies in the hook', async () => {
		const ds = createDataSource();
		const auth = new BasicAuth(ds);

		const token = 'expired-token';
		const sessionId = generateSessionId(token);

		await ds.save({ id: sessionId, userId: 'user-3', expiresAt: new Date(Date.now() - 1000) });

		const { event, cookies } = createRequestEvent();
		cookies.set('sid', token);

		const resolve = vi.fn().mockResolvedValue('ok');
		await auth.hook({ event, resolve });

		expect(ds.find(sessionId)).toBeNull();
		expect(event.locals.session).toBeNull();
		expect(cookies.lastDeleted?.name).toBe('sid');
	});

	it('clears session when no cookie is present in the hook', async () => {
		const ds = createDataSource();
		const auth = new BasicAuth(ds);
		const { event } = createRequestEvent();

		const resolve = vi.fn().mockResolvedValue('ok');
		const result = await auth.hook({ event, resolve });

		expect(result).toBe('ok');
		expect(event.locals.session).toBeNull();
		expect(resolve).toHaveBeenCalledWith(event);
	});

	it('logout deletes the session and clears the cookie', async () => {
		const ds = createDataSource();
		const auth = new BasicAuth(ds);
		const { event, cookies } = createRequestEvent();

		vi.mocked(getRequestEvent).mockReturnValue(event);

		await auth.login('user-4');

		const token = cookies.lastSet?.value ?? '';
		const sessionId = generateSessionId(token);
		event.locals.session = {
			id: sessionId,
			user: { id: 'user-4', name: 'User user-4' },
			expiresAt: new Date()
		} as unknown as typeof event.locals.session;

		await auth.logout();

		expect(ds.find(sessionId)).toBeNull();
		expect(cookies.lastDeleted?.name).toBe('sid');
	});
});

describe('requireUser', () => {
	it('returns the user when a session exists', () => {
		const auth = new BasicAuth(createDataSource());
		const user = { id: 'user-5', name: 'User user-5' };
		const { event } = createRequestEvent({
			routeId: '/sessions',
			session: { id: 'session-1', user, expiresAt: new Date() }
		});
		vi.mocked(getRequestEvent).mockReturnValue(event);

		expect(auth.requireUser()).toEqual(user);
	});

	it('redirects to the login route when there is no session', () => {
		const auth = new BasicAuth(createDataSource());
		const { event } = createRequestEvent({ routeId: '/sessions' });
		vi.mocked(getRequestEvent).mockReturnValue(event);

		let thrown: unknown;
		try {
			auth.requireUser();
		} catch (error) {
			thrown = error;
		}

		expect(isRedirect(thrown)).toBe(true);
		if (isRedirect(thrown)) {
			expect(thrown.status).toBe(303);
			expect(thrown.location).toBe('/login');
		}
	});

	it('does not redirect on the login route', () => {
		const auth = new BasicAuth(createDataSource());
		const { event } = createRequestEvent({ routeId: '/login' });
		vi.mocked(getRequestEvent).mockReturnValue(event);

		expect(auth.requireUser()).toBeUndefined();
	});

	it('does not redirect when the route is unknown', () => {
		const auth = new BasicAuth(createDataSource());
		const { event } = createRequestEvent({ routeId: null });
		vi.mocked(getRequestEvent).mockReturnValue(event);

		expect(auth.requireUser()).toBeUndefined();
	});

	it('uses the login route from the constructor config', () => {
		const auth = new BasicAuth(createDataSource(), { loginRouteId: '/sessions' });
		const { event } = createRequestEvent({ routeId: '/login' });
		vi.mocked(getRequestEvent).mockReturnValue(event);

		let thrown: unknown;
		try {
			auth.requireUser();
		} catch (error) {
			thrown = error;
		}

		expect(isRedirect(thrown)).toBe(true);
		if (isRedirect(thrown)) expect(thrown.location).toBe('/sessions');
	});
});
