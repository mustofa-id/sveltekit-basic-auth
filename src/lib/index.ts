import { error, type Handle, type RequestEvent } from '@sveltejs/kit';
import crypto from 'node:crypto'; // support in most platforms/environments

type MaybePromise<T> = T | Promise<T>;

type CookieOptions = Omit<Parameters<RequestEvent['cookies']['set']>[2], 'expires'> & {
	name: string;
};

export interface AuthSession {
	id: string;
	userId: string;
	expiresAt: Date;
}

export interface SessionDataSource {
	save(session: AuthSession): MaybePromise<void>;
	find(id: string): MaybePromise<AuthSession | null>;
	update(session: Omit<AuthSession, 'userId'>): MaybePromise<void>;
	delete(id: string): MaybePromise<void>;
}

const ENCODER = new TextEncoder();
const MINUTE_IN_MS = 60_000;
const SCRYPT = { saltLength: 16, keyLength: 64, tag: 'scrypt', sep: '$' };
const DEFAULTS = { cookieName: 'sid', expiresIn: 1440 };

async function scrypt(value: string, salt: Buffer<ArrayBuffer>, length: number) {
	return new Promise<Buffer<ArrayBufferLike>>((resolve, reject) => {
		crypto.scrypt(value, salt, length, (err, derivedKey) => {
			if (err) return reject(err);
			resolve(derivedKey);
		});
	});
}

export class BasicAuth {
	constructor(
		private readonly ds: SessionDataSource,
		private readonly config?: {
			/** Session expiration in minutes; defaults to 1440. */
			expiresIn?: number;
			cookieOptions?: CookieOptions;
		}
	) {}

	async hash(plain: string): Promise<string> {
		const salt = crypto.randomBytes(SCRYPT.saltLength);
		const derivedKey = await scrypt(plain, salt, SCRYPT.keyLength);
		return [SCRYPT.tag, salt.toString('base64'), derivedKey.toString('base64')].join(SCRYPT.sep);
	}

	async verify(plain: string, hashed: string): Promise<boolean> {
		const [tag, saltB64, keyB64] = hashed.split(SCRYPT.sep);
		if (tag != SCRYPT.tag) throw new Error('Unsupported algorithm');
		const salt = Buffer.from(saltB64, 'base64');
		const storedKey = Buffer.from(keyB64, 'base64');
		const derivedKey = await scrypt(plain, salt, storedKey.length);
		return crypto.timingSafeEqual(storedKey, derivedKey);
	}

	async login(event: RequestEvent, userId: string): Promise<void> {
		const token = this.generateToken();
		const sessionId = this.generateSessionId(token);
		const expiresAt = this.expiresAt;
		await this.ds.save({ id: sessionId, userId, expiresAt });
		this.setCookie(event, token, expiresAt);
	}

	async logout(event: RequestEvent): Promise<void> {
		const session = event.locals.session;
		if (!session) error(401);
		await this.ds.delete(session.id);
		this.delCookie(event);
	}

	hook: Handle = async ({ event, resolve }) => {
		const token = event.cookies.get(this.cookieOptions.name);
		if (!token) {
			event.locals.session = null;
			return resolve(event);
		}

		const session = await this.validateSession(token);
		if (session) this.setCookie(event, token, session.expiresAt);
		else this.delCookie(event);

		event.locals.session = session;
		return resolve(event);
	};

	private setCookie(event: RequestEvent, token: string, expiresAt: Date) {
		const { name, ...opts } = this.cookieOptions;
		event.cookies.set(name, token, { ...opts, expires: expiresAt });
	}

	private delCookie(event: RequestEvent) {
		const { name, ...opts } = this.cookieOptions;
		event.cookies.delete(name, opts);
	}

	private get cookieOptions() {
		return this.config?.cookieOptions || { name: 'sid', path: '/' };
	}

	private get expiresAt() {
		return new Date(Date.now() + MINUTE_IN_MS * (this.config?.expiresIn || DEFAULTS.expiresIn));
	}

	private generateToken() {
		const bytes = crypto.getRandomValues(new Uint8Array(18));
		return Buffer.from(bytes).toString('base64url');
	}

	private generateSessionId(token: string): string {
		const buf = Buffer.from(ENCODER.encode(token));
		const digest = crypto.createHash('sha256').update(buf).digest();
		return Buffer.from(digest).toString('hex');
	}

	private async validateSession(token: string) {
		const sessionId = this.generateSessionId(token);
		const session = await this.ds.find(sessionId);
		if (!session) return null;

		const expired = Date.now() >= session.expiresAt.getTime();
		if (expired) {
			await this.ds.delete(sessionId);
			return null;
		}

		const renew = Date.now() >= session.expiresAt.getTime() - MINUTE_IN_MS * 15;
		if (renew) {
			const expiresAt = this.expiresAt;
			await this.ds.update({ id: sessionId, expiresAt });
			session.expiresAt = expiresAt;
		}

		return session;
	}
}
