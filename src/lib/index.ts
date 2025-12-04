import { getRequestEvent } from '$app/server';
import { error, type Handle, type RequestEvent } from '@sveltejs/kit';
import crypto from 'node:crypto';
import type { PathLike } from 'node:fs';
import { DatabaseSync, type SQLOutputValue } from 'node:sqlite';

type MaybePromise<T> = T | Promise<T>;

type CookieOptions = Omit<Parameters<RequestEvent['cookies']['set']>[2], 'expires'> & {
	name: string;
};

interface User {
	id: unknown;
}

export interface AuthSession<T extends User = User> {
	id: string;
	user: T;
	expiresAt: Date;
}

export type SaveAuthSession<T extends User = User> = Omit<AuthSession, 'user'> & {
	userId: T['id'];
};

export interface SessionDataSource<T extends User = User> {
	save(session: SaveAuthSession<T>): MaybePromise<void>;
	find(id: string): MaybePromise<AuthSession<T> | null>;
	update(id: string, expiresAt: Date): MaybePromise<void>;
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

export class SQLiteSessionDataSource<T extends User> implements SessionDataSource<T> {
	readonly db: DatabaseSync;
	readonly tableName = 'auth_sessions';

	constructor(
		private readonly config: {
			/** The database file path. Defaults to (shared) memory. */
			path?: PathLike;
			getUser: (id: T['id']) => MaybePromise<T>;
		}
	) {
		this.db = new DatabaseSync(config.path || 'file:sba-db0?mode=memory&cache=shared');
		this.db.exec(`
			-- setting pragmas
			PRAGMA foreign_keys = ON;
			PRAGMA journal_mode = WAL;
			PRAGMA synchronous = NORMAL;
			PRAGMA busy_timeout = 5000;

			-- define auth sessions table
			create table if not exists ${this.tableName} (
				id text primary key,
				user text not null,
				expires_at integer not null
			);
		`);
		Object.freeze(this);
	}

	async save(session: SaveAuthSession<T>): Promise<void> {
		const user = await this.config.getUser(session.userId);
		this.db
			.prepare(
				`insert into ${this.tableName} (id, user, expires_at) 
				values (:id, :user, :expires_at)`
			)
			.run({
				id: session.id,
				user: JSON.stringify(user),
				expires_at: session.expiresAt.getTime()
			});
	}

	find(id: string): AuthSession<T> | null {
		const result = this.db.prepare(`select * from ${this.tableName} where id = ?`).get(id);
		if (!result) return null;
		return this.toSession(result);
	}

	findAll(config?: { page?: number; size?: number }): AuthSession<T>[] {
		const { page = 1, size = 20 } = config || {};
		const offset = (page - 1) * size;
		return this.db
			.prepare(`select * from ${this.tableName} order by expires_at limit ? offset ?`)
			.all(size, offset)
			.map(this.toSession);
	}

	update(id: string, expiresAt: Date): void {
		this.db.prepare(`update ${this.tableName} set expires_at = :expires_at where id = :id`).run({
			id: id,
			expires_at: expiresAt.getTime()
		});
	}

	delete(id: string): void {
		this.db.prepare(`delete from ${this.tableName} where id = ?`).run(id);
	}

	private toSession(row: Record<string, SQLOutputValue>): AuthSession<T> {
		return {
			id: row.id as string,
			user: JSON.parse(row.user as string),
			expiresAt: new Date(row.expires_at as number)
		};
	}
}

export class BasicAuth<T extends User = User> {
	constructor(
		private readonly ds: SessionDataSource<T>,
		private readonly config?: {
			/** Session expiration in minutes; defaults to 1440. */
			expiresIn?: number;
			cookieOptions?: Partial<CookieOptions>;
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

	async login(userId: T['id'], remember?: boolean): Promise<void> {
		const event = getRequestEvent();
		const token = this.generateToken();
		const sessionId = this.generateSessionId(token);
		let expiresAt = this.expirationDate;

		if (remember) {
			expiresAt = new Date();
			expiresAt.setMonth(new Date().getMonth() + 3);
		}

		await this.ds.save({ id: sessionId, userId, expiresAt });
		this.setCookie(event, token, expiresAt);
	}

	async logout(): Promise<void> {
		const event = getRequestEvent();
		const session = event.locals.session;
		if (!session) error(412, 'No active session');
		await this.ds.delete(session.id);
		this.delCookie(event);
	}

	async kill(sessionId: string): Promise<void> {
		// only delete session, cookie will invalidated on hook
		await this.ds.delete(sessionId);
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

		event.locals.session = session as typeof event.locals.session;
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

	private get cookieOptions(): CookieOptions {
		const defaults: CookieOptions = { name: 'sid', path: '/', httpOnly: true };
		return { ...defaults, ...this.config?.cookieOptions };
	}

	private get expirationDate() {
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
			const expiresAt = this.expirationDate;
			await this.ds.update(sessionId, expiresAt);
			session.expiresAt = expiresAt;
		}

		return session;
	}
}
