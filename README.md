# SvelteKit Basic Auth

A lightweight authentication helper library for SvelteKit. Suited for non-critical, low-complexity, or internal environments where lightweight authentication utilities are appropriate.

This library is intentionally minimal. For production-grade or large-scale authentication needs, consider a more robust solution such as [Auth.js](https://authjs.dev/), which provides advanced security features, adapters, and wide ecosystem support.

## Installation

```sh
npm install sveltekit-basic-auth
```

## Usage

### 1. Declare the session on `App.Locals`

```ts
// src/app.d.ts

declare global {
	namespace App {
		interface Locals {
			session: import('sveltekit-basic-auth').AuthSession<YourUserInterface> | null;
		}
	}
}

export {};
```

### 2. Create an auth instance

```ts
// src/auth.server.ts
import { BasicAuth, SQLiteSessionDataSource } from 'sveltekit-basic-auth';

interface User {
	id: string;
	fullName: string;
	username: string;
}

export const sessionDataSource = new SQLiteSessionDataSource<User>({
	getUser(id) {
		return users.find((user) => user.id === id)!;
	}
});

export const auth = new BasicAuth(sessionDataSource, {
	loginRouteId: '/login'
});
```

`SQLiteSessionDataSource` uses Node's built-in `node:sqlite` module, so it is server-only and requires a Node.js version that provides it (Node 22.5+; Node 24 is recommended).

### 3. Install the hook

```ts
// src/hooks.server.ts
import { sequence } from '@sveltejs/kit/hooks';
import { auth } from './auth.server.js';

export const handle = sequence(auth.hook);
```

The hook reads the session cookie, validates the session, refreshes it when it is close to expiring, and populates `event.locals.session`.

### 4. Log users in and out

```ts
import { auth } from './auth.server.js';

// create a session and set the session cookie
await auth.login(user.id, remember);

// delete the current session and clear the cookie
await auth.logout();

// invalidate a specific session
await auth.kill(sessionId);
```

### 5. Protect routes

```ts
// src/routes/+page.server.ts
import { auth } from './auth.server.js';

export function load() {
	const user = auth.requireUser();
	return { user };
}
```

`auth.requireUser()` returns the authenticated user. When there is no active session, it redirects to `loginRouteId` (default `/login`).

The redirect is skipped when the current route is the login route, so `requireUser()` returns `undefined` there instead of causing a redirect loop.

`requireUser()` must be called from server-side code, such as a `load` function, a form action, or a hook.

### Passwords

```ts
const hashed = await auth.hash('plain-password');
const isValid = await auth.verify('plain-password', hashed);
```

## Configuration

`new BasicAuth(dataSource, config)` accepts:

| Option          | Type      | Default                                      | Description                                                       |
| --------------- | --------- | -------------------------------------------- | ----------------------------------------------------------------- |
| `expiresIn`     | `number`  | `1440`                                       | Session lifetime in minutes.                                      |
| `cookieOptions` | `object`  | `{ name: 'sid', path: '/', httpOnly: true }` | Session cookie name and options. `name` is required.              |
| `loginRouteId`  | `RouteId` | `'/login'`                                   | Route used by `requireUser()` when the user is not authenticated. |

`loginRouteId` must be a valid SvelteKit route id from your app.

`cookieOptions` accepts SvelteKit's cookie options (the third argument to `cookies.set`) plus a required `name`. The `expires` option is managed by the library:

```ts
export const auth = new BasicAuth(sessionDataSource, {
	expiresIn: 60 * 24,
	cookieOptions: {
		name: 'session',
		secure: true,
		sameSite: 'lax'
	},
	loginRouteId: '/login'
});
```

## Custom data sources

`SQLiteSessionDataSource` is optional. Implement `SessionDataSource<T>` to store sessions elsewhere:

```ts
import type { SessionDataSource } from 'sveltekit-basic-auth';

export const sessionDataSource: SessionDataSource<User> = {
	save(session) {
		// persist { id, userId, expiresAt }
	},
	find(id) {
		// return { id, user, expiresAt } or null
	},
	update(id, expiresAt) {
		// extend the session expiration
	},
	delete(id) {
		// remove the session
	}
};
```

Each method may return a value or a promise.

## Showcase app

The `src/routes` directory contains a working example, including login, logout, session listing, and route protection.

## Developing

```sh
vp install

vp dev

# or start the server and open the app in a new browser tab
vp dev --open
```

Everything inside `src/lib` is part of the library. Everything inside `src/routes` is the showcase app.

Useful commands:

```sh
vp check       # format, lint, and type checks
vp test --run  # run the test suite
vp run build
```

## Building

```sh
npm pack
```

To create a production version of the showcase app:

```sh
vp run build
```

## Publishing

Releases are managed with Changesets:

```sh
vp run release
```
