# SvelteKit Basic Auth

A lightweight authentication helper library for SvelteKit. Suited for non-critical, low-complexity, or internal environments where lightweight authentication utilities are appropriate.

This library is intentionally minimal, good for quick prototypes, admin tools, or low-complexity apps. For production-grade or large-scale authentication needs, consider a more robust solution such as [Auth.js](https://authjs.dev/), which provides advanced security features, adapters, and wide ecosystem support.

## Usage

```sh
npm install sveltekit-basic-auth
```

See code example in [routes](src/routes) and [hooks.server.ts](src/hooks.server.ts).

## Developing

```sh
npm install

npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

Everything inside `src/lib` is part of library, everything inside `src/routes` can be used as a showcase or preview app.

## Building

```sh
npm pack
```

To create a production version of your showcase app:

```sh
npm run build
```

## Publishing

```sh
npm publish
```
