import adapter from '@sveltejs/adapter-auto';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite-plus';

export default defineConfig({
	lint: {
		categories: {
			correctness: 'error'
		},
		env: {
			builtin: true,
			browser: true,
			node: true
		},
		jsPlugins: [
			{
				name: 'vite-plus',
				specifier: 'vite-plus/oxlint-plugin'
			}
		],
		rules: {
			'vite-plus/prefer-vite-plus-imports': 'error'
		},
		options: {
			typeAware: true,
			typeCheck: true
		}
	},
	fmt: {
		useTabs: true,
		singleQuote: true,
		trailingComma: 'none',
		printWidth: 100,
		sortPackageJson: false,
		svelte: {},
		associations: [
			{
				files: ['*.svelte'],
				language: 'svelte'
			}
		],
		ignorePatterns: ['pnpm-lock.yaml']
	},
	plugins: [
		sveltekit({
			preprocess: vitePreprocess(),
			adapter: adapter()
		})
	],
	test: {
		expect: { requireAssertions: true },
		environment: 'node',
		include: ['src/**/*.{test,spec}.{js,ts}'],
		exclude: ['src/**/*.svelte.{test,spec}.{js,ts}']
	}
});
