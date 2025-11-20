<script lang="ts">
	let { data } = $props();
</script>

<h1>Welcome to SvelteKit Basic Auth</h1>
<p>This is a SvelteKit library that provides basic auth utilities</p>

<a href="/sessions">Sessions</a>

<p>User: {data.user?.fullName}</p>
<a href="/logout" data-sveltekit-reload>Logout</a>
