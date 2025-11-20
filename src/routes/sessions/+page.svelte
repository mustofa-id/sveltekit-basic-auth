<script lang="ts">
	import { enhance } from '$app/forms';

	let { data } = $props();
</script>

<h2>Sessions</h2>

<ul>
	{#each data.sessions as s}
		<li title={s.id}>
			<form action="?/kill" method="post" use:enhance>
				<input type="hidden" name="sessionId" value={s.id} />
				<span>[{s.user.username}] {s.user.fullName}</span>
				<button>Kill</button>
			</form>
		</li>
	{:else}
		<p>No active session</p>
	{/each}
</ul>

<a href="/">Home</a>
