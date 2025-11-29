<script lang="ts">
	import { enhance } from '$app/forms';

	let { form } = $props();
</script>

<form method="post" use:enhance>
	<label>
		<div>Username</div>
		<input type="text" name="username" placeholder="Username" required />
	</label>

	<label>
		<div>Password</div>
		<input type="password" name="password" placeholder="Password" required />
	</label>

	<label style="display: block;">
		<input type="checkbox" name="remember" />
		<span>Keep login on this device</span>
	</label>

	<section>
		<button>Login</button>
	</section>

	{#if form?.message}
		<em style="color: crimson;">{form.message}</em>
	{/if}
</form>
