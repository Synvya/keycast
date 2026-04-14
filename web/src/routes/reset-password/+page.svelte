<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';
	import { getLoginUrl } from '$lib/utils/env';

	const api = new KeycastApi();
	const loginUrl = getLoginUrl();
	const isSynvyaManaged = loginUrl !== '/login';
	const pageTitle = isSynvyaManaged ? 'Reset Password - Synvya' : `Reset Password - ${BRAND.name}`;

	let password = $state('');
	let confirmPassword = $state('');
	let isLoading = $state(false);
	let showSuccess = $state(false);

	const token = $derived($page.url.searchParams.get('token'));

	function redirectToLogin() {
		if (loginUrl.startsWith('http://') || loginUrl.startsWith('https://')) {
			window.location.assign(loginUrl);
			return;
		}

		goto(loginUrl);
	}

	async function handleSubmit() {
		if (!token) {
			toast.error('Invalid or missing reset token');
			return;
		}

		if (password.length < 8) {
			toast.error('Password must be at least 8 characters');
			return;
		}

		if (password !== confirmPassword) {
			toast.error('Passwords do not match');
			return;
		}

		try {
			isLoading = true;

			await api.post('/auth/reset-password', {
				token,
				new_password: password
			});

			toast.success('Password reset successfully!');
			showSuccess = true;
		} catch (err: any) {
			console.error('Reset password error:', err);
			toast.error(err.message || 'Failed to reset password. The link may have expired.');
		} finally {
			isLoading = false;
		}
	}
</script>

<svelte:head>
	<title>{pageTitle}</title>
</svelte:head>

<div class:auth-page={true} class:synvya-page={isSynvyaManaged}>
	<div class:auth-container={true} class:synvya-container={isSynvyaManaged}>
		<a href={isSynvyaManaged ? loginUrl : '/'} class="auth-branding">
			{#if isSynvyaManaged}
				<img src="/synvya-logo.png" alt="Synvya" class="synvya-logo-img" />
			{:else}
				<img src="/divine-logo.svg" alt="{BRAND.shortName}" class="auth-logo-img" />
				<span class="auth-logo-sub">Login</span>
			{/if}
		</a>

		{#if showSuccess}
			<div class="success-notice">
				<div class="notice-icon success">
					<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256">
						<path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm45.66,85.66-56,56a8,8,0,0,1-11.32,0l-24-24a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32Z"></path>
					</svg>
				</div>
				<h1>Password updated</h1>
				<p class="subtitle">Your password has been reset successfully. You can now sign in with your new password.</p>
				{#if isSynvyaManaged && loginUrl.startsWith('http')}
					<a href={loginUrl} class="btn-primary">Sign in</a>
				{:else}
					<a href={loginUrl} class="btn-primary">Sign in</a>
				{/if}
			</div>
		{:else}
			<div class="auth-copy">
				<h1>{isSynvyaManaged ? 'Set new password' : 'Reset Password'}</h1>
				<p class="subtitle">{isSynvyaManaged ? 'Enter your new password below.' : 'Enter your new password'}</p>
			</div>

			{#if !token}
				<div class="error-message">
					<p>Invalid or missing reset token.</p>
					<p>Please request a new password reset link.</p>
				</div>
				<a href={loginUrl} class="btn-primary">Request New Link</a>
			{:else}
				<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
					<div class="form-group">
						<label for="password">New Password</label>
						<input
							id="password"
							type="password"
							bind:value={password}
							placeholder="At least 8 characters"
							required
							minlength="8"
							disabled={isLoading}
						/>
					</div>

					<div class="form-group">
						<label for="confirmPassword">Confirm Password</label>
						<input
							id="confirmPassword"
							type="password"
							bind:value={confirmPassword}
							placeholder="Confirm your password"
							required
							minlength="8"
							disabled={isLoading}
						/>
					</div>

					<button type="submit" class="btn-primary" disabled={isLoading}>
						{isLoading ? 'Resetting...' : 'Reset Password'}
					</button>
				</form>
			{/if}

			<p class="auth-link">
				<a href={loginUrl}>Back to Login</a>
			</p>
		{/if}
	</div>
</div>

<style>
	.auth-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 1rem;
		background: var(--color-divine-bg);
	}

	.synvya-page {
		padding: 1.5rem;
		background: #ffffff;
	}

	.auth-container {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 1rem;
		padding: 2rem;
		max-width: 420px;
		width: 100%;
		box-shadow: 0 2px 8px rgba(39, 197, 139, 0.08);
	}

	.synvya-container {
		background: transparent;
		border: none;
		border-radius: 0;
		padding: 0;
		box-shadow: none;
		max-width: 24rem;
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
	}

	.auth-branding {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 2px;
		text-decoration: none;
		margin-bottom: 1.5rem;
	}

	.auth-branding:hover {
		opacity: 0.85;
	}

	.auth-logo-img {
		height: 28px;
	}

	.synvya-logo-img {
		height: 2.75rem;
		width: auto;
	}

	.auth-copy {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.auth-logo-sub {
		font-family: 'Inter', sans-serif;
		font-weight: 500;
		font-size: 11px;
		letter-spacing: 3px;
		text-transform: uppercase;
		color: var(--color-divine-green);
		opacity: 0.6;
	}

	h1 {
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-text);
		font-family: var(--font-heading);
		font-size: 1.75rem;
		font-weight: 700;
		text-align: center;
		letter-spacing: -0.02em;
	}

	.synvya-container h1 {
		color: #0f172a;
		font-family: var(--font-sans);
		font-size: 1.875rem;
		font-weight: 600;
		letter-spacing: -0.01em;
		line-height: 1.15;
	}

	.subtitle {
		color: var(--color-divine-text-secondary);
		margin: 0 0 1.5rem 0;
		text-align: center;
		font-size: 0.95rem;
	}

	.synvya-container .subtitle,
	.synvya-container .auth-link {
		color: #64748b;
	}

	.synvya-container .subtitle {
		margin: 0;
		font-size: 0.975rem;
		line-height: 1.5;
	}

	.form-group {
		margin-bottom: 1rem;
	}

	.synvya-container .form-group {
		margin-bottom: 0;
	}

	label {
		display: block;
		margin-bottom: 0.375rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.875rem;
		font-weight: 500;
	}

	.synvya-container label {
		margin-bottom: 0.5rem;
		color: #0f172a;
	}

	input {
		width: 100%;
		padding: 0.75rem 1rem;
		background: var(--color-divine-muted);
		border: 1px solid var(--color-divine-border);
		border-radius: 0.5rem;
		color: var(--color-divine-text);
		font-size: 1rem;
		box-sizing: border-box;
		transition: border-color 0.2s, box-shadow 0.2s;
	}

	input:focus {
		outline: none;
		border-color: var(--color-divine-green);
		box-shadow: 0 0 0 2px rgba(39, 197, 139, 0.2);
	}

	input::placeholder {
		color: var(--color-divine-text-secondary);
		opacity: 0.6;
	}

	input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.synvya-container input {
		background: #eff6ff;
		border-color: #dbe4f0;
		border-radius: 0.75rem;
		color: #0f172a;
		padding: 0.875rem 1rem;
	}

	.synvya-container input::placeholder {
		color: #9aa7b8;
		opacity: 1;
	}

	.synvya-container input:focus {
		border-color: #22c55e;
		box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.15);
	}

	.synvya-container form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.btn-primary {
		display: block;
		width: 100%;
		padding: 0.75rem 1.5rem;
		background: var(--color-divine-green);
		color: white;
		border: none;
		border-radius: 9999px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: all 0.2s;
		text-align: center;
		text-decoration: none;
		margin-top: 0.5rem;
	}

	.synvya-container .btn-primary {
		margin-top: 0.25rem;
		border-radius: 0.75rem;
		background: #22c55e;
		box-shadow: none;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--color-divine-green-dark);
		box-shadow: 0 2px 8px rgba(39, 197, 139, 0.16);
	}

	.synvya-container .btn-primary:hover:not(:disabled) {
		background: #16a34a;
	}

	.btn-primary:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.auth-link {
		text-align: center;
		margin-top: 1rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.875rem;
	}

	.auth-link a {
		color: var(--color-divine-green);
		text-decoration: none;
		font-weight: 500;
	}

	.auth-link a:hover {
		text-decoration: underline;
	}

	.synvya-container .auth-link a {
		color: #334155;
		text-decoration: underline;
		text-underline-offset: 2px;
		font-weight: 400;
	}

	.error-message {
		background: rgba(239, 68, 68, 0.1);
		border: 1px solid var(--color-divine-error);
		border-radius: 0.75rem;
		padding: 1rem;
		margin-bottom: 1.5rem;
		color: var(--color-divine-error);
	}

	.error-message p {
		margin: 0 0 0.5rem 0;
	}

	.error-message p:last-child {
		margin-bottom: 0;
	}

	.synvya-container .error-message {
		margin-bottom: 0;
		background: #fef2f2;
		border-color: #fecaca;
		color: #b91c1c;
	}

	.success-notice {
		text-align: center;
		padding: 1rem 0;
	}

	.success-notice .notice-icon {
		display: flex;
		justify-content: center;
		margin-bottom: 1rem;
	}

	.success-notice .notice-icon.success {
		color: var(--color-divine-green);
	}

	.synvya-container .success-notice .notice-icon.success {
		color: #22c55e;
	}

	.success-notice h1 {
		margin-bottom: 0.5rem;
	}

	.success-notice .subtitle {
		margin-bottom: 1.5rem;
	}

	.synvya-container .success-notice .subtitle {
		color: #64748b;
		margin-bottom: 1.5rem;
	}

	@media (max-width: 640px) {
		.synvya-page {
			padding: 1.25rem;
		}

		.synvya-container h1 {
			font-size: 1.625rem;
		}
	}
</style>
