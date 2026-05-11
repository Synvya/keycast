<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { toast } from 'svelte-hot-french-toast';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { BRAND } from '$lib/brand';
	import { getLoginUrl } from '$lib/utils/env';
	import { CheckCircle, XCircle, Warning, CircleNotch } from 'phosphor-svelte';

	const api = new KeycastApi();
	const loginUrl = getLoginUrl();
	const isSynvyaManaged = loginUrl !== '/login';
	const pageTitle = isSynvyaManaged ? 'Verify Email - Synvya Restaurant' : `Verify Email - ${BRAND.name}`;
	let status = $state<'loading' | 'processing' | 'success' | 'oauth_redirect' | 'headless_verified' | 'error' | 'no-token'>('loading');
	let message = $state('');
	let redirectUrl = $state('');

	// Helper function to sleep for ms
	function sleep(ms: number): Promise<void> {
		return new Promise(resolve => setTimeout(resolve, ms));
	}

	// Response type from the verify-email API
	interface VerifyEmailResponse {
		success: boolean;
		message?: string;
		redirect_to?: string;
		authenticated?: boolean;
		status?: string;
		retry_after?: number;
	}

	async function verifyEmail(token: string): Promise<void> {
		const maxAttempts = 30; // Max 30 seconds of polling

		for (let attempt = 0; attempt < maxAttempts; attempt++) {
			try {
				const response = await api.post<VerifyEmailResponse>('/auth/verify-email', { token });

				// Handle "processing" status - bcrypt still hashing
				if (response.status === 'processing') {
					status = 'processing';
					message = response.message || 'Processing your registration...';
					const waitTime = (response.retry_after || 1) * 1000;
					await sleep(waitTime);
					continue;
				}

				if (response.success) {
					// Headless flow (mobile app) — app is polling, just show success
					if (response.status === 'headless') {
						status = 'headless_verified';
						message = response.message || 'Email verified! Open the app to continue.';
						toast.success('Email verified!');
						return;
					}

					// Check if this is an OAuth flow (has redirect_to)
					if (response.redirect_to) {
						status = 'oauth_redirect';
						message = 'Email verified! Redirecting to application...';
						redirectUrl = response.redirect_to;
						toast.success('Email verified!');

						// Redirect to OAuth client immediately
						// Chrome on Android doesn't trigger App Links for window.location.href
						// Use intent:// URL to force Chrome to check for App Links
						setTimeout(() => {
							const url = response.redirect_to!;
							const isAndroid = /Android/i.test(navigator.userAgent);
							if (isAndroid && url.startsWith('https://')) {
								try {
									const parsed = new URL(url);
									const intentUrl = `intent://${parsed.host}${parsed.pathname}${parsed.search}#Intent;scheme=https;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;end`;
									window.location.href = intentUrl;
								} catch (e) {
									window.location.href = url;
								}
							} else {
								window.location.href = url;
							}
						}, 1500);
					} else if (response.authenticated) {
						// Normal flow - user is now logged in
						status = 'success';
						message = response.message || 'Email verified! You are now logged in.';
						toast.success('Email verified!');

						// Redirect to home/dashboard
						setTimeout(() => {
							goto('/');
						}, 2000);
					} else {
						// Legacy flow - just verified, redirect to login
						status = 'success';
						message = response.message || 'Email verified successfully!';
						toast.success('Email verified!');

						setTimeout(() => {
							goto('/login');
						}, 3000);
					}
				} else {
					status = 'error';
					message = response.message || 'Verification failed';
				}
				return; // Exit after successful handling
			} catch (err: any) {
				// Check for 410 Gone (registration expired)
				if (err.status === 410) {
					status = 'error';
					message = 'Registration expired. Please register again.';
					return;
				}
				// Check for 503 Service Unavailable (server busy)
				if (err.status === 503) {
					status = 'processing';
					message = 'Server is busy, please wait...';
					await sleep(5000);
					continue;
				}
				console.error('Verification error:', err);
				status = 'error';
				message = err.message || 'Verification failed. If you have already verified your email, you can log in.';
				return;
			}
		}

		// Timed out after max attempts
		status = 'error';
		message = 'Verification timed out. Please try again.';
	}

	onMount(async () => {
		const token = $page.url.searchParams.get('token');

		if (!token) {
			status = 'no-token';
			message = 'No verification token provided';
			return;
		}

		await verifyEmail(token);
	});
</script>

<svelte:head>
	<title>{pageTitle}</title>
</svelte:head>

<div class:verify-page={true} class:synvya-page={isSynvyaManaged}>
	<div class:verify-container={true} class:synvya-container={isSynvyaManaged}>
		<!-- Logo/Branding -->
		<a href="/" class:verify-branding={true} class:synvya-branding={isSynvyaManaged}>
			{#if isSynvyaManaged}
				<img src="/synvya-logo.png" alt="Synvya" class="synvya-logo-img" />
			{:else}
				<img src="/synvya-logo.svg" alt="{BRAND.shortName}" class="verify-logo-img" />
				<span class="verify-logo-sub">Login</span>
			{/if}
		</a>

		{#if status === 'loading'}
			<div class="status-icon loading">
				{#if isSynvyaManaged}<CircleNotch size={32} weight="regular" class="synvya-spin" />{:else}<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256" class="spin"> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,176A72,72,0,1,1,200,128,72.08,72.08,0,0,1,128,200Z" opacity="0.2"></path> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,16a88,88,0,0,1,88,88h-16a72,72,0,0,0-72-72Z"></path> </svg>{/if}
			</div>
			<h1>Verifying your email...</h1>
			<p class="subtitle">Please wait</p>

		{:else if status === 'processing'}
			<div class="status-icon loading">
				{#if isSynvyaManaged}<CircleNotch size={32} weight="regular" class="synvya-spin" />{:else}<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256" class="spin"> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,176A72,72,0,1,1,200,128,72.08,72.08,0,0,1,128,200Z" opacity="0.2"></path> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,16a88,88,0,0,1,88,88h-16a72,72,0,0,0-72-72Z"></path> </svg>{/if}
			</div>
			<h1>Almost there...</h1>
			<p class="subtitle">{message}</p>
			<p class="processing-notice">Finishing up your registration</p>

		{:else if status === 'oauth_redirect'}
			<div class="status-icon success">
				{#if isSynvyaManaged}<CheckCircle size={32} weight="regular" />{:else}<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256"> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm45.66,85.66-56,56a8,8,0,0,1-11.32,0l-24-24a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32Z"></path> </svg>{/if}
			</div>
			<h1>Email Verified!</h1>
			<p class="subtitle">{message}</p>
			<p class="redirect-notice">Redirecting to application...</p>

		{:else if status === 'headless_verified'}
			<div class="status-icon success">
				{#if isSynvyaManaged}<CheckCircle size={32} weight="regular" />{:else}<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256"> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm45.66,85.66-56,56a8,8,0,0,1-11.32,0l-24-24a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32Z"></path> </svg>{/if}
			</div>
			<h1>Email Verified!</h1>
			<p class="subtitle">{message}</p>

		{:else if status === 'success'}
			<div class="status-icon success">
				{#if isSynvyaManaged}<CheckCircle size={32} weight="regular" />{:else}<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256"> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm45.66,85.66-56,56a8,8,0,0,1-11.32,0l-24-24a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32Z"></path> </svg>{/if}
			</div>
			<h1>Email Verified!</h1>
			<p class="subtitle">{message}</p>
			<p class="redirect-notice">Redirecting...</p>
			<a href="/" class="btn-primary">Go to Dashboard</a>

		{:else if status === 'error'}
			<div class="status-icon error">
				{#if isSynvyaManaged}<XCircle size={32} weight="regular" />{:else}<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256"> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm37.66,130.34a8,8,0,0,1-11.32,11.32L128,139.31l-26.34,26.35a8,8,0,0,1-11.32-11.32L116.69,128,90.34,101.66a8,8,0,0,1,11.32-11.32L128,116.69l26.34-26.35a8,8,0,0,1,11.32,11.32L139.31,128Z"></path> </svg>{/if}
			</div>
			<h1>Verification Failed</h1>
			<p class="subtitle">{message}</p>
			<div class="actions">
				<a href={loginUrl} class="btn-secondary">Go to Login</a>
				<a href="/register" class="btn-primary">Create New Account</a>
			</div>

		{:else if status === 'no-token'}
			<div class="status-icon error">
				{#if isSynvyaManaged}<Warning size={32} weight="regular" />{:else}<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" fill="currentColor" viewBox="0 0 256 256"> <path d="M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm-8,56a8,8,0,0,1,16,0v56a8,8,0,0,1-16,0Zm8,104a12,12,0,1,1,12-12A12,12,0,0,1,128,184Z"></path> </svg>{/if}
			</div>
			<h1>Invalid Link</h1>
			<p class="subtitle">This verification link is invalid or incomplete.</p>
			<div class="actions">
				<a href={loginUrl} class="btn-secondary">Go to Login</a>
				<a href="/register" class="btn-primary">Create New Account</a>
			</div>
		{/if}
	</div>
</div>

<style>
	.verify-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 1rem;
		background: var(--color-divine-bg);
	}

	.synvya-page {
		position: fixed;
		inset: 0;
		z-index: 1;
		background: hsl(0 0% 100%);
		overflow-y: auto;
	}

	@media (prefers-color-scheme: dark) {
		.synvya-page {
			background: hsl(222.2 84% 4.9%);
		}
	}

	.verify-container {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 1rem;
		padding: 2rem;
		max-width: 420px;
		width: 100%;
		text-align: center;
		box-shadow: 0 2px 8px rgba(39, 197, 139, 0.08);
	}

	.synvya-container {
		background: transparent;
		border: none;
		border-radius: 0;
		padding: 0;
		box-shadow: none;
		max-width: 24rem;
	}

	.verify-branding {
		display: inline-flex;
		flex-direction: column;
		align-items: center;
		gap: 2px;
		text-decoration: none;
		margin-bottom: 1.5rem;
	}

	.verify-branding:hover {
		opacity: 0.85;
	}

	.synvya-branding {
		flex-direction: column;
		align-items: center;
		gap: 0;
		opacity: 1;
	}

	.synvya-branding:hover {
		opacity: 0.95;
	}

	.verify-logo-img {
		height: 28px;
	}

	.verify-logo-sub {
		font-family: 'Inter', sans-serif;
		font-weight: 500;
		font-size: 11px;
		letter-spacing: 3px;
		text-transform: uppercase;
		color: var(--color-divine-green);
		opacity: 0.6;
	}

	.synvya-logo-img {
		height: 3rem;
		width: auto;
	}

	.status-icon {
		display: flex;
		justify-content: center;
		margin-bottom: 1.25rem;
	}

	.status-icon.loading {
		color: var(--color-divine-green);
	}

	.status-icon.success {
		color: var(--color-divine-green);
	}

	.status-icon.error {
		color: var(--color-divine-error);
	}

	.spin {
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}

	h1 {
		margin: 0 0 0.5rem 0;
		color: var(--color-divine-text);
		font-family: var(--font-heading);
		font-size: 1.5rem;
		font-weight: 700;
	}

	.synvya-container h1 {
		color: hsl(222.2 84% 4.9%);
		font-family: system-ui, -apple-system, sans-serif;
		font-size: 1.25rem;
		font-weight: 600;
		letter-spacing: -0.01em;
	}

	@media (prefers-color-scheme: dark) {
		.synvya-container h1 {
			color: hsl(210 40% 98%);
		}
	}

	.subtitle {
		color: var(--color-divine-text-secondary);
		margin: 0 0 1.25rem 0;
		font-size: 0.95rem;
	}

	.synvya-container .subtitle,
	.synvya-container .redirect-notice,
	.synvya-container .processing-notice {
		color: hsl(215.4 16.3% 46.9%);
	}

	@media (prefers-color-scheme: dark) {
		.synvya-container .subtitle,
		.synvya-container .redirect-notice,
		.synvya-container .processing-notice {
			color: hsl(215 20.2% 65.1%);
		}
	}

	/* Synvya-themed status icons: small chip with soft background instead of
	   a large filled-circle SVG. */
	.synvya-container .status-icon {
		margin-bottom: 1rem;
	}

	.synvya-container .status-icon :global(svg) {
		padding: 0.45rem;
		border-radius: 999px;
		background: rgba(15, 23, 42, 0.04);
	}

	.synvya-container .status-icon.success :global(svg) {
		color: #16a34a;
		background: rgba(22, 163, 74, 0.1);
	}

	.synvya-container .status-icon.error :global(svg) {
		color: #dc2626;
		background: rgba(220, 38, 38, 0.08);
	}

	.synvya-container .status-icon.loading :global(svg) {
		color: hsl(222.2 84% 4.9%);
		background: rgba(15, 23, 42, 0.04);
	}

	@media (prefers-color-scheme: dark) {
		.synvya-container .status-icon :global(svg) {
			background: rgba(255, 255, 255, 0.06);
		}

		.synvya-container .status-icon.success :global(svg) {
			background: rgba(22, 163, 74, 0.15);
		}

		.synvya-container .status-icon.error :global(svg) {
			background: rgba(220, 38, 38, 0.12);
		}

		.synvya-container .status-icon.loading :global(svg) {
			color: hsl(210 40% 98%);
			background: rgba(255, 255, 255, 0.06);
		}
	}

	.synvya-container .status-icon :global(.synvya-spin) {
		animation: spin 1s linear infinite;
	}

	.redirect-notice {
		color: var(--color-divine-text-tertiary);
		font-size: 0.85rem;
		margin-bottom: 1.25rem;
	}

	.processing-notice {
		color: var(--color-divine-text-tertiary);
		font-size: 0.85rem;
		margin-bottom: 1.25rem;
	}

	.actions {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.btn-primary {
		display: block;
		padding: 0.75rem 1.5rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 9999px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		text-decoration: none;
		transition: all 0.2s;
	}

	.synvya-container .btn-primary {
		background: hsl(142.1 76.2% 36.3%);
		border-radius: 0.375rem;
	}

	.btn-primary:hover {
		background: var(--color-divine-green-dark);
		box-shadow: 0 2px 8px rgba(39, 197, 139, 0.16);
	}

	.synvya-container .btn-primary:hover {
		background: hsl(142.1 76.2% 30%);
	}

	.btn-secondary {
		display: block;
		padding: 0.75rem 1.5rem;
		background: transparent;
		color: var(--color-divine-text-secondary);
		border: 1px solid var(--color-divine-border);
		border-radius: 9999px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		text-decoration: none;
		transition: all 0.2s;
	}

	.synvya-container .btn-secondary {
		background: transparent;
		border-color: hsl(214.3 31.8% 91.4%);
		border-radius: 0.375rem;
		color: hsl(222.2 84% 4.9%);
	}

	.btn-secondary:hover {
		background: var(--color-divine-muted);
		color: var(--color-divine-text);
	}

	.synvya-container .btn-secondary:hover {
		background: hsl(210 40% 96.1%);
		border-color: hsl(214.3 31.8% 83%);
	}

	@media (prefers-color-scheme: dark) {
		.synvya-container .btn-secondary {
			border-color: rgba(255, 255, 255, 0.12);
			color: hsl(210 40% 98%);
		}

		.synvya-container .btn-secondary:hover {
			background: rgba(255, 255, 255, 0.06);
			border-color: rgba(255, 255, 255, 0.2);
		}
	}
</style>
