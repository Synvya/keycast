<script lang="ts">
	import { onMount } from 'svelte';
	import { BRAND } from '$lib/brand';
	import { KeycastApi } from '$lib/keycast_api.svelte';
	import { goto } from '$app/navigation';
	import { getLoginUrl } from '$lib/utils/env';
	import Loader from '$lib/components/Loader.svelte';
	import { ShieldCheck, Warning, MagnifyingGlass, User, Key, Calendar, Globe, Copy, Check, CheckCircle, XCircle, Link, CaretDown, CaretRight, Storefront, UsersThree, Plug } from 'phosphor-svelte';
	import { nip19 } from 'nostr-tools';
	import { toast } from 'svelte-hot-french-toast';

	const api = new KeycastApi();
	const isSynvyaManaged = getLoginUrl() !== '/login';
	const brandName = isSynvyaManaged ? 'Synvya' : BRAND.name;

	let status = $state<'loading' | 'not-admin' | 'ready'>('loading');
	let adminRole = $state<string | null>(null);

	// User lookup state
	let searchQuery = $state('');
	let isSearching = $state(false);
	let searchResult = $state<null | { results: UserDetails[]; total: number }>(null);
	let searchError = $state('');

	// Expand/collapse state
	let expandedPubkey = $state<string | null>(null);

	// Pubkey display state
	let pubkeyFormat = $state<'hex' | 'npub'>('npub');
	let copiedPubkey = $state(false);

	// Claim link state
	let claimToken = $state<{ claim_url: string; expires_at: string } | null>(null);
	let isLoadingClaimToken = $state(false);
	let isGeneratingClaimToken = $state(false);
	let copiedClaimUrl = $state(false);

	// Teams / restaurants / authorizations state (lazy-loaded per expand)
	let userTeams = $state<TeamDetails[] | null>(null);
	let isLoadingTeams = $state(false);
	let teamsError = $state('');

	interface AdminAuthorization {
		id: number;
		label: string | null;
		bunker_public_key: string;
		relays: string[];
		connected_client_pubkey: string | null;
		connected_at: string | null;
		expires_at: string | null;
		created_at: string;
		updated_at: string;
	}

	interface RestaurantKey {
		id: number;
		name: string;
		pubkey: string;
		created_at: string;
		authorizations: AdminAuthorization[];
	}

	interface TeamDetails {
		id: number;
		name: string;
		role: string;
		joined_at: string;
		restaurant_keys: RestaurantKey[];
	}

	interface UserDetails {
		pubkey: string;
		email: string | null;
		email_verified: boolean | null;
		username: string | null;
		display_name: string | null;
		vine_id: string | null;
		has_personal_key: boolean;
		active_sessions: number;
		created_at: string;
		last_active: string | null;
	}

	onMount(async () => {
		try {
			const response = await api.get<{ is_admin: boolean; role: string | null }>('/admin/status');
			if (!response.is_admin) {
				status = 'not-admin';
				return;
			}
			adminRole = response.role;
		} catch {
			goto('/login?redirect=/support-admin', { replaceState: true });
			return;
		}

		status = 'ready';
	});

	async function searchUser() {
		const q = searchQuery.trim();
		if (!q) return;

		isSearching = true;
		searchError = '';
		searchResult = null;
		expandedPubkey = null;

		try {
			const result = await api.get<{ results: UserDetails[]; total: number }>(
				`/admin/user-lookup?q=${encodeURIComponent(q)}`
			);
			searchResult = result;
			// Auto-expand if single result
			if (result.results.length === 1) {
				expandedPubkey = result.results[0].pubkey;
			}
		} catch (err: any) {
			searchError = err.message || 'Search failed';
		} finally {
			isSearching = false;
		}
	}

	function formatDate(iso: string): string {
		return new Date(iso).toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	}

	function formatPubkey(hexPubkey: string): string {
		if (pubkeyFormat === 'npub') {
			try {
				return nip19.npubEncode(hexPubkey);
			} catch {
				return hexPubkey;
			}
		}
		return hexPubkey;
	}

	function truncateFormatted(hexPubkey: string): string {
		const formatted = formatPubkey(hexPubkey);
		if (formatted.length <= 20) return formatted;
		return formatted.slice(0, 12) + '...' + formatted.slice(-8);
	}

	async function copyPubkey(hexPubkey: string) {
		try {
			await navigator.clipboard.writeText(formatPubkey(hexPubkey));
			copiedPubkey = true;
			toast.success(`${pubkeyFormat === 'npub' ? 'npub' : 'Hex pubkey'} copied!`);
			setTimeout(() => (copiedPubkey = false), 2000);
		} catch {
			toast.error('Failed to copy');
		}
	}

	async function loadClaimToken(pubkey: string) {
		isLoadingClaimToken = true;
		claimToken = null;
		try {
			const result = await api.get<{ has_token: boolean; claim_url?: string; expires_at?: string }>(
				`/admin/claim-tokens?pubkey=${encodeURIComponent(pubkey)}`
			);
			if (result.has_token && result.claim_url && result.expires_at) {
				claimToken = { claim_url: result.claim_url, expires_at: result.expires_at };
			}
		} catch {
			// Silently ignore - user may not have claim token access
		} finally {
			isLoadingClaimToken = false;
		}
	}

	async function generateClaimToken(vineId: string) {
		isGeneratingClaimToken = true;
		try {
			const result = await api.post<{ claim_url: string; expires_at: string }>(
				'/admin/claim-tokens',
				{ vine_id: vineId }
			);
			claimToken = result;
			toast.success('Claim link generated');
		} catch (err: any) {
			toast.error(err.message || 'Failed to generate claim link');
		} finally {
			isGeneratingClaimToken = false;
		}
	}

	async function copyClaimUrl() {
		if (!claimToken) return;
		try {
			await navigator.clipboard.writeText(claimToken.claim_url);
			copiedClaimUrl = true;
			toast.success('Claim URL copied!');
			setTimeout(() => (copiedClaimUrl = false), 2000);
		} catch {
			toast.error('Failed to copy');
		}
	}

	function toggleExpand(pubkey: string) {
		expandedPubkey = expandedPubkey === pubkey ? null : pubkey;
	}

	async function loadUserTeams(pubkey: string) {
		isLoadingTeams = true;
		teamsError = '';
		userTeams = null;
		try {
			const result = await api.get<{ teams: TeamDetails[] }>(
				`/admin/user-teams?pubkey=${encodeURIComponent(pubkey)}`
			);
			userTeams = result.teams;
		} catch (err: any) {
			teamsError = err.message || 'Failed to load teams';
		} finally {
			isLoadingTeams = false;
		}
	}

	function formatAuthLabel(a: AdminAuthorization): string {
		return a.label && a.label.trim() ? a.label : `Authorization #${a.id}`;
	}

	function isSynvyaServerAuth(label: string | null): boolean {
		return !!label && /synvya\s+server/i.test(label);
	}

	function isSynvyaClientAuth(label: string | null): boolean {
		return !!label && /synvya\s+client/i.test(label);
	}

	$effect(() => {
		if (expandedPubkey && searchResult) {
			const user = searchResult.results.find(u => u.pubkey === expandedPubkey);
			if (user?.vine_id && !user?.email) {
				loadClaimToken(user.pubkey);
			} else {
				claimToken = null;
			}
			loadUserTeams(expandedPubkey);
		} else {
			claimToken = null;
			userTeams = null;
			teamsError = '';
		}
	});
</script>

<svelte:head>
	<title>Support Admin - {brandName}</title>
</svelte:head>

<div class:support-page={true} class:synvya-admin={isSynvyaManaged}>
	{#if isSynvyaManaged}
		<div class="synvya-brand">
			<img src="/synvya-logo.png" alt="Synvya" class="synvya-brand-logo" />
			<span class="synvya-brand-sub">Support Admin</span>
		</div>
	{/if}
	{#if status === 'loading'}
		<div class="status-card">
			<Loader />
			<p class="status-text">Checking admin status...</p>
		</div>
	{:else if status === 'not-admin'}
		<div class="status-card error">
			<Warning size={32} weight="fill" />
			<h2>Access Denied</h2>
			<p>Your account does not have support admin privileges.</p>
		</div>
	{:else if status === 'ready'}
		<div class="admin-header">
			<div class="admin-identity">
				<ShieldCheck size={20} weight="fill" />
				<span class="admin-label">Support Admin</span>
				<span class="admin-badge">{adminRole === 'full' ? 'Full Admin' : 'Support'}</span>
			</div>
		</div>

		<div class="tools-section">
			<h2>User Lookup</h2>
			<form class="search-form" onsubmit={(e) => { e.preventDefault(); searchUser(); }}>
				<div class="search-input-wrap">
					<MagnifyingGlass size={18} />
					<input
						type="text"
						bind:value={searchQuery}
						placeholder="Search for a user..."
						class="search-input"
						disabled={isSearching}
					/>
				</div>
				<button type="submit" class="btn-search" disabled={isSearching || !searchQuery.trim()}>
					{isSearching ? 'Searching...' : 'Search'}
				</button>
			</form>
			<p class="search-hint">Search by email, Vine username, vine_id, hex pubkey, or npub</p>

			{#if searchError}
				<div class="search-error">
					<Warning size={16} />
					<span>{searchError}</span>
				</div>
			{/if}

			{#if searchResult}
				{#if searchResult.results.length === 0}
					<div class="no-result">
						<p>No user found matching that query.</p>
					</div>
				{:else}
					{#if searchResult.total >= 20}
						<div class="results-banner warning">
							<Warning size={14} />
							<span>Showing first 20 of many results — refine your search</span>
						</div>
					{:else if searchResult.total > 1}
						<div class="results-banner">
							<span>{searchResult.total} users found</span>
						</div>
					{/if}

					<div class="user-list">
						{#each searchResult.results as u (u.pubkey)}
							{@const isExpanded = expandedPubkey === u.pubkey}
							<div class="user-list-item" class:expanded={isExpanded}>
								<button class="user-list-row" onclick={() => toggleExpand(u.pubkey)}>
									<span class="expand-icon">
										{#if isExpanded}
											<CaretDown size={14} weight="bold" />
										{:else}
											<CaretRight size={14} weight="bold" />
										{/if}
									</span>
									<User size={16} weight="fill" />
									<span class="list-name">{u.display_name || u.username || u.email || truncateFormatted(u.pubkey)}</span>
									{#if u.username}
										<span class="list-username">@{u.username}</span>
									{/if}
									<span class="list-sessions">{u.active_sessions} {u.active_sessions === 1 ? 'session' : 'sessions'}</span>
								</button>

								{#if isExpanded}
									<div class="user-card">
										<div class="status-strip">
											<div class="status-item" class:status-ok={u.email_verified} class:status-warn={u.email && !u.email_verified} class:status-none={!u.email}>
												{#if u.email_verified}
													<CheckCircle size={14} weight="fill" />
													<span>Email verified</span>
												{:else if u.email}
													<XCircle size={14} weight="fill" />
													<span>Email unverified</span>
												{:else}
													<span class="status-neutral">No email</span>
												{/if}
											</div>
											<div class="status-item" class:status-ok={u.active_sessions > 0} class:status-none={u.active_sessions === 0}>
												<span>{u.active_sessions} active {u.active_sessions === 1 ? 'session' : 'sessions'}</span>
											</div>
										</div>

										<div class="user-fields">
											<div class="field">
												<span class="field-label"><Key size={14} /> Pubkey</span>
												<span class="field-value mono">
													<span title={formatPubkey(u.pubkey)}>{truncateFormatted(u.pubkey)}</span>
													<button class="icon-btn" onclick={() => copyPubkey(u.pubkey)} title="Copy pubkey">
														{#if copiedPubkey}
															<Check size={14} />
														{:else}
															<Copy size={14} />
														{/if}
													</button>
													<button
														class="format-toggle"
														onclick={() => pubkeyFormat = pubkeyFormat === 'hex' ? 'npub' : 'hex'}
														title="Switch between npub and hex format"
													>
														{pubkeyFormat === 'hex' ? 'npub' : 'hex'}
													</button>
												</span>
											</div>

											{#if u.email}
												<div class="field">
													<span class="field-label">Email</span>
													<span class="field-value">{u.email}</span>
												</div>
											{/if}

											{#if u.username}
												<div class="field">
													<span class="field-label"><User size={14} /> Username</span>
													<span class="field-value">{u.username}</span>
												</div>
											{/if}

											{#if u.vine_id}
												<div class="field">
													<span class="field-label"><Globe size={14} /> Vine ID</span>
													<span class="field-value">{u.vine_id}</span>
												</div>
											{/if}

											<div class="field">
												<span class="field-label"><Calendar size={14} /> Created</span>
												<span class="field-value">{formatDate(u.created_at)}</span>
											</div>

											<div class="field">
												<span class="field-label"><Calendar size={14} /> Last active</span>
												<span class="field-value">{u.last_active ? formatDate(u.last_active) : 'Never'}</span>
											</div>
										</div>

										{#if u.vine_id && !u.email}
											<div class="claim-section">
												<div class="claim-header">
													<Link size={16} />
													<span class="claim-title">Claim Link</span>
												</div>
												{#if isLoadingClaimToken}
													<p class="claim-loading">Checking for existing claim link...</p>
												{:else if claimToken}
													<div class="claim-url-display">
														<div class="claim-url-row">
															<input
																type="text"
																value={claimToken.claim_url}
																readonly
																class="claim-url-input"
															/>
															<button class="icon-btn" onclick={copyClaimUrl} title="Copy claim URL">
																{#if copiedClaimUrl}
																	<Check size={14} />
																{:else}
																	<Copy size={14} />
																{/if}
															</button>
														</div>
														<span class="claim-expiry">
															Expires {formatDate(claimToken.expires_at)}
														</span>
													</div>
												{:else}
													<button
														class="btn-generate-claim"
														onclick={() => generateClaimToken(u.vine_id!)}
														disabled={isGeneratingClaimToken}
													>
														{isGeneratingClaimToken ? 'Generating...' : 'Generate Claim Link'}
													</button>
												{/if}
											</div>
										{/if}

										{#if isSynvyaManaged}
											<div class="teams-section">
												<div class="section-header">
													<UsersThree size={16} />
													<span class="section-title">Teams & Restaurants</span>
												</div>

												{#if isLoadingTeams}
													<p class="muted-text">Loading teams…</p>
												{:else if teamsError}
													<div class="inline-error"><Warning size={14} /><span>{teamsError}</span></div>
												{:else if userTeams && userTeams.length === 0}
													<p class="muted-text">This user is not a member of any team.</p>
												{:else if userTeams}
													<div class="teams-list">
														{#each userTeams as team (team.id)}
															<div class="team-card">
																<div class="team-header">
																	<div class="team-header-main">
																		<Storefront size={16} weight="fill" />
																		<span class="team-name">{team.name}</span>
																	</div>
																	<div class="team-header-meta">
																		<span class="pill pill-role">{team.role}</span>
																		<span class="team-joined">joined {formatDate(team.joined_at)}</span>
																	</div>
																</div>

																{#if team.restaurant_keys.length === 0}
																	<p class="muted-text indent">No restaurant keys in this team.</p>
																{:else}
																	{#each team.restaurant_keys as key (key.id)}
																		<div class="restaurant-block">
																			<div class="restaurant-row">
																				<span class="restaurant-label">Restaurant</span>
																				<span class="restaurant-name">{key.name}</span>
																			</div>
																			<div class="restaurant-row">
																				<span class="restaurant-label"><Key size={12} /> Pubkey</span>
																				<span class="field-value mono">
																					<span title={formatPubkey(key.pubkey)}>{truncateFormatted(key.pubkey)}</span>
																					<button class="icon-btn" onclick={() => copyPubkey(key.pubkey)} title="Copy restaurant pubkey">
																						<Copy size={12} />
																					</button>
																				</span>
																			</div>

																			<div class="auth-header">
																				<Plug size={14} />
																				<span>Authorizations</span>
																				<span class="auth-scope-hint">shared across the team</span>
																			</div>

																			{#if key.authorizations.length === 0}
																				<p class="muted-text indent">No authorizations on this key.</p>
																			{:else}
																				<div class="auth-list">
																					{#each key.authorizations as a (a.id)}
																						{@const serverAuth = isSynvyaServerAuth(a.label)}
																						{@const clientAuth = isSynvyaClientAuth(a.label)}
																						<div class="auth-card" class:auth-server={serverAuth} class:auth-client={clientAuth}>
																							<div class="auth-card-header">
																								<span class="auth-label">{formatAuthLabel(a)}</span>
																								{#if serverAuth}
																									<span class="pill pill-server">24/7</span>
																								{:else if clientAuth}
																									<span class="pill pill-client">interactive</span>
																								{/if}
																							</div>
																							<div class="auth-meta">
																								<div class="auth-meta-row">
																									<span class="auth-meta-label">Bunker</span>
																									<span class="mono auth-meta-value" title={a.bunker_public_key}>{truncateFormatted(a.bunker_public_key)}</span>
																								</div>
																								<div class="auth-meta-row">
																									<span class="auth-meta-label">Created</span>
																									<span class="auth-meta-value">{formatDate(a.created_at)}</span>
																								</div>
																								<div class="auth-meta-row">
																									<span class="auth-meta-label">Connected</span>
																									<span class="auth-meta-value">{a.connected_at ? formatDate(a.connected_at) : '—'}</span>
																								</div>
																								<div class="auth-meta-row">
																									<span class="auth-meta-label">Expires</span>
																									<span class="auth-meta-value">{a.expires_at ? formatDate(a.expires_at) : 'Never'}</span>
																								</div>
																								<div class="auth-meta-row">
																									<span class="auth-meta-label">Relays</span>
																									<span class="auth-meta-value relays">{a.relays.length === 0 ? '—' : a.relays.join(', ')}</span>
																								</div>
																							</div>
																						</div>
																					{/each}
																				</div>
																			{/if}
																		</div>
																	{/each}
																{/if}
															</div>
														{/each}
													</div>
												{/if}
											</div>
										{/if}
									</div>
								{/if}
							</div>
						{/each}
					</div>
				{/if}
			{/if}
		</div>

		{#if adminRole === 'full'}
			<div class="tools-section">
				<h2>Quick Links</h2>
				<div class="links-grid">
					<a href="/admin" class="link-card">
						<span class="link-title">Full Admin Dashboard</span>
						<span class="link-desc">API tokens, preloaded accounts, claim links</span>
					</a>
				</div>
			</div>
		{/if}
	{/if}
</div>

<style>
	.support-page {
		max-width: 560px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}

	.status-card {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 2.5rem 1.5rem;
		text-align: center;
	}

	.status-card.error {
		border-color: color-mix(in srgb, var(--color-divine-error) 40%, var(--color-divine-border));
		color: var(--color-divine-error);
	}

	.status-card h2 {
		color: var(--color-divine-text);
		font-size: 1.25rem;
		font-weight: 600;
		margin: 1rem 0 0.5rem;
	}

	.status-card p {
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		margin: 0 0 0.5rem;
		line-height: 1.5;
	}

	.status-text {
		color: var(--color-divine-text-secondary);
		margin-top: 1rem;
		font-size: 0.9rem;
	}

	.admin-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 1rem 1.25rem;
		margin-bottom: 1.5rem;
	}

	.admin-identity {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--color-divine-green);
	}

	.admin-label {
		color: var(--color-divine-text);
		font-size: 0.9rem;
		font-weight: 500;
	}

	.admin-badge {
		font-size: 0.7rem;
		font-weight: 500;
		padding: 0.125rem 0.5rem;
		border-radius: 9999px;
		background: color-mix(in srgb, var(--color-divine-purple, #8b5cf6) 20%, transparent);
		color: var(--color-divine-purple, #8b5cf6);
	}

	.tools-section {
		margin-bottom: 1.5rem;
	}

	.tools-section h2 {
		font-size: 1rem;
		font-weight: 600;
		color: var(--color-divine-text);
		margin: 0 0 0.75rem;
	}

	/* Search form */
	.search-form {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.search-input-wrap {
		flex: 1;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0 0.75rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 8px;
		color: var(--color-divine-text-secondary);
		transition: border-color 0.2s;
	}

	.search-input-wrap:focus-within {
		border-color: var(--color-divine-green);
	}

	.search-input {
		flex: 1;
		padding: 0.625rem 0;
		background: transparent;
		border: none;
		outline: none;
		color: var(--color-divine-text);
		font-size: 0.875rem;
	}

	.search-input::placeholder {
		color: var(--color-divine-text-tertiary);
	}

	.search-hint {
		font-size: 0.725rem;
		color: var(--color-divine-text-tertiary);
		margin: -0.5rem 0 1rem 0.25rem;
	}

	.results-banner {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.5rem 0.75rem;
		margin-bottom: 0.5rem;
		border-radius: 8px;
		font-size: 0.8rem;
		font-weight: 500;
		color: var(--color-divine-text-secondary);
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
	}

	.results-banner.warning {
		color: var(--color-divine-warning);
		background: color-mix(in srgb, var(--color-divine-warning) 10%, var(--color-divine-bg));
		border-color: color-mix(in srgb, var(--color-divine-warning) 30%, transparent);
	}

	.btn-search {
		padding: 0.625rem 1.25rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 8px;
		font-size: 0.85rem;
		font-weight: 600;
		cursor: pointer;
		transition: opacity 0.2s;
		white-space: nowrap;
	}

	.btn-search:hover:not(:disabled) {
		opacity: 0.9;
	}

	.btn-search:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.search-error {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.75rem 1rem;
		background: color-mix(in srgb, var(--color-divine-error) 10%, var(--color-divine-bg));
		border: 1px solid color-mix(in srgb, var(--color-divine-error) 30%, transparent);
		border-radius: 8px;
		color: var(--color-divine-error);
		font-size: 0.85rem;
		margin-bottom: 1rem;
	}

	.no-result {
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		padding: 1.5rem;
		text-align: center;
	}

	.no-result p {
		color: var(--color-divine-text-secondary);
		font-size: 0.9rem;
		margin: 0;
	}

	/* User list */
	.user-list {
		display: flex;
		flex-direction: column;
		gap: 0;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		overflow: hidden;
	}

	.user-list-item {
		border-bottom: 1px solid var(--color-divine-border);
	}

	.user-list-item:last-child {
		border-bottom: none;
	}

	.user-list-item.expanded {
		background: var(--color-divine-muted);
	}

	.user-list-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.75rem 1rem;
		background: transparent;
		border: none;
		cursor: pointer;
		text-align: left;
		color: var(--color-divine-text);
		font-size: 0.85rem;
		transition: background 0.15s;
	}

	.user-list-row:hover {
		background: var(--color-divine-muted);
	}

	.expand-icon {
		color: var(--color-divine-text-tertiary);
		flex-shrink: 0;
		display: flex;
		align-items: center;
	}

	.list-name {
		font-weight: 500;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		min-width: 0;
	}

	.list-username {
		color: var(--color-divine-text-tertiary);
		font-size: 0.775rem;
		flex-shrink: 0;
	}

	.list-sessions {
		margin-left: auto;
		color: var(--color-divine-text-tertiary);
		font-size: 0.725rem;
		white-space: nowrap;
		flex-shrink: 0;
	}

	/* User card (expanded detail) */
	.user-card {
		border-top: 1px solid var(--color-divine-border);
	}

	.status-strip {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem 1rem;
		padding: 0.75rem 1.25rem;
		border-bottom: 1px solid var(--color-divine-border);
		background: var(--color-divine-muted);
	}

	.status-item {
		display: flex;
		align-items: center;
		gap: 0.25rem;
		font-size: 0.75rem;
		font-weight: 500;
	}

	.status-item + .status-item {
		padding-left: 1rem;
		border-left: 1px solid var(--color-divine-border);
	}

	.status-item.status-ok {
		color: var(--color-divine-green);
	}

	.status-item.status-warn {
		color: var(--color-divine-warning);
	}

	.status-item.status-none {
		color: var(--color-divine-text-tertiary);
	}

	.status-neutral {
		color: var(--color-divine-text-tertiary);
	}

	.user-fields {
		padding: 0.5rem 0;
	}

	.field {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		padding: 0.625rem 1.25rem;
		gap: 1rem;
	}

	.field:hover {
		background: color-mix(in srgb, var(--color-divine-muted) 50%, transparent);
	}

	.field-label {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		color: var(--color-divine-text-secondary);
		font-size: 0.825rem;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.field-value {
		color: var(--color-divine-text);
		font-size: 0.85rem;
		text-align: right;
		word-break: break-all;
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
		justify-content: flex-end;
	}

	.field-value.mono {
		font-family: var(--font-mono);
		font-size: 0.75rem;
	}

	.icon-btn {
		background: transparent;
		border: none;
		color: var(--color-divine-text-tertiary);
		cursor: pointer;
		padding: 0.25rem;
		border-radius: 4px;
		transition: all 0.2s;
		flex-shrink: 0;
	}

	.icon-btn:hover {
		color: var(--color-divine-green);
		background: var(--color-divine-muted);
	}

	.format-toggle {
		font-size: 0.65rem;
		padding: 0.125rem 0.375rem;
		background: var(--color-divine-muted);
		border: 1px solid var(--color-divine-border);
		border-radius: 4px;
		color: var(--color-divine-text-tertiary);
		cursor: pointer;
		transition: all 0.2s;
		text-transform: lowercase;
		flex-shrink: 0;
	}

	.format-toggle:hover {
		background: color-mix(in srgb, var(--color-divine-green) 15%, transparent);
		color: var(--color-divine-green);
	}

	/* Claim link section */
	.claim-section {
		padding: 0.75rem 1.25rem;
		border-top: 1px solid var(--color-divine-border);
		background: color-mix(in srgb, var(--color-divine-green) 5%, var(--color-divine-surface));
	}

	.claim-header {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		color: var(--color-divine-green);
		margin-bottom: 0.5rem;
	}

	.claim-title {
		font-size: 0.825rem;
		font-weight: 600;
		color: var(--color-divine-text);
	}

	.claim-loading {
		font-size: 0.8rem;
		color: var(--color-divine-text-tertiary);
		margin: 0;
	}

	.claim-url-display {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
	}

	.claim-url-row {
		display: flex;
		gap: 0.375rem;
		align-items: center;
	}

	.claim-url-input {
		flex: 1;
		padding: 0.5rem 0.625rem;
		background: var(--color-divine-bg);
		border: 1px solid var(--color-divine-border);
		border-radius: 6px;
		color: var(--color-divine-text);
		font-family: var(--font-mono);
		font-size: 0.725rem;
		outline: none;
	}

	.claim-expiry {
		font-size: 0.725rem;
		color: var(--color-divine-text-tertiary);
	}

	.btn-generate-claim {
		padding: 0.5rem 1rem;
		background: var(--color-divine-green);
		color: #fff;
		border: none;
		border-radius: 6px;
		font-size: 0.825rem;
		font-weight: 600;
		cursor: pointer;
		transition: opacity 0.2s;
	}

	.btn-generate-claim:hover:not(:disabled) {
		opacity: 0.9;
	}

	.btn-generate-claim:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.links-grid {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.link-card {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		padding: 1rem 1.25rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 12px;
		text-decoration: none;
		transition: all 0.2s;
	}

	.link-card:hover {
		border-color: var(--color-divine-green);
		background: var(--color-divine-muted);
	}

	.link-title {
		color: var(--color-divine-text);
		font-weight: 500;
		font-size: 0.9rem;
	}

	.link-desc {
		color: var(--color-divine-text-tertiary);
		font-size: 0.8rem;
	}

	/* =========================================================
	   Teams & Authorizations (shared markup, inherits dark theme)
	   ========================================================= */
	.teams-section {
		padding: 0.875rem 1.25rem 1rem;
		border-top: 1px solid var(--color-divine-border);
	}

	.section-header {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		color: var(--color-divine-text);
		margin-bottom: 0.625rem;
	}

	.section-title {
		font-size: 0.825rem;
		font-weight: 600;
	}

	.muted-text {
		font-size: 0.8rem;
		color: var(--color-divine-text-tertiary);
		margin: 0.25rem 0;
	}

	.muted-text.indent {
		padding-left: 0.5rem;
	}

	.inline-error {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		font-size: 0.8rem;
		color: var(--color-divine-error);
	}

	.teams-list {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
	}

	.team-card {
		background: var(--color-divine-bg);
		border: 1px solid var(--color-divine-border);
		border-radius: 10px;
		padding: 0.75rem 0.875rem;
	}

	.team-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
		margin-bottom: 0.5rem;
	}

	.team-header-main {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		color: var(--color-divine-green);
	}

	.team-name {
		color: var(--color-divine-text);
		font-weight: 600;
		font-size: 0.9rem;
	}

	.team-header-meta {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.team-joined {
		font-size: 0.7rem;
		color: var(--color-divine-text-tertiary);
	}

	.pill {
		display: inline-flex;
		align-items: center;
		padding: 0.1rem 0.5rem;
		font-size: 0.65rem;
		font-weight: 600;
		border-radius: 9999px;
		text-transform: uppercase;
		letter-spacing: 0.03em;
	}

	.pill-role {
		background: color-mix(in srgb, var(--color-divine-purple, #8b5cf6) 18%, transparent);
		color: var(--color-divine-purple, #8b5cf6);
	}

	.pill-server {
		background: color-mix(in srgb, var(--color-divine-green) 20%, transparent);
		color: var(--color-divine-green);
	}

	.pill-client {
		background: color-mix(in srgb, #3b82f6 20%, transparent);
		color: #3b82f6;
	}

	.restaurant-block {
		margin-top: 0.5rem;
		padding: 0.625rem 0.75rem;
		background: var(--color-divine-surface);
		border: 1px solid var(--color-divine-border);
		border-radius: 8px;
	}

	.restaurant-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 0.75rem;
		padding: 0.2rem 0;
		font-size: 0.8rem;
	}

	.restaurant-label {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		color: var(--color-divine-text-secondary);
	}

	.restaurant-name {
		color: var(--color-divine-text);
		font-weight: 500;
	}

	.auth-header {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		margin-top: 0.625rem;
		margin-bottom: 0.375rem;
		font-size: 0.75rem;
		font-weight: 600;
		color: var(--color-divine-text-secondary);
	}

	.auth-scope-hint {
		margin-left: auto;
		font-weight: 400;
		font-size: 0.7rem;
		color: var(--color-divine-text-tertiary);
		font-style: italic;
	}

	.auth-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.auth-card {
		border: 1px solid var(--color-divine-border);
		border-radius: 8px;
		padding: 0.5rem 0.625rem;
		background: var(--color-divine-bg);
	}

	.auth-card.auth-server {
		border-left: 3px solid var(--color-divine-green);
	}

	.auth-card.auth-client {
		border-left: 3px solid #3b82f6;
	}

	.auth-card-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 0.5rem;
		margin-bottom: 0.375rem;
	}

	.auth-label {
		font-size: 0.825rem;
		font-weight: 600;
		color: var(--color-divine-text);
	}

	.auth-meta {
		display: grid;
		grid-template-columns: auto 1fr;
		column-gap: 0.75rem;
		row-gap: 0.2rem;
	}

	.auth-meta-row {
		display: contents;
	}

	.auth-meta-label {
		font-size: 0.7rem;
		color: var(--color-divine-text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.03em;
	}

	.auth-meta-value {
		font-size: 0.75rem;
		color: var(--color-divine-text);
		word-break: break-all;
	}

	.auth-meta-value.relays {
		font-family: var(--font-mono);
		font-size: 0.7rem;
		color: var(--color-divine-text-secondary);
	}

	/* =========================================================
	   Synvya light admin variant (overrides when .synvya-admin)
	   ========================================================= */
	.support-page.synvya-admin {
		max-width: 720px;
		padding: 2rem 1.5rem 3rem;
		background: transparent;
	}

	:global(body:has(.support-page.synvya-admin)) {
		background: #f7f9f8;
	}

	.synvya-brand {
		display: flex;
		align-items: baseline;
		gap: 0.5rem;
		margin-bottom: 1.5rem;
	}

	.synvya-brand-logo {
		height: 26px;
	}

	.synvya-brand-sub {
		font-size: 0.85rem;
		color: #5a6b6a;
		font-weight: 500;
	}

	/* Card surfaces → white with subtle border */
	.support-page.synvya-admin .admin-header,
	.support-page.synvya-admin .status-card,
	.support-page.synvya-admin .no-result,
	.support-page.synvya-admin .user-list,
	.support-page.synvya-admin .link-card,
	.support-page.synvya-admin .results-banner,
	.support-page.synvya-admin .search-input-wrap {
		background: #ffffff;
		border-color: #e2e8e6;
		color: #1f2937;
	}

	.support-page.synvya-admin .tools-section h2,
	.support-page.synvya-admin .admin-label,
	.support-page.synvya-admin .list-name,
	.support-page.synvya-admin .field-value,
	.support-page.synvya-admin .team-name,
	.support-page.synvya-admin .restaurant-name,
	.support-page.synvya-admin .auth-label,
	.support-page.synvya-admin .section-title,
	.support-page.synvya-admin .link-title,
	.support-page.synvya-admin .claim-title,
	.support-page.synvya-admin .auth-meta-value {
		color: #0f1f1c;
	}

	.support-page.synvya-admin .field-label,
	.support-page.synvya-admin .restaurant-label,
	.support-page.synvya-admin .auth-header {
		color: #4b5e5a;
	}

	.support-page.synvya-admin .search-hint,
	.support-page.synvya-admin .list-username,
	.support-page.synvya-admin .list-sessions,
	.support-page.synvya-admin .team-joined,
	.support-page.synvya-admin .auth-meta-label,
	.support-page.synvya-admin .auth-scope-hint,
	.support-page.synvya-admin .muted-text,
	.support-page.synvya-admin .link-desc,
	.support-page.synvya-admin .status-text,
	.support-page.synvya-admin .status-neutral,
	.support-page.synvya-admin .auth-meta-value.relays {
		color: #7a8a86;
	}

	.support-page.synvya-admin .search-input {
		color: #0f1f1c;
	}

	.support-page.synvya-admin .search-input::placeholder {
		color: #9ba8a4;
	}

	.support-page.synvya-admin .user-list-item {
		border-bottom-color: #e9efed;
	}

	.support-page.synvya-admin .user-list-item.expanded {
		background: #f4f9f7;
	}

	.support-page.synvya-admin .user-list-row:hover {
		background: #eff5f3;
	}

	.support-page.synvya-admin .user-card,
	.support-page.synvya-admin .status-strip,
	.support-page.synvya-admin .teams-section,
	.support-page.synvya-admin .claim-section {
		border-top-color: #e9efed;
	}

	.support-page.synvya-admin .status-strip {
		background: #f4f9f7;
	}

	.support-page.synvya-admin .team-card,
	.support-page.synvya-admin .auth-card {
		background: #ffffff;
		border-color: #e2e8e6;
	}

	.support-page.synvya-admin .restaurant-block {
		background: #f7fbf9;
		border-color: #dbe7e3;
	}

	.support-page.synvya-admin .claim-section {
		background: #f1faf5;
	}

	.support-page.synvya-admin .claim-url-input {
		background: #ffffff;
		border-color: #dbe7e3;
		color: #0f1f1c;
	}

	.support-page.synvya-admin .format-toggle {
		background: #eef4f1;
		border-color: #dbe7e3;
		color: #4b5e5a;
	}

	.support-page.synvya-admin .icon-btn {
		color: #7a8a86;
	}
	.support-page.synvya-admin .icon-btn:hover {
		color: var(--color-divine-green);
		background: #eef4f1;
	}
</style>
