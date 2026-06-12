// Clipboard helper with a graceful fallback for non-secure contexts.
//
// `navigator.clipboard.writeText()` is only exposed in a secure context
// — HTTPS, or `localhost` / `127.0.0.1` over plain HTTP. Local dev under
// a custom hostname like `keycast.local.synvya.com` is plain HTTP from a
// non-localhost host, so the browser denies the modern API (either the
// property is undefined or the call rejects with NotAllowedError). The
// helper tries the modern API first and falls back to the legacy
// `document.execCommand('copy')` path via a temporary textarea so copy
// keeps working on those origins.
//
// Used by every clipboard interaction in the web app — dashboards,
// admin tools, the export-key flow, copy components — so the fallback
// applies uniformly.

export async function copyToClipboard(text: string): Promise<void> {
	if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
		try {
			await navigator.clipboard.writeText(text);
			return;
		} catch {
			// Some browsers expose the API but still reject on insecure
			// origins. Fall through to the legacy path.
		}
	}

	if (typeof document === 'undefined') {
		throw new Error('Clipboard unavailable: no document context');
	}

	// `document.execCommand('copy')` is deprecated but remains the only
	// path that works in non-secure contexts. It requires a selection
	// from a visible, focusable element — `display:none` / `hidden`
	// suppress selection in some browsers, so park the textarea
	// off-screen instead.
	const textarea = document.createElement('textarea');
	textarea.value = text;
	textarea.setAttribute('readonly', '');
	textarea.style.position = 'fixed';
	textarea.style.top = '-1000px';
	textarea.style.left = '-1000px';
	textarea.style.opacity = '0';
	document.body.appendChild(textarea);
	try {
		textarea.focus();
		textarea.select();
		const ok = document.execCommand('copy');
		if (!ok) {
			throw new Error('document.execCommand("copy") returned false');
		}
	} finally {
		document.body.removeChild(textarea);
	}
}
