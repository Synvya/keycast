import { nip19 } from "nostr-tools";

let currentUser: CurrentUser | null = $state(null);

class CurrentUser {
    pubkey: string;
    npub: string;
    authMethod: 'nip07' | 'cookie' | null = $state(null);

    constructor(pubkey: string, authMethod: 'nip07' | 'cookie' | null = null) {
        this.pubkey = pubkey;
        this.npub = nip19.npubEncode(pubkey);
        this.authMethod = authMethod;
    }
}

export function getCurrentUser(): CurrentUser | null {
    return currentUser;
}

export function setCurrentUser(
    pubkey: string | null,
    authMethod: 'nip07' | 'cookie' | null = null
): CurrentUser | null {
    if (pubkey) {
        currentUser = new CurrentUser(pubkey, authMethod);
        if (typeof window !== 'undefined') {
            if (authMethod) {
                localStorage.setItem('keycast_auth_method', authMethod);
            }
            document.cookie = `keycastUserPubkey=${pubkey}; max-age=1209600; SameSite=Lax; Secure; path=/`;
        }
    } else {
        currentUser = null;
        if (typeof window !== 'undefined') {
            localStorage.removeItem('keycast_auth_method');
            document.cookie = "keycastUserPubkey=; max-age=0; path=/; SameSite=Lax; Secure";
        }
    }
    return currentUser;
}
