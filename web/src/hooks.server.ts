import type { Handle } from "@sveltejs/kit";
import { redirect } from "@sveltejs/kit";

const protectedRoutes: string[] = ["/teams", "/keys", "/admin", "/support-admin"];

export const handle: Handle = async ({ event, resolve }) => {
    const hasSession = event.cookies.get("keycast_session") || event.cookies.get("keycastUserPubkey");
    if (!hasSession && protectedRoutes.includes(event.url.pathname)) {
        throw redirect(303, "/");
    }

    return resolve(event);
};
