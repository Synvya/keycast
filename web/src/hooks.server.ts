import type { Handle } from "@sveltejs/kit";
import { redirect } from "@sveltejs/kit";

const protectedRoutes: string[] = ["/teams", "/keys", "/admin", "/support-admin"];

export const handle: Handle = async ({ event, resolve }) => {
    const sessionCookie = event.cookies.get("keycastUserPubkey");
    if (!sessionCookie && protectedRoutes.includes(event.url.pathname)) {
        throw redirect(303, "/");
    }

    return resolve(event);
};
