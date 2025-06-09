import { createAlert } from "./notify.js";

function normalizeApiUrl(endpoint) {
    if (!endpoint || typeof endpoint !== "string") {
        createAlert("API Error", "Invalid endpoint provided", "error");
        return null;
    }

    const cleanEndpoint = endpoint.replace(/^\/+/, "").replace(/^api\//, "");
    const baseUrl = (import.meta.env.VITE_URL || "").replace(/\/$/, "");

    return `${baseUrl}/api/${cleanEndpoint}`;
}

export async function authedAPIRequest(endpoint, options) {
    if (options === undefined) {
        options = {};
    }

    if (!endpoint) {
        console.error("[AUTH] Endpoint is required for API request");
        createAlert(
            "API Error",
            "Endpoint is required for API request",
            "error",
        );
        return null;
    }

    const url = normalizeApiUrl(endpoint);

    if (!url) {
        console.error("[AUTH] URL invalide pour la requête", endpoint);
        createAlert("API Error", "Invalid URL format", "error");
        return null;
    }

    const token = localStorage.getItem("token");

    if (!token) {
        const refreshToken = localStorage.getItem("refresh_token");

        if (refreshToken) {
            console.log("[AUTH] Token absent, tentative de rafraîchissement");
            const refreshed = await tryRefreshToken(refreshToken);

            if (refreshed) {
                console.log(
                    "[AUTH] Rafraîchissement réussi, réessai de la requête",
                );
                return authedAPIRequest(endpoint, options);
            }
        }

        console.log("[AUTH] Aucun token valide, redirection vers login");
        redirectToLogin();
        return null;
    }

    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                ...(options.headers || {}),
                Authorization: `Bearer ${token}`,
            },
        });

        if (response.status === 401) {
            const refreshToken = localStorage.getItem("refresh_token");
            const errorText = await response.text();

            console.warn("[AUTH] Erreur 401 reçue:", errorText);

            const isExpired = errorText.includes("expired");

            if (refreshToken && isExpired) {
                console.log("[AUTH] Token expiré, tentative de refresh");
                const refreshed = await tryRefreshToken(refreshToken);

                if (refreshed) {
                    console.log(
                        "[AUTH] Rafraîchissement réussi, nouvelle tentative",
                    );
                    return authedAPIRequest(endpoint, options);
                }
            }

            console.warn("[AUTH] Redirection vers login après 401");
            redirectToLogin();
            return null;
        }

        return response;
    } catch (error) {
        console.error("[AUTH] API request error:", error);
        createAlert("API Error", "Failed to make API request", "error");
        return null;
    }
}

export function redirectToLogin() {
    if (window.location.pathname === "/complete/epita/") {
        console.warn("[AUTH] Déjà sur /complete/epita/, on ne redirige pas.");
        return;
    }

    try {
        localStorage.clear();
    } catch (error) {
        console.error("Error clearing localStorage:", error);
    }

    const redirectUri = `${window.location.origin}/complete/epita/`;

    const params = new URLSearchParams({
        client_id: import.meta.env.VITE_CLIENT_ID,
        response_type: "code",
        redirect_uri: redirectUri,
        scope: "epita profile picture",
    });

    window.location.href = `${import.meta.env.VITE_AUTH_URL}/authorize?${params}`;
}

export async function tryRefreshToken(refreshToken) {
    if (!refreshToken) {
        console.error("[AUTH] No refresh token provided");
        createAlert(
            "Authentication Error",
            "No refresh token provided",
            "error",
        );
        return false;
    }

    try {
        createAlert("Refresh token", "Refreshing token", "warn");

        const form = new URLSearchParams();

        form.set("grant_type", "refresh_token");
        form.set("refresh_token", refreshToken);
        form.set("client_id", import.meta.env.VITE_CLIENT_ID);

        if (window.location.hostname !== "localhost") {
            form.set("redirect_uri", import.meta.env.VITE_REDIRECT_URI);
        }

        const tokenEndpoint =
            window.location.hostname === "localhost"
                ? "/auth-api/token"
                : import.meta.env.VITE_TOKEN_ENDPOINT;

        const response = await fetch(tokenEndpoint, {
            method: "POST",
            body: form,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        });

        if (response.ok) {
            const data = await response.json();

            if (!data.id_token || !data.refresh_token) {
                console.error("[AUTH] Données de token invalides");
                createAlert(
                    "Authentication Error",
                    "Invalid token data received",
                    "error",
                );
                return false;
            }

            localStorage.setItem("token", data.id_token);
            localStorage.setItem("refresh_token", data.refresh_token);
            return true;
        }

        const errorText = await response.text();

        console.error("Token refresh failed:", errorText);
        createAlert("Authentication Error", "Failed to refresh token", "error");

        if (import.meta.env.MODE !== "test") {
            redirectToLogin();
        }

        return false;
    } catch (error) {
        console.error("Error refreshing token:", error);
        createAlert("Authentication Error", "Failed to refresh token", "error");
        return false;
    }
}
