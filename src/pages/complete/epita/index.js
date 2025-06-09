// src/pages/complete/epita/index.js

import { createAlert } from "../../../utils/notify.js";
import { redirectToLogin } from "../../../utils/auth.js";

const AUTH_CONFIG = {
    redirectUri: `${window.location.origin}/complete/epita/`,
    clientId: import.meta.env.VITE_CLIENT_ID,
    tokenEndpoint:
        window.location.hostname === "localhost"
            ? "/auth-api/token"
            : import.meta.env.VITE_TOKEN_ENDPOINT,
};

function getAuthCode() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const error = params.get("error");

    if (error) {
        console.error("[AUTH] Error from Forge:", error);
        createAlert("Authentication Error", error, "error");
        redirectToLogin();
        return null;
    }

    if (!code) {
        createAlert(
            "Authentication Error",
            "Missing authorization code",
            "error",
        );
        redirectToLogin();
        return null;
    }

    return code;
}

async function exchangeCodeForTokens(code) {
    try {
        const form = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: AUTH_CONFIG.redirectUri,
            client_id: AUTH_CONFIG.clientId,
        });

        const response = await fetch(AUTH_CONFIG.tokenEndpoint, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form,
        });

        if (!response.ok) {
            const errorText = await response.text();

            console.error("[AUTH] Token exchange failed:", errorText);
            createAlert(
                "Authentication Error",
                "Token exchange failed",
                "error",
            );
            redirectToLogin();
            return null;
        }

        const data = await response.json();

        if (!data.id_token || !data.refresh_token) {
            console.error("[AUTH] Invalid token data:", data);
            createAlert("Authentication Error", "Invalid token data", "error");
            redirectToLogin();
            return null;
        }

        return data;
    } catch (err) {
        console.error("[AUTH] Token exchange error:", err);
        createAlert("Authentication Error", "Failed to exchange code", "error");
        redirectToLogin();
        return null;
    }
}

function saveTokens({ id_token, refresh_token }) {
    try {
        localStorage.setItem("token", id_token);
        localStorage.setItem("refresh_token", refresh_token);
        return true;
    } catch (err) {
        console.error("[AUTH] Failed to save tokens:", err);
        createAlert("Authentication Error", "Failed to save tokens", "error");
        redirectToLogin();
        return false;
    }
}

(async function completeAuthentication() {
    const code = getAuthCode();

    if (!code) {
        return;
    }

    const tokens = await exchangeCodeForTokens(code);

    if (!tokens) {
        return;
    }

    const saved = saveTokens(tokens);

    if (!saved) {
        return;
    }

    createAlert("Success", "Successfully authenticated", "success");

    setTimeout(() => {
        window.location.href = "/";
    }, 100);
})();
