// src/utils/request.js
import { createAlert } from "./notify.js";
import { authedAPIRequest } from "./auth.js";

export async function request(url, options = {}) {
    try {
        const response = await authedAPIRequest(url, options);

        if (!response) {
            console.error(
                `[REQUEST] authedAPIRequest returned null for ${url}`,
            );
            return null;
        }

        if (!response.ok) {
            const errorText = await response.text();

            createAlert(
                "Erreur API",
                `(${response.status}) ${errorText}`,
                "error",
            );
            return { status: response.status, error: errorText };
        }

        return await response.json();
    } catch (error) {
        console.error(`[REQUEST] Erreur réseau pour ${url}`, error);
        createAlert(
            "Erreur réseau",
            "Impossible de joindre le serveur.",
            "error",
        );
        return null;
    }
}

export async function requestWithRetry(
    url,
    options = {},
    maxRetries = 3,
    baseDelay = 1000,
) {
    let lastError = null;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const result = await request(url, options);

            if (result !== null) {
                return result;
            }
        } catch (error) {
            lastError = error;
            console.warn(
                `[REQUEST] Attempt ${attempt + 1}/${maxRetries} failed for ${url}`,
            );

            if (attempt < maxRetries - 1) {
                const delay = baseDelay * Math.pow(2, attempt);

                console.debug(`[REQUEST] Waiting ${delay}ms before retry...`);
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }

    console.error(
        `[REQUEST] All ${maxRetries} attempts failed for ${url}`,
        lastError,
    );
    return null;
}
