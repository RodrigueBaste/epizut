// src/pages/index.js

import { calculateLayout } from "./utils.js";
import "./debug";
import { getRoomSlug } from "../rooms/index.js";
import {
    decodeCanvas,
    setCanvasSize,
    subscribeToRoom,
} from "../rooms/canvas/index.js";
import { initCanvas } from "../rooms/canvas/utils.js";
import { initSocket } from "../utils/streams.js";
import { createAlert } from "../utils/notify.js";
import { redirectToLogin } from "../utils/auth.js";
import { requestWithRetry } from "../utils/request.js";

calculateLayout();

function normalizeCanvasDimensions(rawDimensions) {
    if (typeof rawDimensions === "number") {
        return { width: rawDimensions, height: rawDimensions };
    }

    if (
        typeof rawDimensions === "object" &&
        typeof rawDimensions.width === "number" &&
        typeof rawDimensions.height === "number"
    ) {
        return rawDimensions;
    }

    throw new Error(
        `Invalid canvasDimensions: ${JSON.stringify(rawDimensions)}`,
    );
}

window.addEventListener("DOMContentLoaded", main);

async function main() {
    try {
        const token = localStorage.getItem("token");
        const refresh = localStorage.getItem("refresh_token");

        if (!token && !refresh) {
            console.log("[AUTH] No tokens found, redirecting to login");
            const redirectUri = `${window.location.origin}/complete/epita/`;
            const params = new URLSearchParams({
                client_id: import.meta.env.VITE_CLIENT_ID,
                response_type: "code",
                redirect_uri: redirectUri,
                scope: "epita profile picture",
            });

            window.location.href = `${import.meta.env.VITE_AUTH_URL}/authorize?${params}`;
            return;
        }

        const roomSlug = getRoomSlug();
        const socket = await initSocket();

        createAlert("Socket", "Initialising WebSocket.", "success");

        if (!socket) {
            createAlert(
                "Erreur API",
                `Socket not initialized. No Auth.`,
                "warning",
            );
            redirectToLogin();
            return;
        }

        // On récupère la liste des rooms
        const rooms = await requestWithRetry("/api/rooms");

        if (!rooms || !Array.isArray(rooms)) {
            createAlert("Error", "Failed to fetch available rooms", "error");
            redirectToLogin();
            return;
        }

        // On vérifie si la room existe et est accessible
        const room = rooms.find((r) => r.slug === roomSlug);

        if (!room) {
            createAlert(
                "Access Denied",
                "This room does not exist or you don't have permission to access it",
                "error",
            );
            redirectToLogin();
            return;
        }

        // On s'abonne à la room
        await subscribeToRoom(socket, roomSlug);
        createAlert(
            "Subscribe Room:",
            `Subscribing to room ${roomSlug}`,
            "success",
        );

        // On récupère la configuration de la room
        const configuration = await requestWithRetry(
            `/api/rooms/${roomSlug}/config`,
        );

        if (!configuration) {
            createAlert("Error", "Failed to fetch room configuration", "error");
            redirectToLogin();
            return;
        }

        const meta = configuration.metadata || {};

        if (!meta.canvasDimensions) {
            createAlert(
                "Error",
                "Canvas dimensions not found in configuration",
                "error",
            );
            redirectToLogin();
            return;
        }

        // On normalise les dimensions du canvas
        const normalizedDimensions = normalizeCanvasDimensions(
            meta.canvasDimensions,
        );

        console.debug(
            "[DEBUG] Normalized canvas dimensions:",
            normalizedDimensions,
        );

        // On récupère le canvas encodé
        const encodedCanvas = await fetchEncodedCanvas(roomSlug);

        if (!encodedCanvas) {
            console.error("[ERROR] Failed to fetch encoded canvas");
            createAlert("Error", "Failed to fetch canvas data", "error");
            return;
        }

        // On décode le canvas
        const decodedCanvas = decodeCanvas(encodedCanvas, normalizedDimensions);

        if (!decodedCanvas || decodedCanvas.length === 0) {
            console.error("[ERROR] Failed to decode canvas");
            createAlert("Error", "Failed to decode canvas data", "error");
            return;
        }

        // On initialise le canvas avec les données décodées
        initCanvas(configuration, decodedCanvas, normalizedDimensions);
        setCanvasSize(normalizedDimensions);

        updateRoomName(meta.name);
        updateRoomDescription(meta.description);
    } catch (error) {
        console.error("uncaught error in main:", error);
        createAlert(
            "Erreur",
            error.message || "Une erreur est survenue",
            "error",
        );
        redirectToLogin();
    }
}

function updateRoomName(name) {
    const nameElement = document.getElementById("room-name");

    if (nameElement && name) {
        console.log(`[DEBUG] Updating room name to : ${name}`);
        nameElement.textContent = name;
    }
}

function updateRoomDescription(description) {
    const descriptionElement = document.getElementById("room-description");
    const cleanDescription = description?.trim();

    if (descriptionElement) {
        console.log(
            `[DEBUG] Updating room description to : ${cleanDescription}`,
        );
        descriptionElement.textContent = cleanDescription || "";
        descriptionElement.style.display = cleanDescription ? "block" : "none";
    }
}

async function fetchEncodedCanvas(roomSlug) {
    const url = `/api/rooms/${roomSlug}/canvas`;
    const response = await requestWithRetry(url);

    return response?.pixels ?? null;
}

// import { authedAPIRequest } from "../utils/auth";

// window.testTokenRefresh = async function () {
//     localStorage.setItem("token", "expired");
//     localStorage.setItem("refresh_token", "valid-test-refresh-token");

//     const res = await authedAPIRequest("tests/expired-token", {
//         method: "POST",
//         headers: {
//             "Content-Type": "application/json",
//             Accept: "application/json",
//         },
//         body: JSON.stringify({}),
//     });

//     if (!res) {
//         console.warn(" La requête a échoué ou a été redirigée");
//         return;
//     }

//     if (res.ok) {
//         const data = await res.json();

//         console.log(" Requête relancée avec nouveau token :", data);
//     } else {
//         const text = await res.text();

//         console.warn(` Statut : ${res.status} - Réponse : ${text}`);
//     }
// };
