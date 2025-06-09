// src/utils/streams.js

import { io } from "socket.io-client";
import { v4 as generateUUID } from "uuid";

const isTestEnv = import.meta.env?.MODE === "test";

async function alertWrapper(...args) {
    if (!isTestEnv) {
        const { createAlert } = await import("./notify.js");

        createAlert(...args);
    }
}

function loginRedirectWrapper() {
    if (!isTestEnv) {
        import("./auth.js").then(({ redirectToLogin }) => redirectToLogin());
    }
}

let socket = null;
let isInitializing = false;
let connectionPromise = null;
const activeSubscriptions = new Map();

export async function initSocket() {
    if (socket?.connected) {
        console.debug("[DEBUG] Socket already connected, reusing");
        return Promise.resolve(socket);
    }

    if (isInitializing && connectionPromise) {
        console.debug("[DEBUG] Socket initialization in progress, waiting");
        return connectionPromise;
    }

    if (socket) {
        console.debug("[DEBUG] Disconnecting existing socket");
        socket.disconnect();
        socket = null;
    }

    isInitializing = true;
    const isTest = import.meta.env.MODE === "test";
    const token = localStorage.getItem("token");

    connectionPromise = new Promise((resolve) => {
        if (!token || typeof token !== "string" || token.trim() === "") {
            console.error("[ERROR] Invalid token format");
            if (!isTest) {
                alertWrapper(
                    "API ERROR",
                    "Invalid token format, redirecting to login.",
                    "warning",
                );
                loginRedirectWrapper();
            }

            isInitializing = false;
            connectionPromise = null;
            resolve(null);
            return;
        }

        const socketUrl = import.meta.env.VITE_URL || "http://localhost:8080";

        console.debug(`[DEBUG] Connecting to socket at: ${socketUrl}`);

        socket = io(socketUrl, {
            auth: { token: `Bearer ${token}` },
            query: { token: `Bearer ${token}` },
            transportOptions: {
                polling: {
                    extraHeaders: {
                        Authorization: `Bearer ${token}`,
                    },
                },
            },
            transports: ["websocket"],
            reconnection: true,
            reconnectionAttempts: 5,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            timeout: isTest ? 2000 : 3000,
            forceNew: true,
            autoConnect: true,
            path: "/socket.io",
        });

        socket.on("error", (err) => {
            console.error("[SOCKET] Global error:", err);
            if (!isTest) {
                alertWrapper(
                    "Socket Error",
                    "An unexpected socket error occurred",
                    "error",
                );
            }
        });

        const connectionTimeout = setTimeout(
            () => {
                console.error("[ERROR] Socket connection timeout");
                if (!isTest) {
                    alertWrapper(
                        "Connection Error",
                        "Failed to connect to server.",
                        "error",
                    );
                }

                socket?.disconnect();
                socket = null;
                isInitializing = false;
                connectionPromise = null;
                resolve(null);
            },
            isTest ? 2000 : 1500,
        );

        socket.on("connect", () => {
            clearTimeout(connectionTimeout);
            console.debug("[DEBUG] Socket connected successfully");

            if (!isTest) {
                alertWrapper("Socket", "Connected to server.", "success");
            }

            isInitializing = false;
            connectionPromise = null;
            resolve(socket);
        });

        socket.on("connect_error", async (error) => {
            clearTimeout(connectionTimeout);
            console.error("[ERROR] Socket connection error:", error);

            const expired = error?.message?.includes("Token expired");

            if (expired) {
                const refreshToken = localStorage.getItem("refresh_token");

                if (refreshToken) {
                    const { tryRefreshToken } = await import("./auth.js");
                    const refreshed = await tryRefreshToken(refreshToken);

                    if (refreshed) {
                        socket.auth = {
                            token: `Bearer ${localStorage.getItem("token")}`,
                        };
                        socket.connect();
                        return;
                    }
                }
            }

            if (!isTest) {
                alertWrapper(
                    "Authentication Error",
                    expired
                        ? "Token expired, redirecting to login."
                        : "Failed to connect to server.",
                    "error",
                );
                if (expired) {
                    loginRedirectWrapper();
                }
            }

            socket?.disconnect();
            socket = null;
            isInitializing = false;
            connectionPromise = null;
            resolve(null);
        });

        socket.on("reconnect", (attemptNumber) => {
            console.debug(
                `[DEBUG] Socket reconnected after ${attemptNumber} attempts`,
            );
            if (!isTest) {
                alertWrapper("Socket", "Reconnected to server.", "success");
            }

            resubscribeToActiveRooms();
        });

        socket.on("reconnect_failed", () => {
            console.error(
                "[ERROR] Socket failed to reconnect after all attempts",
            );
            if (!isTest) {
                alertWrapper(
                    "Connection Error",
                    "Failed to reconnect to server after multiple attempts. Please refresh the page.",
                    "error",
                );
            }
        });

        if (socket.connected) {
            clearTimeout(connectionTimeout);
            console.debug("[DEBUG] Socket already connected");
            if (!isTest) {
                alertWrapper("Socket", "Connected to server.", "success");
            }

            isInitializing = false;
            connectionPromise = null;
            resolve(socket);
        }
    });

    return connectionPromise;
}

export function subscribe(roomId, type = "stream") {
    return new Promise((resolve, reject) => {
        (async () => {
            if (!socket?.connected) {
                console.error("[ERROR] Cannot subscribe: socket not connected");
                return reject(new Error("Socket not connected"));
            }

            if (!roomId || typeof roomId !== "string") {
                console.error("[ERROR] Invalid room ID:", roomId);
                return reject(new Error("Invalid room ID"));
            }

            const channel =
                type === "chat"
                    ? "rooms.chat.getStream"
                    : "rooms.canvas.getStream";
            const subscriptionId = generateUUID();

            console.debug(
                `[DEBUG] Sending subscription request to ${roomId} (${type})`,
            );

            let activeSocket = socket;

            if (!activeSocket || !activeSocket.connected) {
                activeSocket = await initSocket();

                if (!activeSocket) {
                    alertWrapper(
                        "Socket",
                        "Connection not available. Please try again.",
                        "error",
                    );
                    return;
                }
            }

            activeSocket.emit("message", {
                id: subscriptionId,
                method: "subscription",
                params: {
                    path: channel,
                    input: { json: { roomSlug: roomId } },
                },
            });

            const timeoutId = setTimeout(() => {
                console.error(
                    `[ERROR] Subscription timeout for room: ${roomId}`,
                );
                socket.off("message", handler);
                resolve(false);
            }, 10000);

            const handler = (message) => {
                if (message?.id !== subscriptionId) {
                    return;
                }

                if (
                    message?.result?.type === "started" ||
                    message?.result === "started"
                ) {
                    clearTimeout(timeoutId);
                    socket.off("message", handler);
                    activeSubscriptions.set(roomId, { type, time: Date.now() });
                    console.debug(
                        `[DEBUG] Successfully subscribed to room: ${roomId}`,
                    );
                    resolve(true);
                } else if (message?.error) {
                    clearTimeout(timeoutId);
                    socket.off("message", handler);
                    console.error(
                        `[ERROR] Failed subscription to ${roomId}:`,
                        message.error,
                    );
                    resolve(false);
                }
            };

            socket.on("message", handler);
        })();
    });
}

export function isSubscribedToRoom(roomId) {
    return activeSubscriptions.has(roomId);
}

export function resubscribeToActiveRooms() {
    if (!socket?.connected) {
        console.error("[ERROR] Cannot resubscribe: socket not connected");
        return Promise.resolve(false);
    }

    if (activeSubscriptions.size === 0) {
        console.debug("[DEBUG] No active subscriptions to resubscribe");
        return Promise.resolve(true);
    }

    console.debug(`[DEBUG] Resubscribing to ${activeSubscriptions.size} rooms`);

    const resubscribePromises = [];

    activeSubscriptions.forEach((subscription, roomId) => {
        console.debug(
            `[DEBUG] Resubscribing to room ${roomId} (${subscription.type})`,
        );
        resubscribePromises.push(subscribe(roomId, subscription.type));
    });

    return Promise.all(resubscribePromises)
        .then((results) => {
            const allSucceeded = results.every((result) => result === true);

            console.debug(
                `[DEBUG] Resubscription ${allSucceeded ? "succeeded" : "failed"}`,
            );
            return allSucceeded;
        })
        .catch((error) => {
            console.error("[ERROR] Error during resubscription:", error);
            return false;
        });
}

export function onPixelUpdate(callback) {
    if (!socket) {
        return;
    }

    socket.off("pixel-update");
    socket.on("pixel-update", callback);
}

export { socket };
