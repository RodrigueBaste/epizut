// src/rooms/canvas/index.js
// actual
// FIXME: This file should handle the room canvas API
// Link buttons to their respective functions
// Functions may include:
// - getCanvas (get the canvas of a room and deserialize it)
// - subscribeToRoom (subscribe to the stream of a room)
// - getPixelInfo (get the pixel info of a room)
// - placePixel (place a pixel in a room)

import { v4 as uuidv4 } from "uuid";
import {
    getCanvasContext,
    getPalette,
    getBoard,
    transformHexTo32Bits,
} from "./utils.js";
import { initSocket } from "../../utils/streams";
import { createAlert } from "../../utils/notify";

const pendingUpdates = new Map();
let canvasSize = null;
let isProcessingUpdates = false;

export function subscribeToRoom(socket, roomSlug) {
    if (!socket?.connected) {
        console.error("[ERROR] Cannot subscribe: socket not connected");
        return Promise.reject(new Error("Socket not connected"));
    }

    if (!roomSlug || typeof roomSlug !== "string") {
        console.error("[ERROR] Invalid room slug:", roomSlug);
        return Promise.reject(new Error("Invalid room slug"));
    }

    console.debug(`[DEBUG] Subscribing to room: ${roomSlug}`);

    window.canvasReady = false;
    listenToPixelUpdates(socket);

    return new Promise((resolve) => {
        const handleSubscription = async () => {
            const subscriptionId = uuidv4();

            let activeSocket = socket;

            if (!activeSocket || !activeSocket.connected) {
                activeSocket = await initSocket();

                if (!activeSocket) {
                    createAlert(
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
                    path: "rooms.canvas.getStream",
                    input: { json: { roomSlug } },
                },
            });

            const timeout = setTimeout(() => {
                console.error("[ERROR] Subscription timeout");
                socket.off("message", messageHandler);
                resolve(false);
            }, 10000);

            const messageHandler = (message) => {
                console.debug("[SOCKET DEBUG] message received:", message);

                if (
                    message?.id === subscriptionId &&
                    (message?.result?.type === "started" ||
                        message?.result === "started")
                ) {
                    clearTimeout(timeout);
                    socket.off("message", messageHandler);
                    console.debug("[DEBUG] Subscription stream started");

                    window.canvasReady = true;

                    if (!canvasSize) {
                        console.warn(
                            "[WARN] canvasSize is not set at subscription start. Pending updates may be lost.",
                        );
                    }

                    setTimeout(() => processPendingUpdates(), 0);
                    resolve(true);
                }
            };

            socket.on("message", messageHandler);
        };

        handleSubscription();
    });
}

export function setCanvasSize(size) {
    if (
        !size ||
        typeof size.width !== "number" ||
        typeof size.height !== "number" ||
        size.width <= 0 ||
        size.height <= 0 ||
        !Number.isInteger(size.width) ||
        !Number.isInteger(size.height)
    ) {
        console.error("[ERROR] Invalid canvas size:", size);
        return;
    }

    canvasSize = size;
    console.debug("Canvas size set to:", canvasSize);

    if (pendingUpdates.size > 0) {
        processPendingUpdates();
    }
}

function listenToPixelUpdates(socket) {
    socket.off("pixel-update");

    socket.on("pixel-update", (message) => {
        try {
            console.debug(
                "[DEBUG] Received pixel update: date",
                new Date().toISOString(),
                message,
            );
            const update =
                message?.result?.data?.json ||
                message?.result?.data ||
                message?.data?.json ||
                message?.data;

            if (!update) {
                console.warn("[WARN] Invalid update format:", message);
                return;
            }

            const { posX, posY, color } = update;

            if (
                posX === undefined ||
                posY === undefined ||
                color === undefined
            ) {
                console.warn(
                    "[WARN] Missing coordinates or color in update:",
                    update,
                );
                return;
            }

            const key = `${posX},${posY}`;

            pendingUpdates.set(key, { posX, posY, color });

            if (window.canvasReady && !isProcessingUpdates) {
                setTimeout(() => processPendingUpdates(), 0);
            }
        } catch (err) {
            console.error("[ERROR] Failed to process pixel update:", err);
        }
    });
}

function processPendingUpdates() {
    if (isProcessingUpdates || !window.canvasReady || !canvasSize) {
        return;
    }

    const canvasCtx = getCanvasContext();

    if (!canvasCtx) {
        console.error("[ERROR] Canvas context not ready");
        return;
    }

    isProcessingUpdates = true;

    try {
        const updates = Array.from(pendingUpdates.values());

        if (updates.length === 0) {
            isProcessingUpdates = false;
            return;
        }

        console.debug(
            `[DEBUG] Processing ${updates.length} pending updates date :` +
                new Date().toISOString(),
        );

        const img = new ImageData(canvasSize.width, canvasSize.height);
        const data = new Uint32Array(img.data.buffer);

        const currentImgData = canvasCtx.getImageData(
            0,
            0,
            canvasSize.width,
            canvasSize.height,
        );
        const currentData = new Uint32Array(currentImgData.data.buffer);

        data.set(currentData);

        const validUpdates = [];

        for (const { posX, posY, color } of updates) {
            if (
                posX >= 0 &&
                posY >= 0 &&
                posX < canvasSize.width &&
                posY < canvasSize.height
            ) {
                validUpdates.push({ posX, posY, color });
                const index = posY * canvasSize.width + posX;
                const palette = getPalette();

                if (palette && palette[color]) {
                    data[index] = transformHexTo32Bits(palette[color]);
                }
            }
        }

        canvasCtx.putImageData(img, 0, 0);

        // On met a jour le tableau de pixels du tableau
        const board = getBoard();

        if (board) {
            for (const { posX, posY, color } of validUpdates) {
                const index = posY * canvasSize.width + posX;

                board[index] = color;
            }
        }

        // Maintenant, on vide les mises à jour en attente
        pendingUpdates.clear();

        console.debug("[DEBUG] All pending updates processed successfully");
    } catch (error) {
        console.error("[ERROR] Failed to process updates:", error);
    } finally {
        isProcessingUpdates = false;

        if (pendingUpdates.size > 0) {
            setTimeout(() => processPendingUpdates(), 0);
        }
    }
}

export function flushPendingUpdates() {
    processPendingUpdates();
}

export function decodeCanvas(encoded, canvasSize) {
    if (!encoded) {
        console.warn("[WARN] decodeCanvas: encoded data is null or undefined");
        return [];
    }

    if (
        !canvasSize ||
        typeof canvasSize.width !== "number" ||
        typeof canvasSize.height !== "number" ||
        canvasSize.width <= 0 ||
        canvasSize.height <= 0
    ) {
        console.warn("[WARN] decodeCanvas: invalid canvas size", canvasSize);
        return [];
    }

    try {
        const bytes = Uint8Array.from(encoded, (c) => c.charCodeAt(0));
        const totalPixels = canvasSize.width * canvasSize.height;
        const output = new Uint8Array(totalPixels);
        let bitBuffer = 0n;
        let bitsInBuffer = 0n;
        let byteIndex = 0;
        let pixelIndex = 0;

        while (pixelIndex < totalPixels) {
            while (bitsInBuffer < 5n && byteIndex < bytes.length) {
                bitBuffer = (bitBuffer << 8n) | BigInt(bytes[byteIndex++]);
                bitsInBuffer += 8n;
            }

            if (bitsInBuffer < 5n) {
                break;
            }

            bitsInBuffer -= 5n;
            output[pixelIndex++] = Number((bitBuffer >> bitsInBuffer) & 0x1fn);
        }

        return output;
    } catch (error) {
        console.error("[ERROR] Failed to decode canvas:", error);
        return [];
    }
}

export function addTestDelay(ms = 1000) {
    if (!import.meta.env.DEV) {
        return Promise.resolve();
    }

    console.debug(`[TEST] Adding ${ms}ms delay for testing purposes`);
    return new Promise((resolve) => setTimeout(resolve, ms));
}
