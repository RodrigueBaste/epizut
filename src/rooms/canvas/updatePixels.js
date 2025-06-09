// src/rooms/canvas/updatePixels.js

import {
    getBoard,
    getPalette,
    getCanvasContext,
    transformHexTo32Bits,
} from "./utils.js";
import { extractPixelData } from "../../utils/pixelUpdates.js";
import { onPixelUpdate } from "../../utils/streams.js";

const CONFIG = {
    UPDATE_BATCH_DELAY: 0,
    MAX_UPDATES_PER_BATCH: 1000,
    USE_REQUEST_ANIMATION_FRAME: true,
    DEBUG_LEVEL: 3,
};

let canvasSize = null;
let canvasReady = false;
let isProcessingUpdates = false;
let animationFrameRequested = false;

const pendingUpdates = new Map();

function log(level, message, ...args) {
    const levels = ["NONE", "ERROR", "WARN", "INFO", "DEBUG"];

    if (level <= CONFIG.DEBUG_LEVEL) {
        console[
            level === 1
                ? "error"
                : level === 2
                  ? "warn"
                  : level === 3
                    ? "info"
                    : "debug"
        ](`[${levels[level]}] ${message}`, ...args);
    }
}

export function initCanvasUpdater(size) {
    if (!size || !size.width || !size.height) {
        log(1, "Invalid canvas size:", size);
        return false;
    }

    canvasSize = size;
    canvasReady = true;
    log(3, "Canvas updater initialized with size:", size);
    if (pendingUpdates.size > 0) {
        log(
            3,
            `Processing ${pendingUpdates.size} pending updates after initialization`,
        );
        processBatchUpdates();
    }

    return true;
}

export function setupPixelUpdateHandler() {
    try {
        onPixelUpdate(handlePixelUpdate);
        log(3, "Pixel update handler set up successfully");
        return true;
    } catch (error) {
        log(1, "Failed to set up pixel update handler:", error);
        return false;
    }
}

function handlePixelUpdate(update) {
    if (!update) {
        log(2, "Received empty update");
        return;
    }

    const pixelData = extractPixelData(update);

    if (!pixelData) {
        log(4, "Could not extract valid pixel data from update:", update);
        return;
    }

    const { posX, posY, color } = pixelData;

    if (canvasSize) {
        if (
            posX < 0 ||
            posX >= canvasSize.width ||
            posY < 0 ||
            posY >= canvasSize.height
        ) {
            log(2, "Pixel update out of bounds:", { posX, posY, color });
            return;
        }
    }

    const updateKey = `${posX},${posY}`;

    pendingUpdates.set(updateKey, pixelData);

    if (canvasReady && canvasSize) {
        scheduleUpdateProcessing();
    } else {
        log(4, "Canvas not ready, queuing update:", pixelData);
    }
}

function scheduleUpdateProcessing() {
    if (isProcessingUpdates || animationFrameRequested) {
        return;
    }

    if (CONFIG.USE_REQUEST_ANIMATION_FRAME) {
        animationFrameRequested = true;
        requestAnimationFrame(() => {
            animationFrameRequested = false;
            processBatchUpdates();
        });
    } else {
        setTimeout(processBatchUpdates, CONFIG.UPDATE_BATCH_DELAY);
    }
}

export function processBatchUpdates() {
    if (isProcessingUpdates || !canvasReady || !canvasSize) {
        return false;
    }

    isProcessingUpdates = true;
    try {
        const updates = Array.from(pendingUpdates.values());

        pendingUpdates.clear();
        if (updates.length === 0) {
            isProcessingUpdates = false;
            return true;
        }

        log(
            3,
            `Processing ${updates.length} pixel updates at ${new Date().toISOString()}`,
        );
        const canvasCtx = getCanvasContext();
        const board = getBoard();
        const palette = getPalette();

        if (!canvasCtx || !board || !palette) {
            log(1, "Required components not available");
            return false;
        }

        const imgData = canvasCtx.getImageData(
            0,
            0,
            canvasSize.width,
            canvasSize.height,
        );
        const data = new Uint32Array(imgData.data.buffer);
        let hasChanges = false;
        const batchSize = Math.min(
            updates.length,
            CONFIG.MAX_UPDATES_PER_BATCH,
        );

        for (let i = 0; i < batchSize; i++) {
            const { posX, posY, color } = updates[i];

            if (
                typeof posX !== "number" ||
                typeof posY !== "number" ||
                typeof color !== "number" ||
                posX < 0 ||
                posX >= canvasSize.width ||
                posY < 0 ||
                posY >= canvasSize.height ||
                color < 0 ||
                color >= palette.length
            ) {
                log(2, "Skipping invalid pixel update:", { posX, posY, color });
                continue;
            }

            const index = posY * canvasSize.width + posX;

            board[index] = color;
            data[index] = transformHexTo32Bits(palette[color]);
            hasChanges = true;
        }

        if (hasChanges) {
            canvasCtx.putImageData(imgData, 0, 0);
            log(4, `Successfully updated ${batchSize} pixels on the canvas`);
        }

        if (updates.length > CONFIG.MAX_UPDATES_PER_BATCH) {
            log(
                3,
                `Requeuing ${updates.length - CONFIG.MAX_UPDATES_PER_BATCH} updates for next batch`,
            );
            for (
                let i = CONFIG.MAX_UPDATES_PER_BATCH;
                i < updates.length;
                i++
            ) {
                const { posX, posY } = updates[i];
                const updateKey = `${posX},${posY}`;

                pendingUpdates.set(updateKey, updates[i]);
            }
        }

        return true;
    } catch (error) {
        log(1, "Failed to process pixel updates:", error);
        return false;
    } finally {
        isProcessingUpdates = false;
        if (pendingUpdates.size > 0) {
            scheduleUpdateProcessing();
        }
    }
}

export function setCanvasReady(ready) {
    canvasReady = ready;
    if (ready && pendingUpdates.size > 0) {
        processBatchUpdates();
    }
}

export function setCanvasSize(size) {
    if (!size || !size.width || !size.height) {
        log(1, "Invalid canvas size:", size);
        return;
    }

    canvasSize = size;
}

export function updateConfig(options) {
    if (!options || typeof options !== "object") {
        return;
    }

    Object.assign(CONFIG, options);
    log(3, "Updated configuration:", CONFIG);
}

export { pendingUpdates, canvasReady, canvasSize, isProcessingUpdates, CONFIG };
