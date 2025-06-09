// src/utils/pixelUpdates.js
export function extractPixelData(update) {
    console.debug("[DEBUG]!!!!!!!!!!!!!!!!!!!!!!!! :", update);
    if (!update || typeof update !== "object") {
        console.warn("[WARN] Invalid update object:", update);
        return null;
    }

    let pixelData = update;

    if (update.result) {
        if (update.result.type === "data" && update.result.data) {
            pixelData = update.result.data;
            console.debug(
                "[DEBUG] Extracted pixel data from data field:",
                pixelData,
            );
        } else if (update.result.json) {
            pixelData = update.result.json;
            console.debug(
                "[DEBUG] Extracted pixel data from json field:",
                pixelData,
            );
        }
    } else if (update.json) {
        pixelData = update.json;
        console.debug(
            "[DEBUG] Extracted pixel data from top-level json field:",
            pixelData,
        );
    }

    const { posX, posY, color } = pixelData;

    if (
        typeof posX !== "number" ||
        typeof posY !== "number" ||
        typeof color !== "number"
    ) {
        console.warn("[WARN] Invalid pixel data format:", pixelData);
        return null;
    }

    return { posX, posY, color };
}
