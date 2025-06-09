// This file handles the room canvas DOM manipulation
// Functions includes:
// - initCanvas (initialize the canvas)
// - renderCanvasUpdate (render a canvas update)
// - getPlacementData (get the necessary data to place a pixel)
// - toggleTooltip (toggle the tooltip and display the pixel's information)

import $ from "jquery";
import { socket, initSocket } from "../../utils/streams.js";
import { createAlert } from "../../utils/notify.js";
import { request } from "../../utils/request.js";
import { getRoomSlug } from "../index.js";

const canvasContainer = $("#canvas-container")?.[0];
const canvas = $("#canvas")?.[0];
const canvasCtx = canvas?.getContext("2d");
const selector = $("#selector")?.[0];

const positionTooltip = $("#position-tooltip")?.[0];
const tooltip = $("#tooltip")?.[0];
const colorPicker = $("#color-picker")?.[0];
const colorWheelContainer = $("#color-wheel-container")?.[0];
const colorWheel = $("#color-wheel")?.[0];

// On fait un check pour s'assurer que tous les éléments nécessaires sont présents
if (
    !canvas ||
    !canvasCtx ||
    !selector ||
    !positionTooltip ||
    !tooltip ||
    !colorPicker ||
    !colorWheelContainer ||
    !colorWheel
) {
    console.error("[ERROR] Required DOM elements not found");
    throw new Error("Required DOM elements not found");
}

/**
 * Global variables
 */
let board, palette, selectedColorIdx;
let animation;

const zoomSpeed = 1 / 25;
let zoom = 2.5;

let x, y;
let cx = 0;
let cy = 0;
let target = { x: 0, y: 0 };
let isDrag = false;

/**
 * Returns the necessary data to place a pixel
 * @returns {{color: number, posX: number, posX: number}} the data
 */
export const getPlacementData = () => ({
    color: selectedColorIdx,
    posX: target.x,
    posY: target.y,
});

// ajouter par rodrigue baste

/**
 * Get pixel information at the given coordinates
 * @param {number} x - X coordinate
 * @param {number} y - Y coordinate
 * @returns {{color: string, index: number}|null} pixel information or null if invalid
 */
const _getPixelInfo = (x, y) => {
    if (!board || !palette || typeof x !== "number" || typeof y !== "number") {
        return null;
    }

    const index = y * canvas.width + x;

    if (index < 0 || index >= board.length) {
        return null;
    }

    const colorIndex = board[index];

    return {
        color: palette[colorIndex],
        index: colorIndex,
    };
};

/**
 * Toggle the tooltip and display the pixel's information
 * @param {boolean} state
 */
export const toggleTooltip = async (state = false) => {
    tooltip.style.display = state ? "flex" : "none";

    if (state) {
        try {
            const roomSlug = getRoomSlug();

            if (!roomSlug) {
                console.error("[TOOLTIP] roomSlug is undefined");
                return;
            }

            if (
                typeof target.x !== "number" ||
                typeof target.y !== "number" ||
                isNaN(target.x) ||
                isNaN(target.y) ||
                target.x < 0 ||
                target.y < 0 ||
                target.x >= canvas.width ||
                target.y >= canvas.height
            ) {
                console.warn("[TOOLTIP] Invalid target coordinates", target);
                createAlert(
                    "Erreur",
                    "Coordonnées de pixel invalides",
                    "error",
                );
                return;
            }

            const url = `/api/rooms/${roomSlug}/canvas/pixels?posX=${target.x}&posY=${target.y}`;

            console.debug("[TOOLTIP] Fetching pixel info:", url);
            const pixelData = await request(url);

            if (!pixelData) {
                createAlert("Erreur", "Aucune donnée pixel trouvée", "error");
                return;
            }

            if (pixelData.status === 404) {
                createAlert("Erreur", "Pixel non trouvé (404)", "error");
                return;
            }

            const student = await request(
                `/api/students/${pixelData.placedByUid}`,
            );

            const avatarImg = document.getElementById("tooltip-info-avatar");
            const loginText = document.getElementById("tooltip-info-login");
            const quoteText = document.getElementById("tooltip-info-quote");
            const dateText = document.getElementById("tooltip-date");
            const timeText = document.getElementById("tooltip-time");

            const avatar = student?.avatar || "/default-avatar.png";
            const login = student?.login || "";
            const quote = student?.quote || "";
            const date = new Date(pixelData.timestamp || 0);

            if (avatarImg) {
                avatarImg.src = avatar;
            }

            if (loginText) {
                loginText.textContent = login;
            }

            if (quoteText) {
                quoteText.textContent = quote;
            }

            if (dateText) {
                dateText.textContent = date.toLocaleDateString();
            }

            if (timeText) {
                timeText.textContent = date.toLocaleTimeString();
            }
        } catch (err) {
            console.error("[TOOLTIP] Failed to fetch pixel info", err);
        }
    }
};

/**
 * Calculate the target position according to the top left corner of the canvas
 * @param {*} event
 * @returns {x: number, y: number} the target position
 */
const calculateTarget = (event) => {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const canvasLeft = rect.left + window.pageXOffset;
    const canvasTop = rect.top + window.pageYOffset;

    return {
        x: Math.floor(
            ((event?.pageX ?? window.innerWidth / 2) - canvasLeft) * scaleX,
        ),
        y: Math.floor(
            ((event?.pageY ?? window.innerHeight / 2) - canvasTop) * scaleY,
        ),
    };
};

/**
 * Update the position tooltip
 * @param {*} event
 */
const positionUpdate = (event) => positionDisplay(calculateTarget(event));

/**
 * Update the position tooltip
 * @param {{x: number, y: number}} target
 */
const positionDisplay = ({ x, y }) => {
    positionTooltip.innerText = `X=${x} Y=${y}`;
    canvas.style.transform = `translate(${cx}px, ${cy}px) scale(${zoom})`;

    // We add the canvas.width * zoom to make cx and cy positive
    let selectorX = cx + canvas.width * zoom;
    let selectorY = cy + canvas.height * zoom;

    // Make odd canvas align
    if (canvas.width % 2 !== 0) {
        selectorX += zoom / 2;
        selectorY += zoom / 2;
    }

    // Find the translate
    selectorX %= zoom;
    selectorY %= zoom;

    // Center selector on the pixel
    selectorX -= zoom / 2;
    selectorY -= zoom / 2;

    selector.style.transform = `translate(${selectorX}px, ${selectorY}px) scale(${zoom})`;
};

// Toggle the color wheel on click on the color picker
colorPicker.addEventListener("click", () => {
    const state = colorWheelContainer.style.display;

    colorWheelContainer.style.display =
        !state || state === "none" ? "block" : "none";
});

// Transformation d'une couleur hexadécimale en entier 32 bits
export const transformHexTo32Bits = (hex) => {
    // Suppression du # si présent
    hex = hex.replace("#", "");

    // Conversion en entier
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);

    // Construction de l'entier 32 bits.
    // Le canvas utilise l'ordre BGRA en mémoire. On place donc le bleu en
    // premier, suivi du vert puis du rouge avant l'alpha.
    return (b << 24) | (g << 16) | (r << 8) | 255;
};

/**
 * Render the canvas
 * @param {number[]} pixels
 * @param {string[]} colors
 */
const renderCanvas = (pixels, colors) => {
    const img = new ImageData(canvas.width, canvas.height);
    const data = new Uint32Array(img.data.buffer);

    board = pixels;
    palette = colors;
    for (let i = 0; i < pixels.length; i++) {
        data[i] = transformHexTo32Bits(colors[pixels[i]]);
    }

    canvasCtx.putImageData(img, 0, 0);
    canvasCtx.imageSmoothingEnabled = false;
    canvas.style.imageRendering = "pixelated";

    // Remove all the colors from the color wheel
    while (colorWheel.firstChild) {
        colorWheel.removeChild(colorWheel.firstChild);
    }

    // Add the colors to the color wheel
    for (let i = 0; i < colors.length; i++) {
        const btn = document.createElement("button");

        colorWheel.appendChild(btn);

        btn.addEventListener("click", () => {
            selectedColorIdx = i;
            colorPicker.style.color = colors[i];
            colorPicker.style.border = `${colors[i]} 0.1rem solid`;
        });

        btn.style.backgroundColor = colors[i];
    }
};

/**
 * Initialize the canvas
 * @param {*} roomConfig
 * @param {number[]} pixels
 */
export const initCanvas = (roomConfig, pixels, { width, height }) => {
    canvas.width = width;
    canvas.height = height;

    positionDisplay({ x: width / 2, y: height / 2 });
    selectedColorIdx = 0;

    const roomColors = roomConfig.settings.roomColors.split(",");

    colorPicker.style.color = roomColors[0];
    colorPicker.style.border = `${roomColors[0]} 0.1rem solid`;

    renderCanvas(pixels, roomColors);
};

/**
 * Update the canvas
 * @param {string} color
 * @param {number} x
 * @param {number} y
 */
export function renderCanvasUpdate(colorIndex, x, y) {
    const board = getBoard();
    const palette = getPalette();
    const canvasCtx = getCanvasContext();

    if (!board || !palette || !canvasCtx) {
        console.warn("[WARN] Canvas context not ready");
        return;
    }

    // Vérification des coordonnées
    if (
        x < 0 ||
        y < 0 ||
        x >= canvasCtx.canvas.width ||
        y >= canvasCtx.canvas.height
    ) {
        console.warn(`[WARN] Invalid pixel coordinates: (${x}, ${y})`);
        return;
    }

    // Calcul de l'index avec la largeur du canvas
    const index = y * canvasCtx.canvas.width + x;

    // Vérification de l'index
    if (index < 0 || index >= board.length) {
        console.warn(`[WARN] Invalid pixel index: ${index}`);
        return;
    }

    // Mise à jour du tableau board
    board[index] = colorIndex;

    // Create a 1x1 ImageData for this single pixel
    const img = new ImageData(1, 1);
    const data = new Uint32Array(img.data.buffer);

    data[0] = transformHexTo32Bits(palette[colorIndex]);

    // Update just this pixel
    canvasCtx.putImageData(img, x, y);
}

/**
 * Reset the canvas values
 */
export const resetValues = () => {
    zoom = 2.5;
    x = 0;
    y = 0;
    cx = 0;
    cy = 0;
    isDrag = false;

    positionDisplay({ x, y });
    colorWheelContainer.style.display = "none";
    toggleTooltip(false);
};

// Handle scroll on canvas
document.addEventListener("wheel", (e) => {
    // Make sure we're scrolling on the canvas or the body and not the UI
    if (e.target !== canvas && e.target !== canvasContainer) {
        return;
    }

    clearInterval(animation);
    toggleTooltip(false);

    const delta = Math.sign(e.deltaY) * zoomSpeed;
    const zoomFactor = 1 + delta;
    const oldZoom = zoom;
    const newZoom = Math.max(2.5, Math.min(40, oldZoom * zoomFactor));

    // Get the position of the mouse relative to the canvas
    const mouseX = e.clientX - window.innerWidth / 2;
    const mouseY = e.clientY - window.innerHeight / 2;

    // Calculate the new center point based on the mouse position
    const newCx = mouseX - (mouseX - cx) * (newZoom / oldZoom);
    const newCy = mouseY - (mouseY - cy) * (newZoom / oldZoom);

    if (newZoom !== oldZoom) {
        zoom = newZoom;
        cx = newCx;
        cy = newCy;
        positionUpdate();
    }
});

// Handle click and drag on canvas
document.addEventListener("mousedown", (e) => {
    // Make sure we're clicking on the canvas or the body and not the UI
    if (e.target !== canvas && e.target !== canvasContainer) {
        return;
    }

    e.preventDefault();

    // Ignore if right click
    if (e.button === 2) {
        return;
    }

    clearInterval(animation);

    isDrag = false;
    x = e.clientX;
    y = e.clientY;

    document.addEventListener("mousemove", mouseMove);
});

// Smooth animation
function easeOutQuart(t, b, c, d) {
    t /= d;
    t--;
    return -c * (t * t * t * t - 1) + b;
}

// Handle when the user releases the mouse
document.addEventListener("mouseup", async (e) => {
    document.removeEventListener("mousemove", mouseMove);

    // Make sure we're clicking on the canvas or the body and not the UI
    if (e.target !== canvas && e.target !== canvasContainer) {
        return;
    }

    e.preventDefault();

    // Get the tile position
    target = calculateTarget(e);

    // Make sure we're clicking on the canvas
    if (
        target.x >= 0 &&
        target.x < canvas.width &&
        target.y >= 0 &&
        target.y < canvas.height
    ) {
        if (!isDrag) {
            const { color, posX, posY } = getPlacementData();

            if (
                typeof color !== "number" ||
                typeof posX !== "number" ||
                typeof posY !== "number" ||
                isNaN(color) ||
                isNaN(posX) ||
                isNaN(posY)
            ) {
                console.warn("[PLACE] Invalid placement data", {
                    color,
                    posX,
                    posY,
                });
                createAlert("Error", "Invalid pixel data", "error");
                return;
            }

            console.debug(
                `[PLACE] Tentative de placement : (${posX}, ${posY}) couleur ${color}`,
            );

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

            activeSocket.emit(
                "place-pixel",
                {
                    position: { x: posX, y: posY },
                    color: color,
                },
                (response) => {
                    if (!response || response.status !== "ok") {
                        console.error(
                            "[PLACE] Échec du placement :",
                            response?.message,
                        );
                        createAlert(
                            "Placement échoué",
                            response?.message || "Erreur inconnue",
                            "error",
                        );
                        return;
                    }

                    console.log("[PLACE] Pixel placé avec succès !");
                    createAlert("Succès", "Pixel placé avec succès", "success");
                },
            );

            const duration = 1000;
            const startZoom = zoom;
            const endZoom = Math.max(15, Math.min(40, zoom));

            const clickX = e.clientX - window.innerWidth / 2;
            const clickY = e.clientY - window.innerHeight / 2;
            const canvaswidthzoom = canvas.width * startZoom;
            const canvasheightzoom = canvas.height * startZoom;
            const startx = (cx + canvaswidthzoom / 2) / startZoom;
            const starty = (cy + canvasheightzoom / 2) / startZoom;
            const endx = startx - clickX / startZoom;
            const endy = starty - clickY / startZoom;
            const endCx = endx * endZoom - (canvas.width / 2) * endZoom;
            const endCy = endy * endZoom - (canvas.height / 2) * endZoom;
            const startCx = cx;
            const startCy = cy;
            const startTime = Date.now();

            if (
                Math.abs(endCx - startCx) < 10 &&
                Math.abs(endCy - startCy) < 10
            ) {
                cx = endCx;
                cy = endCy;
                zoom = endZoom;
                canvas.style.transform = `translate(${cx}px, ${cy}px) scale(${zoom})`;
            } else {
                clearInterval(animation);

                animation = setInterval(() => {
                    const elapsed = Date.now() - startTime;

                    if (elapsed >= duration) {
                        clearInterval(animation);
                        return;
                    }

                    const t = elapsed / duration;

                    zoom = easeOutQuart(t, startZoom, endZoom - startZoom, 1);
                    cx = easeOutQuart(t, startCx, endCx - startCx, 1);
                    cy = easeOutQuart(t, startCy, endCy - startCy, 1);

                    positionUpdate();
                }, 10);
            }
        }

        toggleTooltip(!isDrag);

        positionDisplay(target);
    }
});

const mouseMove = (e) => {
    e.preventDefault();

    toggleTooltip(false);
    positionUpdate();

    const dx = e.clientX - x;
    const dy = e.clientY - y;

    if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) {
        isDrag = true;
    }

    x = e.clientX;
    y = e.clientY;
    cx += dx;
    cy += dy;

    canvas.style.transform = `translate(${cx}px, ${cy}px) scale(${zoom})`;
};

// Getters pour accéder aux variables globales de manière sécurisée
export const getBoard = () => board;
export const getPalette = () => palette;
export const getCanvasContext = () => canvasCtx;
