// src/rooms/index.js

// FIXME: This file should handle the rooms API
// Functions may include:
// - fetchRoomConfig (get the configuration of a room)
// - joinRoom (join a room by its slug)
// - listRooms (list all the rooms available)
// - createRoom (create a room)
// - updateRoom (update a room's configuration)
// - deleteRoom (delete a room)

import { request } from "../utils/request.js";

export function getRoomSlug() {
    const pathSegments = window.location.pathname.split("/").filter(Boolean);

    return pathSegments.length > 0 ? pathSegments[0] : "epi-place";
}

export async function fetchRoomConfig(roomSlug) {
    const url = `/api/rooms/${roomSlug}/config`;

    console.log(`[DEBUG] Getting room config for ${roomSlug}`);
    return await request(url);
}

export async function fetchRoomCanvas(roomSlug) {
    const url = `/api/rooms/${roomSlug}/canvas`;

    console.log(`[DEBUG] Getting room canvas for ${roomSlug}`);
    const result = await request(url);

    return result?.pixels ?? null;
}

export async function joinRoom(roomSlug) {
    const url = `/api/rooms/${roomSlug}/join`;

    console.log(`[DEBUG] Joining room ${roomSlug}`);
    return await request(url, { method: "POST" });
}

export async function listRooms() {
    const url = "/api/rooms";

    console.log("[DEBUG] Listing all rooms");
    return await request(url);
}

export async function createRoom(config) {
    const url = "/api/rooms";

    console.log("[DEBUG] Creating new room", config);
    return await request(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(config),
    });
}

export async function updateRoom(roomSlug, config) {
    const url = `/api/rooms/${roomSlug}`;

    console.log(`[DEBUG] Updating room ${roomSlug}`, config);
    return await request(url, {
        method: "PUT",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(config),
    });
}

export async function deleteRoom(roomSlug) {
    const url = `/api/rooms/${roomSlug}`;

    console.log(`[DEBUG] Deleting room ${roomSlug}`);
    const result = await request(url, { method: "DELETE" });

    return result !== null;
}
