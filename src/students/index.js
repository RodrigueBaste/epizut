// file: src/students/index.js

// FIXME: This file should handle the students API
// Functions may include:
// - getStudent (get a student from the API by its uid or login)
// - getUserUidFromToken (get the user's uid from the token in local storage)
// - updateStudent (update the student's profile through the API)

import jwtDecode from "jwt-decode";
import { request } from "../utils/request.js";

function isNonEmptyString(value) {
    return typeof value === "string" && value.trim() !== "";
}

function isObject(value) {
    return value !== null && typeof value === "object";
}

export function getUserUidFromToken() {
    const token = localStorage.getItem("token");

    if (!isNonEmptyString(token)) {
        return null;
    }

    try {
        const payload = jwtDecode(token);

        return payload?.uid || payload?.sub || null;
    } catch (error) {
        console.error("[STUDENTS] Failed to decode token:", error);
        return null;
    }
}

export async function getStudent(identifier) {
    if (!isNonEmptyString(identifier)) {
        return null;
    }

    const url = `/api/students/${identifier}`;

    return await request(url);
}

export async function updateStudent(uid, data) {
    if (!isNonEmptyString(uid) || !isObject(data)) {
        return null;
    }

    const url = `/api/students/${uid}`;

    return await request(url, {
        method: "PUT",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
    });
}
