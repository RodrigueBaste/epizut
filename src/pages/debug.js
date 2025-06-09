import $ from "jquery";
import debugHtml from "../components/debug.html";
import { authedAPIRequest } from "../utils/auth.js";
import { createAlert } from "../utils/notify.js";
import { requestWithRetry } from "../utils/request.js";

function refreshLocalStorage() {
    $("#token").text(localStorage.getItem("token") ?? "N/A");
    $("#refresh_token").text(localStorage.getItem("refresh_token") ?? "N/A");
}

if (import.meta.env.MODE === "debug") {
    $.get(debugHtml, function (response) {
        $("body").html(response);
        refreshLocalStorage();
    }).fail(function (xhr, status, error) {
        console.error("Error fetching debug HTML:", error);
    });

    $(document).on("click", "#errorBtn", async function () {
        try {
            const response = await authedAPIRequest("tests/error", {
                method: "GET",
            });

            if (response) {
                const data = await response.json();

                console.log("[DEBUG] Error endpoint response:", data);
                createAlert("Debug", "Error test completed", "info");
            }
        } catch (err) {
            console.error("[DEBUG] Error while calling error endpoint:", err);
            createAlert(
                "Debug Error",
                "Failed to call error endpoint",
                "error",
            );
        }
    });

    $(document).on("click", "#expiredTokenBtn", async function () {
        try {
            const response = await authedAPIRequest("tests/expired", {
                method: "GET",
            });

            if (response) {
                const data = await response.json();

                console.log("[DEBUG] Expired token response:", data);
                createAlert("Debug", "Expired token test completed", "info");
            }
        } catch (err) {
            console.error(
                "[DEBUG] Error while calling expired token endpoint:",
                err,
            );
            createAlert(
                "Debug Error",
                "Failed to call expired token endpoint",
                "error",
            );
        }
    });

    $(document).on("click", "#deleteTokenBtn", function () {
        localStorage.removeItem("token");
        refreshLocalStorage();
        createAlert("Debug", "Token deleted from localStorage", "warn");
    });

    $(document).on("click", "#deleteRefreshTokenBtn", function () {
        localStorage.removeItem("refresh_token");
        refreshLocalStorage();
        createAlert("Debug", "Refresh token deleted from localStorage", "warn");
    });

    $(document).on("click", "#testApiRequestBtn", async function () {
        try {
            const result = await requestWithRetry("rooms", {
                method: "GET",
            });

            console.log("[DEBUG] API Request test result:", result);
            createAlert("Debug", "API Request test completed", "success");
        } catch (err) {
            console.error("[DEBUG] Error in API request test:", err);
            createAlert("Debug Error", "API Request test failed", "error");
        }
    });

    $(document).on("click", "#testRefreshFlowBtn", async function () {
        try {
            const oldToken = localStorage.getItem("token");
            const backupToken = oldToken;

            localStorage.setItem("token", "expired.token.value");

            createAlert("Debug", "Testing token refresh flow...", "info");

            const response = await authedAPIRequest("rooms", {
                method: "GET",
            });

            const newToken = localStorage.getItem("token");

            if (response && newToken !== "expired.token.value") {
                console.log("[DEBUG] Token refresh flow test succeeded");
                createAlert(
                    "Debug",
                    "Token refresh flow test completed",
                    "success",
                );
            } else {
                // On restore le token de sauvegarde
                if (backupToken) {
                    localStorage.setItem("token", backupToken);
                }

                console.error("[DEBUG] Token refresh flow test failed");
                createAlert("Debug", "Token refresh flow test failed", "error");
            }
        } catch (err) {
            console.error("[DEBUG] Error in token refresh flow test:", err);
            createAlert(
                "Debug Error",
                "Token refresh flow test failed",
                "error",
            );
        }

        refreshLocalStorage();
    });
}
