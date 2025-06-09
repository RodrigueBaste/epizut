// FIXME: This file should handle the students DOM manipulation
// Link buttons to their respective functions
// Functions may include:
// - displayStudentProfile (display the student's profile in the DOM)
// - showModal (add a form modal to the DOM)

import $ from "jquery";
import updateHtml from "../components/students/update.html";

function getById(id) {
    return document.getElementById(id);
}

function setTextContent(element, value) {
    if (element) {
        element.textContent = value || "";
    }
}

function setAvatar(element, url) {
    if (element) {
        element.src = url || "/default-avatar.png";
    }
}

export function displayStudentProfile(student) {
    if (!student) {
        return;
    }

    setAvatar(getById("profile-info-avatar"), student.avatar);
    setTextContent(getById("profile-info-login"), student.login);
    setTextContent(getById("profile-info-quote"), student.quote);
}

export function showModal() {
    if (getById("student-update-form")) {
        return;
    }

    $.get(updateHtml, (html) => {
        const [modal] = $(html);

        if (!modal) {
            return;
        }

        $("body").append(modal);

        $("#close-modal").on("click", () => modal.remove());
        $("#student-update-form").on("submit", (e) => {
            e.preventDefault();
            modal.remove();
        });
    });
}

document.getElementById("profile-update")?.addEventListener("click", showModal);
