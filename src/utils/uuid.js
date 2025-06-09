// src/utils/uuid.js

export function generateUUID() {
    // On utilise l implementation native si elle est disponible
    if (
        typeof crypto !== "undefined" &&
        typeof crypto.randomUUID === "function"
    ) {
        return crypto.randomUUID();
    }

    // on va utiliser pour les anciens navigateurs la méthode de génération de UUID v4
    // qui est compatible avec les navigateurs plus anciens pour eviter les erreurs de compatibilité
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
        /[xy]/g,
        function (c) {
            const r = (Math.random() * 16) | 0;
            const v = c === "x" ? r : (r & 0x3) | 0x8;

            return v.toString(16);
        },
    );
}
