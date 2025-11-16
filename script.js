const API_KEY = "TU_API_KEY_AQUI";
const URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=" + API_KEY;

document.getElementById("sendBtn").addEventListener("click", sendMessage);

function sendMessage() {
    const input = document.getElementById("userInput");
    const text = input.value.trim();
    if (!text) return;

    addMessage(text, "user");
    input.value = "";

    fetch(URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            contents: [{ parts: [{ text: text }] }]
        })
    })
    .then(res => res.json())
    .then(data => {
        const reply = data.candidates?.[0]?.content?.parts?.[0]?.text || "Error procesando respuesta";
        addMessage(reply, "bot");
    })
    .catch(() => {
        addMessage("Error conectando al servidor de Gemini.", "bot");
    });
}

function addMessage(text, type) {
    const box = document.getElementById("messages");
    const div = document.createElement("div");
    div.className = "message " + type;
    div.textContent = text;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
}
