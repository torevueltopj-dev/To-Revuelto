// 💡 PON TU API AQUÍ
const API_KEY = "AIzaSyArz0HOBHd8XB73KegLzG-NGxt5vbl-z0o";

// CHAT ELEMENTS
const chat = document.getElementById("chat");
const input = document.getElementById("userInput");
const sendBtn = document.getElementById("sendBtn");

// 📌 FUNCIONES MUN
function generarPromptMUN(text) {
    return `
Eres una IA diplomática especializada en Modelo de Naciones Unidas.

Funciones integradas:

1. **Búsqueda diplomática:**  
   - Usa solo fuentes .org, .gov, .int o de la ONU.  
   - Devuelve 3 enlaces confiables ordenados por fecha (reciente → antiguo)  
   - Un párrafo diplomático por enlace.

2. **Interpelación MUN:**  
   - Habla SIEMPRE en tercera persona.  
   - Ejemplo: "La delegación de To' Revuelto se cuestiona…"  
   - Sé crítico y analiza cada línea.

3. **Corrección de discursos:**  
   - Debes corregir siguiendo:  
     a) Introducción global  
     b) Desarrollo nacional  
     c) Conclusión internacional con propuestas  

4. **Desglose de tópico:**  
   - Preguntas clave  
   - Subtemas  
   - Líneas diplomáticas  

5. **Corrección de position paper:**  
   - 500-800 palabras  
   - Tópico, Comisión, Delegación, Delegado  
   - Bibliografía válida  
   - Tono diplomático

👉 Entrada del usuario:
${text}
`;
}


// 📌 FUNCIÓN PARA AÑADIR MENSAJES AL CHAT
function addMessage(text, sender) {
    const msg = document.createElement("div");
    msg.classList.add("message", sender);
    msg.textContent = text;
    chat.appendChild(msg);
    chat.scrollTop = chat.scrollHeight;
}


// 📌 LLAMADA A GEMINI
async function enviarPrompt() {
    const texto = input.value.trim();
    if (!texto) return;

    addMessage(texto, "user");
    input.value = "";

    addMessage("Procesando…", "ai");

    try {
        const response = await fetch(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=" + API_KEY,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    contents: [{ role: "user", parts: [{ text: generarPromptMUN(texto) }] }]
                })
            }
        );

        const data = await response.json();
        const respuesta = data.candidates?.[0]?.content?.parts?.[0]?.text || "Error en la respuesta.";

        addMessage(respuesta, "ai");

    } catch (e) {
        addMessage("❌ Error al conectar con Gemini.", "ai");
    }
}


// EVENTOS
sendBtn.addEventListener("click", enviarPrompt);
input.addEventListener("keypress", (e) => {
    if (e.key === "Enter") enviarPrompt();
});