const API_KEY = "AQUI_TU_API_KEY_DE_DEEPSEEK";

async function procesar() {
    const modo = document.getElementById("mode").value;
    const input = document.getElementById("input").value.trim();
    const respuesta = document.getElementById("respuesta");

    if (!input) {
        respuesta.innerHTML = "⚠️ Escribe algo primero.";
        return;
    }

    respuesta.innerHTML = "Procesando…";

    let prompt = "";

    // 🟦 1. BÚSQUEDA DIPLOMÁTICA
    if (modo === "busqueda") {
        prompt = `
Eres una IA diplomática para delegados de Modelo de Naciones Unidas.

Objetivo: ofrecer enlaces confiables (.org, .gov, .int o de la ONU)
sobre el siguiente tema, en orden del más reciente al más antiguo.

Tras cada enlace, da un breve párrafo diplomático describiendo su relevancia.

Tema: ${input}
        `;
    }

    // 🟩 2. INTERPELACIÓN MUN
    if (modo === "interpelacion") {
        prompt = `
Actúa como un delegado crítico en un Modelo de Naciones Unidas.
Habla SIEMPRE en tercera persona.
Ejemplos:
- "La delegación de To' Revuelto se cuestiona…"
- "La delegación observa con preocupación…"

Interpela, cuestiona y analiza cada afirmación del discurso:

"${input}"
        `;
    }

    // 🟨 3. CORRECCIÓN DE DISCURSOS
    if (modo === "correccion") {
        prompt = `
Corrige este discurso respetando la estructura MUN:
1. Introducción global
2. Desarrollo nacional
3. Conclusión internacional con propuestas

Mejorar diplomacia, coherencia y estructura.

Discurso:
"${input}"
        `;
    }

    // 🟧 4. DESGLOSE DE TÓPICO
    if (modo === "desglose") {
        prompt = `
Desglosa el siguiente tópico para que un delegado investigue
y pueda redactar un discurso o position paper.

Incluye:
- Preguntas clave
- Subtemas
- Líneas de investigación diplomática

Tópico: ${input}
        `;
    }

    // 🟥 5. CORRECCIÓN DE POSITION PAPER
    if (modo === "documento") {
        prompt = `
Corrige este Position Paper según estándares MUN:

Debe tener:
- 500 a 800 palabras
- Campos: Tópico, Comisión, Delegación, Delegado
- Desarrollo tipo discurso
- Bibliografía válida
- Tono diplomático

Texto del PP:
"${input}"
        `;
    }

    try {
        const result = await fetch("https://api.deepseek.com/chat/completions", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + API_KEY
            },
            body: JSON.stringify({
                model: "deepseek-chat",
                messages: [
                    { role: "user", content: prompt }
                ]
            })
        });

        const data = await result.json();
        respuesta.innerHTML = data.choices[0].message.content;

    } catch (e) {
        respuesta.innerHTML = "❌ Error al conectar con DeepSeek.";
        console.log(e);
    }
}
