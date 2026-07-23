const ROLES = {
  DIRECTOR_GENERAL: 'director_general',
  SUBDIRECTORA_GENERAL: 'subdirectora_general',
  SECRETARIA: 'secretaria',
  VOLUNTARIO: 'voluntario',
};

const ROLES_ALTA_DIRECCION = [ROLES.DIRECTOR_GENERAL, ROLES.SUBDIRECTORA_GENERAL, ROLES.SECRETARIA];
const ROLES_CON_ACCESO_TOTAL = [ROLES.DIRECTOR_GENERAL, ROLES.SUBDIRECTORA_GENERAL];



const NOMBRES_ROLES = {
  [ROLES.DIRECTOR_GENERAL]: "Director General",
  [ROLES.SUBDIRECTORA_GENERAL]: "Sub-Directora General",
  [ROLES.SECRETARIA]: "Secretaría",
  [ROLES.VOLUNTARIO]: "Voluntario",
};

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      ...extraHeaders,
    },
  });
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Content-Security-Policy':
        "default-src 'self'; img-src 'self' https: data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; connect-src 'self';",
      ...extraHeaders,
    },
  });
}

function errorResponse(mensaje, status = 400) {
  return jsonResponse({ ok: false, error: mensaje }, status);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const ETIQUETAS_PERMITIDAS = new Set(['b', 'strong', 'i', 'em', 'u', 'p', 'div', 'br', 'ul', 'ol', 'li', 'h2', 'h3', 'blockquote', 'a']);
const ALINEACIONES_PERMITIDAS = new Set(['left', 'right', 'center', 'justify']);

function sanitizarHtmlArticulo(html) {
  if (!html) return '';
  let limpio = html.replace(/<script[\s\S]*?<\/script>/gi, '');
  limpio = limpio.replace(/<style[\s\S]*?<\/style>/gi, '');
  limpio = limpio.replace(/on\w+="[^"]*"/gi, '');
  limpio = limpio.replace(/on\w+='[^']*'/gi, '');
  limpio = limpio.replace(/javascript:/gi, '');
  limpio = limpio.replace(/<\/?([a-zA-Z0-9]+)([^>]*)>/g, (match, tag, attrs) => {
    const tagLower = tag.toLowerCase();
    if (!ETIQUETAS_PERMITIDAS.has(tagLower)) return '';
    if (tagLower === 'a') {
      const hrefMatch = attrs.match(/href="([^"]*)"/i);
      const href = hrefMatch ? hrefMatch[1] : '#';
      if (/^https?:\/\//i.test(href)) {
        return match.startsWith('</') ? '</a>' : `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">`;
      }
      return match.startsWith('</') ? '</a>' : '<a>';
    }
    if ((tagLower === 'p' || tagLower === 'div') && !match.startsWith('</')) {
      const estiloMatch = attrs.match(/style="([^"]*)"/i);
      const alineacionMatch = estiloMatch ? estiloMatch[1].match(/text-align:\s*(left|right|center|justify)/i) : null;
      if (alineacionMatch && ALINEACIONES_PERMITIDAS.has(alineacionMatch[1].toLowerCase())) {
        return `<${tagLower} style="text-align:${alineacionMatch[1].toLowerCase()}">`;
      }
      return `<${tagLower}>`;
    }
    return match.startsWith('</') ? `</${tagLower}>` : `<${tagLower}>`;
  });
  return limpio;
}

function slugify(texto) {
  return String(texto)
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 80);
}

function generarIdAleatorio(longitud = 12) {
  const bytes = new Uint8Array(longitud);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fechaISOaYMD(fecha) {
  return fecha.toISOString().slice(0, 10);
}

async function hashPassword(password, salt, pepper) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password + pepper),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(derivedBits), (b) => b.toString(16).padStart(2, '0')).join('');
}

function generarSalt() {
  return generarIdAleatorio(16);
}

async function verificarPassword(password, salt, pepper, hashGuardado) {
  const hashCalculado = await hashPassword(password, salt, pepper);
  return timingSafeEqual(hashCalculado, hashGuardado);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let resultado = 0;
  for (let i = 0; i < a.length; i++) {
    resultado |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return resultado === 0;
}

function validarUsername(username) {
  return typeof username === 'string' && /^[a-zA-Z0-9_.]{3,32}$/.test(username);
}

function validarPassword(password) {
  return typeof password === 'string' && password.length >= 6 && password.length <= 128;
}

function validarCorreo(correo) {
  if (!correo) return true; // opcional en algunos flujos
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo) && correo.length <= 254;
}

function validarTelefono(telefono) {
  if (!telefono) return true;
  return /^[0-9+\-\s()]{7,20}$/.test(telefono);
}

function normalizarTelefonoRD(telefono) {
  if (!telefono) return null;
  let limpio = String(telefono).replace(/[^\d+]/g, '');
  if (limpio.startsWith('+')) {
    limpio = '+' + limpio.slice(1).replace(/\+/g, '');
  } else {
    limpio = limpio.replace(/\+/g, '');
  }
  if (limpio.startsWith('+1')) {
    const resto = limpio.slice(2);
    if (resto.length === 10) return '+1' + resto;
    return null;
  }
  if (limpio.length === 10 && /^(809|829|849)/.test(limpio)) {
    return '+1' + limpio;
  }
  if (limpio.length === 11 && limpio.startsWith('1')) {
    return '+' + limpio;
  }
  return null;
}

function validarRolAsignable(rol, rolQuienAsigna) {
  const rolesValidos = Object.values(ROLES);
  if (!rolesValidos.includes(rol)) return false;
  if (ROLES_ALTA_DIRECCION.includes(rol) && !ROLES_CON_ACCESO_TOTAL.includes(rolQuienAsigna)) {
    return false;
  }
  return true;
}

const GRUPO_WHATSAPP_UNICO_FALLBACK = '';
function obtenerLinkGrupoWhatsapp(env) {
  return env.GROUPW || GRUPO_WHATSAPP_UNICO_FALLBACK;
}

const NOMBRE_COOKIE = 'tr_session';
const DURACION_SESION_SEGUNDOS = 60 * 60 * 24 * 7; // 7 dias

function parsearCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const cookies = {};
  header.split(';').forEach((parte) => {
    const [k, ...v] = parte.trim().split('=');
    if (k) cookies[k] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

async function crearSesion(env, username) {
  const token = generarIdAleatorio(32);
  const datos = { username, creado_en: Date.now() };
  await env.SESSIONS_KV.put(`sesion:${token}`, JSON.stringify(datos), {
    expirationTtl: DURACION_SESION_SEGUNDOS,
  });
  return token;
}

async function obtenerSesion(request, env) {
  const cookies = parsearCookies(request);
  const token = cookies[NOMBRE_COOKIE];
  if (!token) return null;
  const datosRaw = await env.SESSIONS_KV.get(`sesion:${token}`);
  if (!datosRaw) return null;
  try {
    const datos = JSON.parse(datosRaw);
    return { token, username: datos.username };
  } catch {
    return null;
  }
}

async function destruirSesion(env, token) {
  await env.SESSIONS_KV.delete(`sesion:${token}`);
}

function cookieDeSesion(token) {
  return `${NOMBRE_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${DURACION_SESION_SEGUNDOS}`;
}

function cookieBorrarSesion() {
  return `${NOMBRE_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

async function obtenerUsuario(env, username) {
  const raw = await env.USERS_KV.get(`usuario:${username}`);
  if (!raw) return null;
  return JSON.parse(raw);
}

async function guardarUsuario(env, usuario) {
  await env.USERS_KV.put(`usuario:${usuario.username}`, JSON.stringify(usuario));
}

const TEMAS_DISPONIBLES = {
  azul: { nombre: 'Azul (predeterminado)', acento: '#75BCE1' },
  amarillo: { nombre: 'Amarillo', acento: '#F7D52F' },
  morado: { nombre: 'Morado', acento: '#9d4edd' },
  verde: { nombre: 'Verde', acento: '#4ade80' },
  rojo: { nombre: 'Rojo', acento: '#f87171' },
};

const PREFERENCIAS_DEFECTO = {
  tema: 'azul',
  orden_tabs: [],
  widgets_resumen_colapsados: [],
};

async function obtenerPreferenciasUsuario(env, username) {
  const raw = await env.USERS_KV.get(`prefs:${username}`);
  if (!raw) return { ...PREFERENCIAS_DEFECTO };
  try {
    return { ...PREFERENCIAS_DEFECTO, ...JSON.parse(raw) };
  } catch {
    return { ...PREFERENCIAS_DEFECTO };
  }
}

async function guardarPreferenciasUsuario(env, username, prefs) {
  await env.USERS_KV.put(`prefs:${username}`, JSON.stringify(prefs));
}

async function obtenerIndiceUsuarios(env) {
  const raw = await env.USERS_KV.get('indice_usuarios');
  return raw ? JSON.parse(raw) : [];
}

async function agregarAIndiceUsuarios(env, username) {
  const indice = await obtenerIndiceUsuarios(env);
  if (!indice.includes(username)) {
    indice.push(username);
    await env.USERS_KV.put('indice_usuarios', JSON.stringify(indice));
  }
}

async function listarUsuarios(env) {
  const indice = await obtenerIndiceUsuarios(env);
  const usuarios = [];
  for (const username of indice) {
    const u = await obtenerUsuario(env, username);
    if (u) usuarios.push(u);
  }
  return usuarios;
}

async function existeAlgunUsuario(env) {
  const indice = await obtenerIndiceUsuarios(env);
  return indice.length > 0;
}

function usuarioPublico(usuario) {
  const { password_hash, salt, ...resto } = usuario;
  return resto;
}

function usuarioPublicoConFoto(env, usuario) {
  return { ...usuarioPublico(usuario), foto_url: urlPublicaR2(env, usuario.foto_key) };
}

async function requiereAuth(request, env) {
  const sesion = await obtenerSesion(request, env);
  if (!sesion) return null;
  const usuario = await obtenerUsuario(env, sesion.username);
  if (!usuario) return null;
  if (usuario.estado !== 'activo') return null;
  return usuario;
}

const FIRMAS_IMAGEN = [
  { tipo: 'image/webp', bytes: [0x52, 0x49, 0x46, 0x46], offsetExtra: { pos: 8, bytes: [0x57, 0x45, 0x42, 0x50] } },
  { tipo: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47] },
  { tipo: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },
];

function detectarTipoImagenReal(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer.slice(0, 16));
  for (const firma of FIRMAS_IMAGEN) {
    const coincide = firma.bytes.every((b, i) => bytes[i] === b);
    if (coincide) {
      if (firma.offsetExtra) {
        const extra = firma.offsetExtra.bytes.every((b, i) => bytes[firma.offsetExtra.pos + i] === b);
        if (!extra) continue;
      }
      return firma.tipo;
    }
  }
  return null;
}

async function subirImagenR2(env, arrayBuffer, carpeta, nombreBase) {
  if (arrayBuffer.byteLength === 0) throw new Error('Archivo vacío.');
  if (arrayBuffer.byteLength > 12 * 1024 * 1024) throw new Error('Imagen demasiado grande (máx 12MB).');

  const tipoReal = detectarTipoImagenReal(arrayBuffer);
  if (!tipoReal) throw new Error('El archivo no es una imagen válida (webp, png o jpeg).');

  const extension = tipoReal === 'image/webp' ? 'webp' : tipoReal === 'image/png' ? 'png' : 'jpg';
  const key = `${carpeta}/${nombreBase}-${generarIdAleatorio(8)}.${extension}`;
  await env.BUCKET.put(key, arrayBuffer, {
    httpMetadata: { contentType: tipoReal },
  });
  return key;
}

function urlPublicaR2(env, key) {
  if (!key) return null;
  return `${env.R2_PUBLIC_URL}/${key}`;
}

async function subirMultiplesImagenesR2(env, archivos, carpeta, nombreBase) {
  const keys = [];
  for (let i = 0; i < archivos.length && i < 5; i++) {
    const archivo = archivos[i];
    if (!archivo || archivo.size === 0) continue;
    const buffer = await archivo.arrayBuffer();
    const key = await subirImagenR2(env, buffer, carpeta, `${nombreBase}-${i}`);
    keys.push(key);
  }
  return keys;
}

function urlsPublicasR2(env, fotosKeysJson) {
  if (!fotosKeysJson) return [];
  try {
    const keys = JSON.parse(fotosKeysJson);
    if (!Array.isArray(keys)) return [];
    return keys.map((k) => urlPublicaR2(env, k)).filter(Boolean);
  } catch {
    return [];
  }
}

async function notificarReporteConvocatoria(env, convocatoria, motivo) {
  const textoMotivo = motivo ? ` Motivo: "${motivo}".` : '';
  const textoAviso = `To' Revuelto: se reportó la publicación "${convocatoria.titulo}" en Comunidad.${textoMotivo} Puedes revisarla y eliminarla desde el panel.`;
  await notificarDireccionGeneral(env, textoAviso, {
    asunto: "Reporte en Comunidad — To' Revuelto",
    tituloSuperior: 'Reporte recibido',
    tipoObjeto: 'convocatoria',
    objetoId: convocatoria.id,
  });
}

async function registrarAuditoria(env, actorUsername, accion, detalle) {
  try {
    await env.DB.prepare(
      `INSERT INTO auditoria (actor_username, accion, detalle) VALUES (?, ?, ?)`
    ).bind(actorUsername, accion, detalle || '').run();
  } catch (e) {
  }
}

async function otorgarPuntoInterno(env, username, puntos, motivo, otorgadoPor) {
  await env.DB.prepare(
    `INSERT INTO racha_puntos (username, puntos, motivo, otorgado_por) VALUES (?, ?, ?, ?)`
  ).bind(username, puntos, motivo || null, otorgadoPor).run();

  const totalRow = await env.DB.prepare(
    `SELECT COALESCE(SUM(puntos), 0) as total FROM racha_puntos WHERE username = ?`
  ).bind(username).first();

  const total = totalRow ? totalRow.total : 0;

  await notificarUsuarioCompleto(env, username, `To' Revuelto: se te ${puntos > 0 ? 'otorgó' : 'restó'} ${Math.abs(puntos)} punto${Math.abs(puntos) === 1 ? '' : 's'} en tu racha${motivo ? ` (${motivo})` : ''}. Total actual: ${total}.`, {
    link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin#rachas`,
    asunto: "Actualización de tu racha — To' Revuelto",
    tituloSuperior: 'Punto de racha',
    etiquetaBoton: 'Ver mi racha',
  });

  if (total <= -10) {
    const usuario = await obtenerUsuario(env, username);
    if (usuario && usuario.estado === 'activo') {
      usuario.estado = 'baneado';
      usuario.baneado_por_racha = true;
      await guardarUsuario(env, usuario);
      await registrarAuditoria(env, otorgadoPor, 'baneo_automatico_racha', `Usuario ${username} llego a ${total} puntos`);
      await notificarDireccionGeneral(env, `To' Revuelto: el usuario ${usuario.nombre_completo} (@${username}) fue baneado automáticamente por llegar a ${total} puntos en su racha.`, {
        asunto: "Baneo automático por racha — To' Revuelto",
        tituloSuperior: 'Baneo automático',
      });
    }
  }
  return total;
}

async function obtenerTotalRachaUsuario(env, username) {
  const row = await env.DB.prepare(
    `SELECT COALESCE(SUM(puntos), 0) as total FROM racha_puntos WHERE username = ?`
  ).bind(username).first();
  return row ? row.total : 0;
}

async function obtenerRankingVoluntarios(env, limite) {
  const rows = await env.DB.prepare(
    `SELECT username, SUM(puntos) as total FROM racha_puntos GROUP BY username ORDER BY total DESC LIMIT ?`
  ).bind(limite || 100).all();
  const resultados = [];
  for (const row of rows.results) {
    const usuario = await obtenerUsuario(env, row.username);
    if (usuario) {
      resultados.push({
        username: usuario.username,
        nombre_completo: usuario.nombre_completo,
        foto_url: urlPublicaR2(env, usuario.foto_key),
        total: row.total,
      });
    }
  }
  return resultados;
}

async function generarTemasSugeridosRD(env) {
  const respuestaNoticias = await fetch('https://news.google.com/rss/search?q=Rep%C3%BAblica%20Dominicana%20when%3A3d&hl=es-419&gl=DO&ceid=DO:es-419');
  const xmlNoticias = await respuestaNoticias.text();
  const titulares = Array.from(xmlNoticias.matchAll(/<title>((?:(?!<\/title>).)*)<\/title>/g))
    .map((m) => m[1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"'))
    .slice(1, 21);

  if (!titulares.length) throw new Error('No se encontraron noticias recientes de RD.');

  const prompt = `Eres editor de "To' Revuelto", un periódico juvenil dominicano hecho por y para jóvenes de República Dominicana, con voz y lenguaje dominicano auténtico. Aquí tienes titulares recientes de noticias de República Dominicana:\n${titulares.join('\n')}\n\nA partir de estos titulares, genera 5 ideas de temas de artículo para "To' Revuelto", tono fresco, dominicano y para Gen Z de acá. Cada tema debe ser una frase corta (máximo 15 palabras) que un redactor pueda usar como título de trabajo, y puede reflejar el habla dominicana natural sin exagerarla. Responde SOLO con un array JSON de 5 strings, sin explicaciones ni comillas markdown, ejemplo: ["tema 1", "tema 2", "tema 3", "tema 4", "tema 5"]`;

  const respuestaIA = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.OPENROUTER_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'openai/gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 400,
      temperature: 0.8,
    }),
  });

  if (!respuestaIA.ok) throw new Error('No se pudo generar temas con IA');

  const data = await respuestaIA.json();
  const contenido = data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content.trim() : null;
  if (!contenido) throw new Error('La IA no devolvió contenido válido');

  const limpio = contenido.replace(/```json/g, '').replace(/```/g, '').trim();
  let temas;
  try {
    temas = JSON.parse(limpio);
  } catch {
    throw new Error('La IA devolvió un formato inválido');
  }
  if (!Array.isArray(temas)) throw new Error('La IA devolvió un formato inválido');
  return temas.slice(0, 5).map((t) => String(t).slice(0, 150));
}

async function generarIdeaUnica(env, tipo, otorgadoPor) {
  const ideasExistentes = await env.DB.prepare(
    `SELECT contenido FROM ideas_generadas ORDER BY creado_en DESC LIMIT 40`
  ).all();
  const listaExistentes = ideasExistentes.results.map((r) => r.contenido);

  const prompt = `Eres redactor de "To' Revuelto", un periódico juvenil dominicano hecho por y para jóvenes de República Dominicana. Escribe siempre en dominicano auténtico, con el habla criolla de acá — puedes usar "vaina", "tato", "manín", "un chin", "guardar el hombro", "jevi", "eso ta' bueno", "dique" y giros dominicanos naturales, sin forzarlo ni exagerarlo, como hablaría un joven dominicano real, no un estereotipo. Genera UNA sola idea original y breve (maximo 2 frases) para un ${tipo === 'articulo' ? 'artículo de periódico' : tipo === 'redaccion' ? 'texto de redacción' : tipo === 'meme' ? 'meme' : tipo === 'historia' ? 'historia de Instagram' : 'post'}. Tono: fresco, actual, para Gen Z dominicana. NO repitas ninguna de estas ideas ya usadas: ${listaExistentes.slice(0, 25).join(' | ') || 'ninguna aun'}. Responde SOLO con la idea, sin comillas ni explicaciones adicionales.`;

  const respuesta = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.OPENROUTER_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'openai/gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 150,
      temperature: 0.9,
    }),
  });

  if (!respuesta.ok) {
    throw new Error('No se pudo generar la idea con IA');
  }

  const data = await respuesta.json();
  const idea = data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content.trim() : null;
  if (!idea) throw new Error('La IA no devolvio contenido valido');

  const normalizada = idea.toLowerCase().replace(/\s+/g, ' ').trim();
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(normalizada));
  const idea_hash = Array.from(new Uint8Array(hashBuffer), (b) => b.toString(16).padStart(2, '0')).join('');

  const yaExiste = await env.DB.prepare(`SELECT id FROM ideas_generadas WHERE idea_hash = ?`).bind(idea_hash).first();
  if (yaExiste) {
    return generarIdeaUnica(env, tipo, otorgadoPor);
  }

  await env.DB.prepare(`INSERT INTO ideas_generadas (idea_hash, contenido) VALUES (?, ?)`).bind(idea_hash, idea).run();
  return { idea, idea_hash };
}

function verificarWebhookWhatsapp(url, env) {
  const modo = url.searchParams.get('hub.mode');
  const tokenRecibido = url.searchParams.get('hub.verify_token');
  const challenge = url.searchParams.get('hub.challenge');

  if (modo === 'subscribe' && tokenRecibido === env.WHATSAPP_VERIFY_TOKEN && challenge) {
    return new Response(challenge, { status: 200, headers: { 'Content-Type': 'text/plain' } });
  }
  return new Response('Verificación fallida.', { status: 403 });
}

function sanearTextoParaPlantillaWhatsapp(texto) {
  return String(texto || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/ {2,}/g, ' ')
    .trim();
}

async function enviarMensajeWhatsapp(env, telefonoE164, texto, contexto) {

  if (!telefonoE164) return { ok: false, error: 'Sin teléfono registrado.' };
  if (!env.WHATSAPP_ACCESS_TOKEN || !env.WHATSAPP_PHONE_NUMBER_ID) {
    return { ok: false, error: 'WhatsApp no configurado (faltan variables).' };
  }

  const numeroSinMas = telefonoE164.replace('+', '');
  const textoSaneado = sanearTextoParaPlantillaWhatsapp(texto).slice(0, 1024);

  if (!textoSaneado) {
    return { ok: false, error: 'El mensaje quedó vacío después de limpiarlo.' };
  }

  try {
    const respuesta = await fetch(`https://graph.facebook.com/v22.0/${env.WHATSAPP_PHONE_NUMBER_ID}/messages`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.WHATSAPP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: numeroSinMas,
        type: 'template',
        template: {
          name: 'yeii',
          language: { code: 'es' },
          components: [
            {
              type: 'body',
              parameters: [
                { type: 'text', text: textoSaneado },
              ],
            },
          ],
        },
      }),
    });

    const data = await respuesta.json().catch(() => ({}));

    if (!respuesta.ok) {
      const mensajeCorto = (data && data.error && data.error.message) || `HTTP ${respuesta.status}`;
      const detalleExtra = (data && data.error && data.error.error_data && data.error.error_data.details) || '';
      const detalleError = detalleExtra ? `${mensajeCorto} — ${detalleExtra}` : mensajeCorto;
      await registrarMensajeWhatsapp(env, 'saliente', telefonoE164, contexto, texto, null, 'error', JSON.stringify(data && data.error ? data.error : data));
      return { ok: false, error: detalleError };
    }

    const wamid = data && data.messages && data.messages[0] ? data.messages[0].id : null;
    await registrarMensajeWhatsapp(env, 'saliente', telefonoE164, contexto, texto, wamid, 'enviado', null);
    return { ok: true, wamid };
  } catch (error) {
    await registrarMensajeWhatsapp(env, 'saliente', telefonoE164, contexto, texto, null, 'error', String(error));
    return { ok: false, error: String(error) };
  }
}

async function registrarMensajeWhatsapp(env, direccion, telefono, contexto, mensaje, wamid, estado, errorDetalle) {
  try {
    await env.DB.prepare(
      `INSERT INTO whatsapp_mensajes (direccion, telefono, username, tipo_objeto, objeto_id, mensaje, wamid, estado, error_detalle)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      direccion, telefono,
      (contexto && contexto.username) || null,
      (contexto && contexto.tipo_objeto) || null,
      (contexto && contexto.objeto_id) || null,
      mensaje || null, wamid || null, estado, errorDetalle || null
    ).run();
  } catch (e) {

  }
}

async function listarUsuariosPorRoles(env, roles) {
  const todos = await listarUsuarios(env);
  return todos.filter((u) => roles.includes(u.rol) && u.estado === 'activo');
}

async function notificarUsuarioCompleto(env, usernameDestino, texto, opciones) {
  const destino = await obtenerUsuario(env, usernameDestino);
  if (!destino) return;
  const enlace = (opciones && opciones.link) || `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin`;
  const asunto = (opciones && opciones.asunto) || "Nueva notificación de To' Revuelto";
  const etiquetaBoton = (opciones && opciones.etiquetaBoton) || 'Ver en el panel';
  const tituloSuperior = (opciones && opciones.tituloSuperior) || 'Notificación';

  if (destino.telefono) {
    await enviarMensajeWhatsapp(env, destino.telefono, `${texto} ${enlace}`, { username: usernameDestino, tipo_objeto: (opciones && opciones.tipoObjeto) || null, objeto_id: (opciones && opciones.objetoId) || null });
  }
  if (destino.correo) {
    await enviarCorreoBrevo(env, destino.correo, destino.nombre_completo, asunto, texto, enlace, etiquetaBoton, tituloSuperior);
  }
  if (destino.telefono) {
    await enviarSmsBrevo(env, destino.telefono, `${texto} ${enlace}`, destino.correo, destino.nombre_completo);
  }
}

async function notificarDireccionGeneral(env, texto, opciones) {
  const directivos = await listarUsuariosPorRoles(env, [ROLES.DIRECTOR_GENERAL, ROLES.SUBDIRECTORA_GENERAL]);
  for (const d of directivos) {
    await notificarUsuarioCompleto(env, d.username, texto, opciones);
  }
}

async function agregarSuscriptor(env, correo) {
  await env.DB.prepare(`INSERT OR IGNORE INTO suscriptores (correo) VALUES (?)`).bind(correo).run();
}

async function notificarSuscriptoresNuevaPublicacion(env, titulo, tipoTexto, urlDestino) {
  const rows = await env.DB.prepare(`SELECT correo FROM suscriptores ORDER BY id ASC LIMIT 5000`).all();
  const suscriptores = rows.results || [];
  if (!suscriptores.length) return;
  const asunto = `Nuevo ${tipoTexto} en To' Revuelto: ${titulo}`;
  const texto = `Se publicó algo nuevo en To' Revuelto — ${tipoTexto}: "${titulo}". Entra para verlo completo.`;
  for (const s of suscriptores) {
    await enviarCorreoBrevo(env, s.correo, null, asunto, texto, urlDestino, 'Ver ahora', `Nuevo ${tipoTexto}`);
  }
}

async function notificarTareaPorWhatsapp(env, usernameDestino, texto, tipoObjeto, objetoId, linkPanel) {
  const destino = await obtenerUsuario(env, usernameDestino);
  if (!destino) return;
  const enlacePanel = linkPanel || `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin`;

  if (destino.telefono) {
    await enviarMensajeWhatsapp(env, destino.telefono, texto, { username: usernameDestino, tipo_objeto: tipoObjeto, objeto_id: objetoId });
  }
  if (destino.correo) {
    await enviarCorreoBrevo(env, destino.correo, destino.nombre_completo, "Nueva tarea en To' Revuelto", texto, enlacePanel);
  }
  if (destino.telefono) {
    await enviarSmsBrevo(env, destino.telefono, `${texto} ${enlacePanel}`, destino.correo, destino.nombre_completo);
  }
}

function plantillaCorreoHtml(nombreDestino, texto, link, etiquetaBoton, tituloSuperior) {
  const botonTexto = etiquetaBoton || 'Ver en el panel';
  const tituloTexto = tituloSuperior || 'Notificación';
  return `<!DOCTYPE html>
<html lang="es">
<body style="margin:0; padding:0; background-color:#030509; font-family: Arial, Helvetica, sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#030509; padding: 32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width: 480px; background-color:#0d111c; border-radius: 24px; border: 1px solid rgba(255,255,255,0.08); border-top: 1px solid rgba(255,255,255,0.18); overflow: hidden;">
          <tr>
            <td style="background: linear-gradient(180deg, rgba(117,188,225,0.10) 0%, rgba(13,17,28,0) 100%); padding: 32px 32px 16px 32px; text-align:center;">
              <div style="display:inline-block; background: linear-gradient(135deg, #F7D52F 0%, #75BCE1 100%); padding: 2px; border-radius: 9999px;">
                <div style="background:#030509; border-radius: 9999px; padding: 10px 22px;">
                  <span style="color:#ffffff; font-size:18px; font-weight:800; letter-spacing: -0.5px;">TO'<span style="color:#75BCE1;">REVUELTO</span></span>
                </div>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding: 8px 32px 12px 32px;">
              <div style="background: rgba(255,255,255,0.035); border: 1px solid rgba(255,255,255,0.07); border-radius: 18px; padding: 24px;">
                <p style="color:#9ca3af; font-size:13px; margin: 0 0 6px 0; text-transform:uppercase; letter-spacing:0.05em;">${escapeHtml(tituloTexto)}</p>
                <p style="color:#9ca3af; font-size:14px; margin: 0 0 10px 0;">Hola${nombreDestino ? ', ' + escapeHtml(nombreDestino) : ''}</p>
                <p style="color:#ffffff; font-size:16px; line-height:1.6; margin: 0 0 22px 0;">${escapeHtml(texto)}</p>
                <table role="presentation" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="border-radius: 9999px; background-color:#F7D52F;">
                      <a href="${escapeHtml(link)}" target="_blank" style="display:inline-block; padding: 14px 28px; color:#030509; font-weight:700; font-size:14px; text-decoration:none; border-radius:9999px;">${escapeHtml(botonTexto)}</a>
                    </td>
                  </tr>
                </table>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 32px 24px 32px; border-top: 1px solid rgba(255,255,255,0.06);">
              <p style="color:#4b5563; font-size:11px; margin:0; text-align:center;">To' Revuelto — mensaje automático de notificación interna.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

async function enviarCorreoBrevo(env, correoDestino, nombreDestino, asunto, texto, link, etiquetaBoton, tituloSuperior) {
  if (!env.BREVO_API_KEY) return { ok: false, error: 'Brevo no configurado.' };
  const enlaceFinal = link || `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin`;
  try {
    const respuesta = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': env.BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        sender: { name: "To' Revuelto", email: 'torevueltopj@gmail.com' },
        to: [{ email: correoDestino, name: nombreDestino || correoDestino }],
        subject: asunto,
        htmlContent: plantillaCorreoHtml(nombreDestino, texto, enlaceFinal, etiquetaBoton, tituloSuperior),
      }),
    });
    if (!respuesta.ok) {
      const data = await respuesta.json().catch(() => ({}));
      return { ok: false, error: (data && data.message) || `HTTP ${respuesta.status}` };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

async function actualizarContactoBrevo(env, correoDestino, nombreCompleto, telefonoE164) {
  if (!env.BREVO_API_KEY || !correoDestino) return { ok: false };
  try {
    const respuesta = await fetch('https://api.brevo.com/v3/contacts', {
      method: 'POST',
      headers: {
        'api-key': env.BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        email: correoDestino,
        attributes: {
          FIRSTNAME: nombreCompleto || correoDestino,
          LASTNAME: "Revuelto",
          SMS: telefonoE164 || undefined,
        },
        updateEnabled: true,
      }),
    });
    if (!respuesta.ok && respuesta.status !== 400) {
      const data = await respuesta.json().catch(() => ({}));
      return { ok: false, error: (data && data.message) || `HTTP ${respuesta.status}` };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

async function enviarSmsBrevo(env, telefonoE164, texto, correoDestino, nombreCompleto) {
  if (!env.BREVO_API_KEY) return { ok: false, error: 'Brevo no configurado.' };
  if (!telefonoE164) return { ok: false, error: 'Sin teléfono registrado.' };
  try {
    if (correoDestino) {
      await actualizarContactoBrevo(env, correoDestino, nombreCompleto, telefonoE164);
    }
    const respuesta = await fetch('https://api.brevo.com/v3/transactionalSMS/sms', {
      method: 'POST',
      headers: {
        'api-key': env.BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        sender: 'ToRevuelto',
        recipient: telefonoE164.replace('+', ''),
        content: texto.slice(0, 160),
        type: 'transactional',
      }),
    });
    if (!respuesta.ok) {
      const data = await respuesta.json().catch(() => ({}));
      return { ok: false, error: (data && data.message) || `HTTP ${respuesta.status}` };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

async function verificarFirmaWhatsapp(request, appSecret, bodyCrudo) {
  const encabezado = request.headers.get('X-Hub-Signature-256') || '';
  const firmaRecibida = encabezado.startsWith('sha256=') ? encabezado.slice(7) : '';
  if (!firmaRecibida || !appSecret) return false;

  const encoder = new TextEncoder();
  const clave = await crypto.subtle.importKey(
    'raw', encoder.encode(appSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const firmaCalculadaBuffer = await crypto.subtle.sign('HMAC', clave, encoder.encode(bodyCrudo));
  const firmaCalculadaHex = Array.from(new Uint8Array(firmaCalculadaBuffer), (b) => b.toString(16).padStart(2, '0')).join('');

  return timingSafeEqual(firmaCalculadaHex, firmaRecibida);
}

async function manejarWebhookWhatsappEntrante(request, env) {
  const bodyCrudo = await request.text();

  const firmaValida = await verificarFirmaWhatsapp(request, env.WHATSAPP_APP_SECRET, bodyCrudo);
  if (!firmaValida) {

    return new Response('OK', { status: 200 });
  }

  let body;
  try {
    body = JSON.parse(bodyCrudo);
  } catch {
    return new Response('OK', { status: 200 });
  }

  try {
    const entradas = body.entry || [];
    for (const entrada of entradas) {
      const cambios = entrada.changes || [];
      for (const cambio of cambios) {
        const valor = cambio.value || {};
        const mensajes = valor.messages || [];
        for (const msg of mensajes) {
          const telefono = msg.from ? `+${msg.from}` : null;
          const textoRecibido = msg.text ? msg.text.body : null;
          await registrarMensajeWhatsapp(env, 'entrante', telefono || 'desconocido', null, textoRecibido, msg.id, 'enviado', null);
        }
      }
    }
  } catch (e) {

  }

  return new Response('OK', { status: 200 });
}

function estilosBase() {
  return `
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Syne:wght@500;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.tailwindcss.com"><\/script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: { sans: ['Inter', 'sans-serif'], display: ['Syne', 'sans-serif'] },
                    colors: { brand: { yellow: '#F7D52F', blue: '#75BCE1', dark: '#030509' } },
                    animation: {
                        'float-slow': 'float 20s ease-in-out infinite',
                        'float-medium': 'float 15s ease-in-out infinite reverse',
                        'float-fast': 'float 10s ease-in-out infinite',
                    },
                    keyframes: {
                        float: {
                            '0%, 100%': { transform: 'translate(0, 0) scale(1)' },
                            '33%': { transform: 'translate(5%, -5%) scale(1.1)' },
                            '66%': { transform: 'translate(-5%, 5%) scale(0.95)' },
                        }
                    }
                }
            }
        }
    <\/script>
    <style>
        html { background-color: #030509; }
        body { background-color: #030509; color: #ffffff; overflow-x: hidden; min-height: 100vh; min-height: 100dvh; }
        .bg-orb { position: absolute; border-radius: 50%; filter: blur(120px); opacity: 0.6; z-index: -1; mix-blend-mode: screen; }
        .ultra-glass {
            background: rgba(13, 17, 28, 0.4);
            backdrop-filter: blur(32px); -webkit-backdrop-filter: blur(32px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-top: 1px solid rgba(255, 255, 255, 0.25);
            border-left: 1px solid rgba(255, 255, 255, 0.15);
            box-shadow: 0 30px 60px -12px rgba(0, 0, 0, 0.6), inset 0 0 20px rgba(255, 255, 255, 0.03);
            border-radius: 2rem;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }
        .ultra-glass-nav {
            background: rgba(13, 17, 28, 0.6);
            backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
        }
        .glass-card-interactive:hover {
            transform: translateY(-8px) scale(1.01);
            background: rgba(20, 26, 40, 0.5);
            border-color: rgba(247, 213, 47, 0.3);
            box-shadow: 0 40px 70px -15px rgba(0, 0, 0, 0.8), 0 0 30px rgba(247, 213, 47, 0.1);
        }
        .text-fluid { background: linear-gradient(135deg, #ffffff 0%, #75BCE1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .text-brand-gradient { background: linear-gradient(135deg, #F7D52F 0%, #75BCE1 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .glass-img-wrapper { position: relative; border-radius: 1.25rem; overflow: hidden; }
        .glass-img-wrapper::after { content: ''; position: absolute; inset: 0; border-radius: 1.25rem; border: 1px solid rgba(255, 255, 255, 0.1); pointer-events: none; }
        ::-webkit-scrollbar { width: 10px; }
        ::-webkit-scrollbar-track { background: #030509; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 20px; border: 3px solid #030509; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.3); }
        .fade-up { opacity: 0; transform: translateY(30px); transition: opacity 0.8s ease-out, transform 0.8s ease-out; }
        .fade-up.visible { opacity: 1; transform: translateY(0); }

        .logo-neon-wrap { position: relative; display: inline-flex; align-items: center; justify-content: center; }
        .logo-neon-glow {
            position: absolute; inset: -30%; border-radius: 9999px;
            background: radial-gradient(circle, rgba(117,188,225,0.55) 0%, rgba(157,78,221,0.35) 45%, transparent 70%);
            filter: blur(30px); z-index: 0; animation: pulse-neon 3.5s ease-in-out infinite;
        }
        @keyframes pulse-neon { 0%, 100% { opacity: 0.7; transform: scale(1);} 50% { opacity: 1; transform: scale(1.08);} }
        .logo-neon-img { position: relative; z-index: 1; filter: drop-shadow(0 0 18px rgba(117,188,225,0.8)) drop-shadow(0 0 36px rgba(157,78,221,0.5)); }

        /* Burbujas flotantes de directiva */
        .directiva-bubble {
            border-radius: 9999px; overflow: hidden; position: relative;
            aspect-ratio: 1 / 1; cursor: pointer;
            border: 2px solid rgba(255,255,255,0.15);
            box-shadow: 0 20px 40px -10px rgba(0,0,0,0.6);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), border-color 0.3s;
        }
        .directiva-bubble:hover { transform: translateY(-10px) scale(1.05); border-color: rgba(247,213,47,0.6); }
        .directiva-bubble img { width: 100%; height: 100%; object-fit: cover; }
        .directiva-float-1 { animation: float 9s ease-in-out infinite; }
        .directiva-float-2 { animation: float 11s ease-in-out infinite reverse; }
        .directiva-float-3 { animation: float 13s ease-in-out infinite; }

        /* Modal generico */
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            width: 100vw; height: 100dvh;
            background: rgba(3,5,9,0); backdrop-filter: blur(0px); -webkit-backdrop-filter: blur(0px);
            display: none; align-items: flex-start; justify-content: center; z-index: 999;
            overflow-y: auto; -webkit-overflow-scrolling: touch;
            padding: 0 1rem;
            transition: background-color 0.32s cubic-bezier(0.16, 1, 0.3, 1), backdrop-filter 0.32s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .modal-overlay.activo { display: flex; }
        .modal-overlay.activo.entrando {
            background: rgba(3,5,9,0.8); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
        }
        .modal-box {
            max-width: 32rem; width: 100%; max-height: none; overflow-y: visible;
            overscroll-behavior: contain; position: relative;
            padding-bottom: 2rem; -webkit-overflow-scrolling: touch;
            margin-top: calc(7rem + env(safe-area-inset-top, 0px));
            margin-bottom: 2rem;
            opacity: 0; transform: translateY(18px) scale(0.96);
            transition: opacity 0.32s cubic-bezier(0.16, 1, 0.3, 1), transform 0.32s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .modal-overlay.activo.entrando .modal-box {
            opacity: 1; transform: translateY(0) scale(1);
        }
        .modal-cerrar-btn {
            position: sticky; top: 0; left: 100%; width: 2.25rem; height: 2.25rem; border-radius: 9999px;
            background: rgba(255,255,255,0.1); display: flex; align-items: center; justify-content: center;
            color: white; margin-bottom: -2.25rem; z-index: 10; flex-shrink: 0;
            transition: background-color 0.25s ease, transform 0.25s ease;
        }
        .modal-cerrar-btn:hover { background: rgba(255,255,255,0.2); transform: rotate(90deg); }
        @media (max-width: 640px) {
            .modal-box { margin-top: calc(5.5rem + env(safe-area-inset-top, 0px)); }
        }
        @media (prefers-reduced-motion: reduce) {
            .modal-overlay, .modal-box, .modal-cerrar-btn { transition: none !important; }
        }

        /* Notificaciones toast */
        #toast-container { position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 200; display: flex; flex-direction: column; gap: 0.75rem; max-width: calc(100vw - 2rem); }
        .toast {
            padding: 1rem 1.25rem; border-radius: 1rem; font-size: 0.875rem; font-weight: 500;
            display: flex; align-items: center; gap: 0.75rem; min-width: 260px;
            animation: toast-in 0.3s ease-out;
        }
        @keyframes toast-in { from { opacity: 0; transform: translateX(30px);} to { opacity: 1; transform: translateX(0);} }
        .toast-exito { border: 1px solid rgba(247,213,47,0.4); }
        .toast-error { border: 1px solid rgba(239,68,68,0.5); }
        .toast-info { border: 1px solid rgba(117,188,225,0.4); }

        .btn-compartir {
            display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem;
            border-radius: 9999px; border: 1px solid rgba(255,255,255,0.15);
            background: rgba(255,255,255,0.05); font-size: 0.8rem; font-weight: 600;
            transition: all 0.3s;
        }
        .btn-compartir:hover { background: rgba(247,213,47,0.15); border-color: rgba(247,213,47,0.5); color: #F7D52F; }

        /* Campos de formulario — diseño glass consistente en todo el sitio */
        .campo-form {
            width: 100%;
            box-sizing: border-box;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 1rem;
            padding: 0.85rem 1.1rem;
            color: #ffffff;
            font-size: 0.9rem;
            font-family: 'Inter', sans-serif;
            transition: border-color 0.3s ease, background-color 0.3s ease, box-shadow 0.3s ease, transform 0.2s ease;
            appearance: none;
            -webkit-appearance: none;
        }
        .campo-form::placeholder { color: rgba(255,255,255,0.35); }
        .campo-form:hover { border-color: rgba(255,255,255,0.2); background: rgba(255,255,255,0.06); }
        .campo-form:focus {
            outline: none;
            border-color: rgba(117,188,225,0.6);
            background: rgba(255,255,255,0.06);
            box-shadow: 0 0 0 4px rgba(117,188,225,0.12), 0 8px 20px -8px rgba(117,188,225,0.3);
            transform: translateY(-1px);
        }
        .campo-form:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        textarea.campo-form { resize: vertical; min-height: 90px; line-height: 1.5; }
        select.campo-form {
            cursor: pointer;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8' fill='none'%3E%3Cpath d='M1 1.5L6 6.5L11 1.5' stroke='%2375BCE1' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 1rem center;
            padding-right: 2.5rem;
        }
        select.campo-form option { background: #0d111c; color: #ffffff; }
        input[type="date"].campo-form, input[type="datetime-local"].campo-form {
            color-scheme: dark;
        }
        input[type="file"].campo-form {
            padding: 0.65rem 1rem;
            cursor: pointer;
        }
        input[type="file"].campo-form::file-selector-button {
            background: rgba(247,213,47,0.15);
            color: #F7D52F;
            border: none;
            border-radius: 0.6rem;
            padding: 0.5rem 0.9rem;
            font-weight: 700;
            font-size: 0.75rem;
            margin-right: 0.85rem;
            cursor: pointer;
            transition: background-color 0.25s ease;
        }
        input[type="file"].campo-form::file-selector-button:hover { background: rgba(247,213,47,0.28); }
        .campo-form:invalid:not(:placeholder-shown):not(:focus) { border-color: rgba(239,68,68,0.4); }

        @media (max-width: 640px) {
            .ultra-glass { border-radius: 1.5rem; }
            .campo-form { padding: 0.75rem 1rem; font-size: 16px; } /* 16px evita zoom automático en iOS */
        }
    </style>
  `;
}

function scriptToastYModal() {
  return `
    <div id="toast-container"></div>
    <script>
      function mostrarToast(mensaje, tipo) {
        tipo = tipo || 'info';
        const cont = document.getElementById('toast-container');
        const el = document.createElement('div');
        el.className = 'toast ultra-glass toast-' + tipo;
        const icono = tipo === 'exito' ? 'fa-circle-check' : tipo === 'error' ? 'fa-circle-exclamation' : 'fa-circle-info';
        const color = tipo === 'exito' ? 'text-brand-yellow' : tipo === 'error' ? 'text-red-400' : 'text-brand-blue';
        el.innerHTML = '<i class="fa-solid ' + icono + ' ' + color + '"></i><span>' + mensaje + '</span>';
        cont.appendChild(el);
        setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, 4000);
      }
      const _origenModales = new Map();
      function abrirModal(id) {
        const modal = document.getElementById(id);
        if (!modal) return;
        if (modal.parentNode !== document.body) {
          _origenModales.set(id, { padre: modal.parentNode, siguiente: modal.nextSibling });
          document.body.appendChild(modal);
        }
        modal.classList.remove('saliendo');
        modal.classList.add('activo');
        document.body.style.overflow = 'hidden';
        requestAnimationFrame(() => {
          requestAnimationFrame(() => { modal.classList.add('entrando'); });
        });
      }
      function cerrarModal(id) {
        const modal = document.getElementById(id);
        if (!modal) return;
        modal.classList.remove('entrando');
        modal.classList.add('saliendo');
        document.body.style.overflow = '';
        const terminar = () => {
          modal.classList.remove('activo', 'saliendo');
          const origen = _origenModales.get(id);
          if (origen && origen.padre) {
            origen.padre.insertBefore(modal, origen.siguiente);
            _origenModales.delete(id);
          }
        };
        modal.addEventListener('transitionend', terminar, { once: true });
        setTimeout(terminar, 400); // salvaguarda por si transitionend no dispara
      }
    <\/script>
  `;
}

function fondoOrbes() {
  return `
    <div style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; overflow: hidden; pointer-events: none; z-index: -1; background-color: #030509; isolation: isolate;">
        <div class="bg-orb bg-brand-blue w-[60vw] h-[60vw] md:w-[40vw] md:h-[40vw] -top-[10%] -left-[10%] animate-float-slow rounded-full opacity-40"></div>
        <div class="bg-orb bg-brand-yellow w-[50vw] h-[50vw] md:w-[35vw] md:h-[35vw] top-[20%] -right-[5%] animate-float-medium rounded-full opacity-30"></div>
        <div class="bg-orb bg-[#9d4edd] w-[70vw] h-[70vw] md:w-[45vw] md:h-[45vw] -bottom-[20%] left-[10%] animate-float-fast rounded-full opacity-40"></div>
    </div>
  `;
}

function navegacionPublica(env, activo) {
  const links = [
    { href: '/', texto: 'Inicio', id: 'inicio' },
    { href: '/secciones', texto: 'Secciones', id: 'secciones' },
    { href: '/directiva', texto: 'Directiva', id: 'directiva' },
    { href: '/voluntariado', texto: 'Voluntariado', id: 'voluntariado' },
    { href: '/eventos', texto: 'Eventos', id: 'eventos' },
    { href: '/comunidad', texto: 'Comunidad', id: 'comunidad' },
  ];
  const linksHtml = links.map((l) => {
    const esActivo = l.id === activo;
    return `<a href="${l.href}" class="px-5 py-2 rounded-full text-sm font-medium transition-all ${esActivo ? 'text-black bg-white shadow-lg shadow-white/20' : 'text-gray-300 hover:text-white hover:bg-white/10'}">${l.texto}</a>`;
  }).join('');

  return `
    <div class="fixed top-6 left-0 right-0 z-50 px-4 md:px-8 flex justify-center w-full">
        <nav class="ultra-glass-nav rounded-full px-4 md:px-6 py-3 md:py-4 flex justify-between items-center w-full max-w-6xl mx-auto transition-all duration-300" id="navbar">
            <a href="/" class="flex-shrink-0 flex items-center cursor-pointer group">
                <div class="logo-neon-wrap w-10 h-10 mr-2 md:mr-3">
                    <div class="logo-neon-glow"></div>
                    <img src="${escapeHtml(env.LOGO_URL)}" alt="Logo To' Revuelto" class="logo-neon-img w-9 h-9 object-contain">
                </div>
                <div class="font-display font-bold text-lg md:text-xl tracking-tight hidden sm:block">
                    <span class="text-white">TO'</span><span class="text-brand-blue">REVUELTO</span>
                </div>
            </a>
            <div class="hidden md:flex items-center space-x-1 p-1 bg-white/5 rounded-full border border-white/10">
                ${linksHtml}
            </div>
            <div class="flex items-center space-x-2 md:space-x-3">
                <button onclick="toggleMenuMovil()" id="btn-menu-movil" class="md:hidden w-10 h-10 rounded-full bg-white/10 text-white border border-white/20 flex items-center justify-center relative overflow-hidden">
                    <i class="fa-solid fa-bars" id="icono-menu-movil" style="transition: transform 0.3s ease, opacity 0.2s ease;"></i>
                </button>
            </div>
        </nav>
        <div id="menu-movil" class="absolute top-20 left-4 right-4 ultra-glass rounded-3xl p-4 flex flex-col gap-2 md:hidden" style="opacity:0; transform: translateY(-12px) scale(0.98); pointer-events:none; visibility:hidden; transition: opacity 0.25s ease, transform 0.25s cubic-bezier(0.175,0.885,0.32,1.275), visibility 0.25s;">
            ${links.map((l) => `<a href="${l.href}" class="px-4 py-3 rounded-2xl text-sm font-medium text-gray-200 hover:bg-white/10 transition-all">${l.texto}</a>`).join('')}
        </div>
    </div>
    <script>
        function toggleMenuMovil() {
            const menu = document.getElementById('menu-movil');
            const icono = document.getElementById('icono-menu-movil');
            const abierto = menu.style.visibility === 'visible';
            if (abierto) {
                menu.style.opacity = '0';
                menu.style.transform = 'translateY(-12px) scale(0.98)';
                menu.style.pointerEvents = 'none';
                setTimeout(() => { menu.style.visibility = 'hidden'; }, 250);
                icono.className = 'fa-solid fa-bars';
            } else {
                menu.style.visibility = 'visible';
                menu.style.pointerEvents = 'auto';
                requestAnimationFrame(() => {
                    menu.style.opacity = '1';
                    menu.style.transform = 'translateY(0) scale(1)';
                });
                icono.className = 'fa-solid fa-xmark';
            }
        }
    <\/script>
  `;
}

function bloqueSuscripcion() {
  return `
    <section class="fade-up">
        <div class="ultra-glass p-8 md:p-10 text-center">
            <i class="fa-solid fa-bell text-4xl text-brand-yellow mb-4"></i>
            <h2 class="font-display text-2xl md:text-3xl font-bold text-white mb-2">No te pierdas nada</h2>
            <p class="text-gray-400 mb-6 max-w-md mx-auto">Recibe un correo directo cada vez que publiquemos un artículo, evento, MUN o voluntariado nuevo.</p>
            <form id="form-suscripcion" class="flex flex-col sm:flex-row gap-3 max-w-md mx-auto">
                <input required type="email" name="correo" placeholder="tu@correo.com" class="flex-grow bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                <button type="submit" class="px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black whitespace-nowrap">Suscribirme</button>
            </form>
        </div>
    </section>
    <script>
        document.getElementById('form-suscripcion').addEventListener('submit', async (e) => {
            e.preventDefault();
            const correo = e.target.correo.value.trim();
            try {
                const r = await fetch('/api/publico/suscribirse', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ correo }) });
                const data = await r.json();
                if (data.ok) { mostrarToast('¡Listo! Te avisaremos por correo', 'exito'); e.target.reset(); }
                else { mostrarToast(data.error || 'Error al suscribirte', 'error'); }
            } catch (err) { mostrarToast('Error de conexión', 'error'); }
        });
    <\/script>
  `;
}

function footerPublico() {
  return `
    <script>
        const observerOptions = { root: null, rootMargin: '0px', threshold: 0.1 };
        const observer = new IntersectionObserver((entries, obs) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) { entry.target.classList.add('visible'); obs.unobserve(entry.target); }
            });
        }, observerOptions);
        document.querySelectorAll('.fade-up').forEach((el) => observer.observe(el));

        let ultimoConteo = document.querySelectorAll('[data-articulo-id]').length;
        setInterval(async () => {
            try {
                const resp = await fetch('/api/publico/conteo-articulos');
                const data = await resp.json();
                if (data.ok && data.total !== ultimoConteo) { window.location.reload(); }
            } catch (e) {}
        }, 45000);
    <\/script>
  `;
}

function paginaBase(env, { titulo, activo, contenido, descripcion = '', urlCanonica = '', imagenOg = '', tipoOg = 'website', datosEstructurados = '' }) {
  const siteUrl = String(env.PUBLIC_SITE_URL || 'https://web.torevueltopj.workers.dev').replace(/\/$/, '');
  const descripcionFinal = descripcion || "To' Revuelto es el periódico juvenil digital de República Dominicana, hecho por y para jóvenes dominicanos. Noticias, voluntariado, eventos y comunidad.";
  const tituloCompleto = titulo === 'Inicio' ? "To' Revuelto — Periódico Juvenil Dominicano" : `${escapeHtml(titulo)} | To' Revuelto`;
  const canonicaFinal = urlCanonica ? `${siteUrl}${urlCanonica}` : siteUrl;
  const imagenOgFinal = imagenOg || env.LOGO_URL;

  return `<!DOCTYPE html>
<html lang="es" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <title>${tituloCompleto}</title>
    <meta name="description" content="${escapeHtml(descripcionFinal)}">
    <meta name="robots" content="index, follow">
    <link rel="canonical" href="${escapeHtml(canonicaFinal)}">
    <meta name="google-site-verification" content="Dx1UQ57dtTemgpPM4nhPqtppkGOYefRK1a_ef7OH8V4" />

    <meta property="og:type" content="${escapeHtml(tipoOg)}">
    <meta property="og:title" content="${escapeHtml(tituloCompleto)}">
    <meta property="og:description" content="${escapeHtml(descripcionFinal)}">
    <meta property="og:url" content="${escapeHtml(canonicaFinal)}">
    <meta property="og:image" content="${escapeHtml(imagenOgFinal)}">
    <meta property="og:site_name" content="To' Revuelto">
    <meta property="og:locale" content="es_DO">

    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${escapeHtml(tituloCompleto)}">
    <meta name="twitter:description" content="${escapeHtml(descripcionFinal)}">
    <meta name="twitter:image" content="${escapeHtml(imagenOgFinal)}">

    <link rel="icon" href="${escapeHtml(env.LOGO_URL)}" type="image/png">
    <link rel="apple-touch-icon" href="${escapeHtml(env.LOGO_URL)}">
    <link rel="prefetch" href="/">
    <link rel="prefetch" href="/secciones">
    <link rel="prefetch" href="/directiva">
    <link rel="prefetch" href="/voluntariado">
    <link rel="prefetch" href="/eventos">
    ${datosEstructurados}
    ${estilosBase()}
</head>
<body class="relative min-h-screen antialiased selection:bg-brand-yellow selection:text-black">
    ${fondoOrbes()}
    ${navegacionPublica(env, activo)}
    <main class="pt-32 md:pt-40 pb-20 px-4 sm:px-6 lg:px-8 max-w-[1400px] mx-auto space-y-12 md:space-y-20">
        ${contenido}
    </main>
    ${footerPublico()}
    ${scriptToastYModal()}
</body>
</html>`;
}

function botonCompartir(env, slug, titulo) {
  const url = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/articulo/${slug}`;
  return `
    <button type="button" class="btn-compartir" onclick="compartirArticulo('${escapeHtml(url)}', '${escapeHtml(titulo).replace(/'/g, "&#39;")}')">
        <i class="fa-solid fa-share-nodes"></i> Compartir
    </button>
  `;
}

function scriptCompartir() {
  return `
    <script>
        async function compartirArticulo(url, titulo) {
            if (navigator.share) {
                try { await navigator.share({ title: titulo, url: url }); return; } catch (e) {}
            }
            try {
                await navigator.clipboard.writeText(url);
                mostrarToast('Enlace copiado al portapapeles', 'exito');
            } catch (e) {
                mostrarToast('No se pudo copiar el enlace', 'error');
            }
        }
    <\/script>
  `;
}

function tarjetaArticulo(env, articulo) {
  const portada = urlPublicaR2(env, articulo.portada_key) || urlPublicaR2(env, articulo.diseno_key);
  return `
    <article data-articulo-id="${articulo.id}" class="ultra-glass glass-card-interactive p-3 flex flex-col group cursor-pointer relative overflow-hidden">
        <a href="/articulo/${escapeHtml(articulo.slug)}" class="glass-img-wrapper h-40 w-full mb-4 block">
            ${portada ? `<img src="${escapeHtml(portada)}" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" alt="${escapeHtml(articulo.titulo)}">` : `<div class="w-full h-full bg-white/5 flex items-center justify-center"><i class="fa-solid fa-newspaper text-3xl text-white/20"></i></div>`}
        </a>
        <div class="px-3 pb-3 flex flex-col flex-grow justify-between">
            <div>
                <span class="text-brand-blue text-xs font-bold uppercase mb-2 block tracking-wider">${escapeHtml(articulo.seccion)}</span>
                <a href="/articulo/${escapeHtml(articulo.slug)}">
                    <h3 class="font-display text-xl font-bold text-white leading-tight hover:text-brand-yellow transition-colors">${escapeHtml(articulo.titulo)}</h3>
                </a>
            </div>
            <div class="mt-4 flex justify-between items-center text-xs text-gray-500">
                <span><i class="fa-regular fa-clock mr-1"></i> ${escapeHtml((articulo.fecha_publicacion || '').slice(0, 10))}</span>
                ${botonCompartir(env, articulo.slug, articulo.titulo)}
            </div>
        </div>
    </article>
  `;
}

async function paginaInicio(env) {
  const ultimos = await env.DB.prepare(
    `SELECT * FROM articulos WHERE estado = 'publicado' ORDER BY fecha_publicacion DESC LIMIT 12`
  ).all();

  const articulos = ultimos.results || [];
  const destacado = articulos[0];
  const resto = articulos.slice(1);

  const heroHtml = destacado ? `
    <section class="fade-up">
        <article class="ultra-glass glass-card-interactive p-3 md:p-6 flex flex-col lg:flex-row gap-6 relative group cursor-pointer overflow-hidden min-h-[400px] md:min-h-[500px]">
            <div class="absolute -top-32 -left-32 w-64 h-64 bg-brand-blue/30 rounded-full blur-[80px] pointer-events-none"></div>
            <a href="/articulo/${escapeHtml(destacado.slug)}" class="w-full lg:w-3/5 lg:order-2 glass-img-wrapper h-[220px] md:h-[300px] lg:h-auto block">
                ${urlPublicaR2(env, destacado.portada_key) ? `<img src="${escapeHtml(urlPublicaR2(env, destacado.portada_key))}" alt="${escapeHtml(destacado.titulo)}" class="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110">` : `<div class="w-full h-full bg-white/5 flex items-center justify-center"><i class="fa-solid fa-newspaper text-5xl text-white/20"></i></div>`}
                <div class="absolute top-4 right-4 bg-black/60 backdrop-blur-xl border border-white/20 rounded-full px-4 py-1.5 flex items-center gap-2">
                    <i class="fa-solid fa-fire text-brand-yellow text-sm"></i>
                    <span class="text-white text-xs font-bold uppercase tracking-wide">Portada</span>
                </div>
            </a>
            <div class="w-full lg:w-2/5 p-4 md:p-8 flex flex-col justify-center relative z-10">
                <span class="text-brand-blue font-bold text-sm uppercase tracking-widest mb-4 block">${escapeHtml(destacado.seccion)}</span>
                <a href="/articulo/${escapeHtml(destacado.slug)}">
                    <h2 class="font-display text-2xl md:text-5xl font-bold text-white mb-6 leading-tight">${escapeHtml(destacado.titulo)}</h2>
                </a>
                <p class="text-gray-300 text-base md:text-lg mb-8 line-clamp-3 font-light">${escapeHtml(destacado.extracto || '')}</p>
                <div class="mt-auto flex items-center justify-between border-t border-white/10 pt-6">
                    <div class="flex items-center gap-3">
                        <div>
                            <p class="text-sm font-bold text-white">${escapeHtml(destacado.autor_username)}</p>
                            <p class="text-xs text-gray-400">${escapeHtml((destacado.fecha_publicacion || '').slice(0, 10))}</p>
                        </div>
                    </div>
                    ${botonCompartir(env, destacado.slug, destacado.titulo)}
                </div>
            </div>
        </article>
    </section>
  ` : `<section class="fade-up"><div class="ultra-glass p-10 text-center text-gray-400">Todavía no hay artículos publicados.</div></section>`;

  const grillaHtml = resto.length ? `
    <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8 fade-up">
        ${resto.map((a) => tarjetaArticulo(env, a)).join('')}
    </section>
  ` : '';

  const cta = `
    <section class="fade-up">
        <div class="ultra-glass p-8 md:p-12 text-center relative overflow-hidden">
            <div class="absolute inset-0 flex items-center justify-center opacity-10 pointer-events-none">
                <div class="w-64 h-64 rounded-full border-2 border-brand-yellow absolute animate-ping" style="animation-duration: 3s;"></div>
            </div>
            <h2 class="font-display text-3xl md:text-5xl font-black text-white mb-4">¿Quieres ser parte del <span class="text-fluid">crew</span>?</h2>
            <p class="text-gray-300 mb-8 max-w-xl mx-auto">Únete al voluntariado de To' Revuelto: redacción, comunicación y difusión.</p>
            <a href="/voluntariado" class="inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 hover:shadow-[0_0_20px_rgba(247,213,47,0.4)] transition-all items-center gap-2">
                Unirme al voluntariado <i class="fa-solid fa-bolt"></i>
            </a>
        </div>
    </section>
  `;

  const siteUrlInicio = String(env.PUBLIC_SITE_URL || 'https://web.torevueltopj.workers.dev').replace(/\/$/, '');
  const jsonLdOrganizacion = `<script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'NewsMediaOrganization',
    name: "To' Revuelto",
    alternateName: 'To Revuelto',
    url: siteUrlInicio,
    logo: env.LOGO_URL,
    description: "Periódico juvenil digital de República Dominicana hecho por y para jóvenes dominicanos. Noticias, voluntariado, eventos, MUN y comunidad Gen Z.",
    areaServed: {
      '@type': 'Country',
      name: 'República Dominicana',
    },
    sameAs: [],
  })}</script>`;

  return paginaBase(env, {
    titulo: 'Inicio',
    activo: 'inicio',
    urlCanonica: '/',
    descripcion: "To' Revuelto es el periódico juvenil digital de República Dominicana. Noticias frescas, voluntariado, eventos y MUN hechos por y para jóvenes dominicanos.",
    datosEstructurados: jsonLdOrganizacion,
    contenido: `
        <header class="text-center md:text-left fade-up">
            <h1 class="font-display text-4xl md:text-7xl lg:text-8xl font-extrabold text-white leading-[1.1] tracking-tight">
                Rompiendo <br class="hidden md:block">
                la <span class="text-brand-gradient">algoritmia</span>
            </h1>
            <p class="text-gray-400 text-base md:text-lg mt-4 max-w-2xl">
                To' Revuelto es el periódico juvenil digital de República Dominicana: noticias hechas por y para jóvenes dominicanos, oportunidades de <a href="/voluntariado" class="text-brand-blue underline">voluntariado en República Dominicana</a>, y una <a href="/comunidad" class="text-brand-blue underline">comunidad</a> activa de eventos y MUN.
            </p>
        </header>
        ${heroHtml}
        ${grillaHtml}
        ${cta}
        ${bloqueSuscripcion()}
    ` + scriptCompartir(),
  });
}

async function paginaSecciones(env, request) {
  const url = new URL(request.url);
  const seccionFiltro = url.searchParams.get('s');

  let seccionesRows;
  if (seccionFiltro) {
    seccionesRows = { results: [{ seccion: seccionFiltro }] };
  } else {
    seccionesRows = await env.DB.prepare(
      `SELECT DISTINCT seccion FROM articulos WHERE estado = 'publicado' ORDER BY seccion ASC`
    ).all();
  }

  let contenido = `<header class="fade-up"><h1 class="font-display text-4xl md:text-6xl font-extrabold text-white mb-4">Secciones</h1></header>`;

  if (!seccionFiltro) {
    const todasSecciones = await env.DB.prepare(
      `SELECT DISTINCT seccion FROM articulos WHERE estado = 'publicado' ORDER BY seccion ASC`
    ).all();
    contenido += `<section class="flex flex-wrap gap-3 fade-up">
        ${(todasSecciones.results || []).map((s) => `<a href="/secciones?s=${encodeURIComponent(s.seccion)}" class="px-5 py-2 rounded-full text-sm font-medium border border-white/10 bg-white/5 text-gray-200 hover:bg-brand-yellow hover:text-black hover:border-transparent transition-all">${escapeHtml(s.seccion)}</a>`).join('')}
    </section>`;
  }

  const articulosFiltrados = await env.DB.prepare(
    seccionFiltro
      ? `SELECT * FROM articulos WHERE estado = 'publicado' AND seccion = ? ORDER BY fecha_publicacion DESC LIMIT 60`
      : `SELECT * FROM articulos WHERE estado = 'publicado' ORDER BY fecha_publicacion DESC LIMIT 60`
  ).bind(...(seccionFiltro ? [seccionFiltro] : [])).all();

  const lista = articulosFiltrados.results || [];
  contenido += `<section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8 fade-up">
      ${lista.length ? lista.map((a) => tarjetaArticulo(env, a)).join('') : `<div class="col-span-full ultra-glass p-10 text-center text-gray-400">No hay artículos en esta sección todavía.</div>`}
  </section>`;

  return paginaBase(env, {
    titulo: seccionFiltro ? `Sección: ${seccionFiltro}` : 'Secciones',
    activo: 'secciones',
    urlCanonica: seccionFiltro ? `/secciones?s=${encodeURIComponent(seccionFiltro)}` : '/secciones',
    descripcion: "Todas las secciones y artículos de To' Revuelto, el periódico juvenil digital de República Dominicana.",
    contenido: contenido + scriptCompartir(),
  });
}

async function paginaArticulo(env, slug) {
  const articulo = await env.DB.prepare(
    `SELECT * FROM articulos WHERE slug = ? AND estado = 'publicado'`
  ).bind(slug).first();

  if (!articulo) {
    return paginaBase(env, {
      titulo: 'No encontrado',
      activo: '',
      contenido: `<div class="ultra-glass p-10 text-center text-gray-400">Este artículo no existe o no está publicado.</div>`,
    });
  }

  await env.DB.prepare(`UPDATE articulos SET vistas = vistas + 1 WHERE id = ?`).bind(articulo.id).run();

  const portada = urlPublicaR2(env, articulo.portada_key) || urlPublicaR2(env, articulo.diseno_key);

  const contenido = `
    <article class="fade-up max-w-3xl mx-auto">
        <span class="text-brand-blue font-bold text-sm uppercase tracking-widest mb-4 block">${escapeHtml(articulo.seccion)} · ${escapeHtml(articulo.categoria)}</span>
        <h1 class="font-display text-3xl md:text-6xl font-extrabold text-white mb-6 leading-tight">${escapeHtml(articulo.titulo)}</h1>
        <div class="flex items-center justify-between border-y border-white/10 py-4 mb-8">
            <div>
                <p class="text-sm font-bold text-white">${escapeHtml(articulo.autor_username)}</p>
                <p class="text-xs text-gray-400">${escapeHtml((articulo.fecha_publicacion || '').slice(0, 10))} · ${articulo.vistas + 1} vistas</p>
            </div>
            ${botonCompartir(env, articulo.slug, articulo.titulo)}
        </div>
        ${portada ? `<div class="glass-img-wrapper mb-8"><img src="${escapeHtml(portada)}" class="w-full h-auto max-h-[500px] object-cover" alt="${escapeHtml(articulo.titulo)}"></div>` : ''}
        <div class="ultra-glass p-6 md:p-10">
            <div class="prose prose-invert max-w-none text-gray-200 leading-relaxed text-base md:text-lg">
                ${sanitizarHtmlArticulo(articulo.cuerpo_html)}
            </div>
        </div>
        <div class="mt-8 flex justify-center">
            ${botonCompartir(env, articulo.slug, articulo.titulo)}
        </div>
    </article>
  ` + scriptCompartir();

  const jsonLdArticulo = `<script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'NewsArticle',
    headline: articulo.titulo,
    description: articulo.extracto || '',
    image: urlPublicaR2(env, articulo.portada_key) || undefined,
    datePublished: articulo.fecha_publicacion || undefined,
    author: { '@type': 'Person', name: articulo.autor_username },
    publisher: {
      '@type': 'Organization',
      name: "To' Revuelto",
      logo: { '@type': 'ImageObject', url: env.LOGO_URL },
    },
  })}</script>`;

  return paginaBase(env, {
    titulo: articulo.titulo,
    activo: '',
    urlCanonica: `/articulo/${articulo.slug}`,
    descripcion: articulo.extracto || `${articulo.titulo} — Lee este artículo en To' Revuelto, el periódico juvenil digital de República Dominicana.`,
    imagenOg: urlPublicaR2(env, articulo.portada_key) || urlPublicaR2(env, articulo.diseno_key) || '',
    tipoOg: 'article',
    datosEstructurados: jsonLdArticulo,
    contenido,
  });
}

async function paginaDirectiva(env) {
  const miembros = await env.DB.prepare(
    `SELECT * FROM directiva WHERE visible = 1 ORDER BY orden ASC`
  ).all();

  const lista = miembros.results || [];
  const floats = ['directiva-float-1', 'directiva-float-2', 'directiva-float-3'];

  const burbujasHtml = lista.map((m, i) => {
    const foto = urlPublicaR2(env, m.foto_key);
    return `
    <div class="flex flex-col items-center gap-4 fade-up">
        <div class="directiva-bubble w-36 h-36 md:w-48 md:h-48 ${floats[i % floats.length]}" onclick="abrirModal('modal-directiva-${m.id}')">
            ${foto ? `<img src="${escapeHtml(foto)}" alt="${escapeHtml(m.nombre_completo)}">` : `<div class="w-full h-full bg-white/10 flex items-center justify-center"><i class="fa-solid fa-user text-4xl text-white/30"></i></div>`}
        </div>
        <div class="text-center">
            <p class="font-display font-bold text-white text-lg">${escapeHtml(m.nombre_completo)}</p>
            <p class="text-brand-blue text-xs uppercase tracking-wider">${escapeHtml(m.cargo)}</p>
        </div>
    </div>
    <div id="modal-directiva-${m.id}" class="modal-overlay">
        <div class="modal-box ultra-glass p-8 relative">
            <button onclick="cerrarModal('modal-directiva-${m.id}')" class="absolute top-4 right-4 w-9 h-9 rounded-full bg-white/10 flex items-center justify-center hover:bg-white/20"><i class="fa-solid fa-xmark"></i></button>
            <div class="flex flex-col items-center text-center gap-4">
                <div class="directiva-bubble w-28 h-28">
                    ${foto ? `<img src="${escapeHtml(foto)}" alt="${escapeHtml(m.nombre_completo)}">` : `<div class="w-full h-full bg-white/10 flex items-center justify-center"><i class="fa-solid fa-user text-3xl text-white/30"></i></div>`}
                </div>
                <h3 class="font-display text-2xl font-bold text-white">${escapeHtml(m.nombre_completo)}</h3>
                <p class="text-brand-yellow text-sm uppercase tracking-wider font-bold">${escapeHtml(m.cargo)}</p>
                <p class="text-gray-300 text-sm leading-relaxed">${escapeHtml(m.biografia || 'Sin biografía disponible.')}</p>
            </div>
        </div>
    </div>
    `;
  }).join('');

  return paginaBase(env, {
    titulo: 'Directiva',
    activo: 'directiva',
    urlCanonica: '/directiva',
    descripcion: "Conoce al equipo directivo de To' Revuelto, el periódico juvenil digital de República Dominicana.",
    contenido: `
        <header class="text-center fade-up">
            <h1 class="font-display text-4xl md:text-6xl font-extrabold text-white mb-4">La Directiva</h1>
            <p class="text-gray-400 max-w-xl mx-auto">El equipo detrás de To' Revuelto. Toca una foto para conocer más.</p>
        </header>
        <section class="flex flex-wrap justify-center gap-10 md:gap-16 py-10">
            ${lista.length ? burbujasHtml : `<div class="ultra-glass p-10 text-center text-gray-400">Directiva no disponible por el momento.</div>`}
        </section>
    `,
  });
}

const TIPOS_CONVOCATORIA = {
  voluntariado: 'Voluntariado',
  evento: 'Evento',
  mun: 'MUN',
};

function textoCupos(cupos_tipo, cupos_cantidad) {
  if (cupos_tipo === 'personalizado' && cupos_cantidad !== null && cupos_cantidad !== undefined) {
    return `${cupos_cantidad} cupo${cupos_cantidad === 1 ? '' : 's'} disponible${cupos_cantidad === 1 ? '' : 's'}`;
  }
  return 'Cupos abiertos';
}

function badgeCupos(cupos_tipo, cupos_cantidad) {
  return `<span class="px-3 py-1 rounded-full text-xs font-bold bg-brand-blue/20 text-brand-blue inline-flex items-center gap-1"><i class="fa-solid fa-ticket"></i> ${escapeHtml(textoCupos(cupos_tipo, cupos_cantidad))}</span>`;
}

const NOMBRES_AREA_VISIBLE = {
  redaccion: 'Redacción',
  comunicacion_difusion: 'Comunicación y Difusión',
  general: 'Voluntariado',
};

function plantillaCorreoAceptacionHtml(nombreDestino, areaNombre, username, passwordTemporal, linkGrupoWhatsapp, linkPanel) {
  return `<!DOCTYPE html>
<html lang="es">
<body style="margin:0; padding:0; background-color:#030509; font-family: Arial, Helvetica, sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#030509; padding: 32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width: 480px; background-color:#0d111c; border-radius: 24px; border: 1px solid rgba(255,255,255,0.08); border-top: 1px solid rgba(255,255,255,0.18); overflow: hidden;">
          <tr>
            <td style="background: linear-gradient(180deg, rgba(117,188,225,0.10) 0%, rgba(13,17,28,0) 100%); padding: 32px 32px 16px 32px; text-align:center;">
              <div style="display:inline-block; background: linear-gradient(135deg, #F7D52F 0%, #75BCE1 100%); padding: 2px; border-radius: 9999px;">
                <div style="background:#030509; border-radius: 9999px; padding: 10px 22px;">
                  <span style="color:#ffffff; font-size:18px; font-weight:800; letter-spacing: -0.5px;">TO'<span style="color:#75BCE1;">REVUELTO</span></span>
                </div>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding: 8px 32px 12px 32px;">
              <div style="background: rgba(255,255,255,0.035); border: 1px solid rgba(255,255,255,0.07); border-radius: 18px; padding: 24px;">
                <p style="color:#9ca3af; font-size:13px; margin: 0 0 6px 0; text-transform:uppercase; letter-spacing:0.05em;">¡Bienvenido al equipo!</p>
                <p style="color:#9ca3af; font-size:14px; margin: 0 0 10px 0;">Hola, ${escapeHtml(nombreDestino)}</p>
                <p style="color:#ffffff; font-size:16px; line-height:1.6; margin: 0 0 18px 0;">¡Felicidades! Tu postulación a To' Revuelto fue <strong style="color:#F7D52F;">aceptada</strong> en el área de <strong style="color:#75BCE1;">${escapeHtml(areaNombre)}</strong>.</p>
                <p style="color:#ffffff; font-size:15px; line-height:1.6; margin: 0 0 18px 0;">Estos son tus próximos pasos:</p>
                <ol style="color:#e5e7eb; font-size:14px; line-height:1.8; margin: 0 0 22px 0; padding-left: 20px;">
                  <li>Únete al grupo de WhatsApp de tu área: <a href="${escapeHtml(linkGrupoWhatsapp)}" target="_blank" style="color:#75BCE1;">Entrar al grupo</a></li>
                  <li>Regístrate en la web con el usuario y contraseña que te damos abajo, y espera la aprobación del director.</li>
                </ol>
                <div style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 16px; margin-bottom: 22px;">
                  <p style="color:#9ca3af; font-size:12px; margin:0 0 4px 0; text-transform:uppercase;">Usuario</p>
                  <p style="color:#ffffff; font-size:15px; margin:0 0 12px 0; font-weight:700;">${escapeHtml(username)}</p>
                  <p style="color:#9ca3af; font-size:12px; margin:0 0 4px 0; text-transform:uppercase;">Contraseña temporal</p>
                  <p style="color:#ffffff; font-size:15px; margin:0; font-weight:700;">${escapeHtml(passwordTemporal)}</p>
                </div>
                <p style="color:#9ca3af; font-size:12px; margin: 0 0 22px 0;">Puedes cambiar tu contraseña en cualquier momento desde "Mi Perfil" dentro del panel.</p>
                <table role="presentation" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="border-radius: 9999px; background-color:#F7D52F;">
                      <a href="${escapeHtml(linkPanel)}" target="_blank" style="display:inline-block; padding: 14px 28px; color:#030509; font-weight:700; font-size:14px; text-decoration:none; border-radius:9999px;">Entrar al panel</a>
                    </td>
                  </tr>
                </table>
              </div>
            </td>
          </tr>
          <tr>
            <td style="padding: 12px 32px 24px 32px; border-top: 1px solid rgba(255,255,255,0.06);">
              <p style="color:#4b5563; font-size:11px; margin:0; text-align:center;">To' Revuelto — mensaje automático de notificación interna.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

async function enviarCorreoAceptacionPostulante(env, correoDestino, nombreDestino, areaNombre, username, passwordTemporal, linkGrupoWhatsapp, linkPanel) {
  if (!env.BREVO_API_KEY) return { ok: false, error: 'Brevo no configurado.' };
  try {
    const respuesta = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': env.BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        sender: { name: "To' Revuelto", email: 'torevueltopj@gmail.com' },
        to: [{ email: correoDestino, name: nombreDestino || correoDestino }],
        subject: "¡Fuiste aceptado en To' Revuelto! 🎉",
        htmlContent: plantillaCorreoAceptacionHtml(nombreDestino, areaNombre, username, passwordTemporal, linkGrupoWhatsapp, linkPanel),
      }),
    });
    if (!respuesta.ok) {
      const data = await respuesta.json().catch(() => ({}));
      return { ok: false, error: (data && data.message) || `HTTP ${respuesta.status}` };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

async function notificarPostulanteAceptado(env, postulante, areaNombre, username, passwordTemporal) {
  const linkGrupoWhatsapp = obtenerLinkGrupoWhatsapp(env);
  const linkPanel = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin`;
  const linkBienvenida = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/bienvenida/${postulante.id}`;
  const telefonoNormalizado = normalizarTelefonoRD(postulante.telefono);

  if (telefonoNormalizado) {
    const textoWhatsapp = `¡Hola ${postulante.nombre_completo}! Te escribimos de To' Revuelto: fuiste ACEPTADO/A en el área de ${areaNombre}. Entra aquí para ver tu usuario, contraseña y los próximos pasos: ${linkBienvenida} ¡Bienvenido/a!`;
    await enviarMensajeWhatsapp(env, telefonoNormalizado, textoWhatsapp, { tipo_objeto: 'postulante_voluntariado', objeto_id: postulante.id });
  }

  if (postulante.correo) {
    await enviarCorreoAceptacionPostulante(env, postulante.correo, postulante.nombre_completo, areaNombre, username, passwordTemporal, linkGrupoWhatsapp, linkPanel);
  }
}

function generarPasswordTemporal() {
  const alfabeto = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alfabeto[b % alfabeto.length]).join('');
}

async function generarUsernameDisponible(env, nombreCompleto) {
  let base = slugify(nombreCompleto).replace(/-/g, '').slice(0, 20);
  if (!base || base.length < 3) base = 'voluntario';
  let candidato = base;
  let intentos = 0;
  while (await obtenerUsuario(env, candidato)) {
    intentos += 1;
    candidato = `${base}${generarIdAleatorio(2)}`;
    if (intentos > 15) {
      candidato = `${base}${generarIdAleatorio(6)}`;
      break;
    }
  }
  return candidato;
}

function botonRegistrarmeOCerrada(form_url, convocatoria_cerrada, clases) {
  if (convocatoria_cerrada) {
    return `<span class="${clases || 'px-4 py-2 rounded-full text-xs font-bold bg-white/10 text-gray-400'} inline-flex items-center gap-1"><i class="fa-solid fa-lock"></i> Convocatoria cerrada</span>`;
  }
  return `<a href="${escapeHtml(form_url)}" target="_blank" rel="noopener noreferrer" class="${clases || 'px-4 py-2 rounded-full text-xs font-bold bg-brand-yellow text-black hover:scale-105 transition-all'}">Registrarme</a>`;
}

function bloqueFechasConvocatoria(fecha_apertura, fecha_cierre) {
  if (!fecha_apertura && !fecha_cierre) return '';
  const partes = [];
  if (fecha_apertura) partes.push(`Abre: ${escapeHtml(fecha_apertura.slice(0, 10))}`);
  if (fecha_cierre) partes.push(`Cierra: ${escapeHtml(fecha_cierre.slice(0, 10))}`);
  return `<p class="text-gray-400 text-xs mt-1"><i class="fa-regular fa-calendar-check mr-1"></i> ${partes.join(' · ')}</p>`;
}

function tarjetaConvocatoria(env, c) {
  const fotos = urlsPublicasR2(env, c.fotos_keys);
  const portada = fotos[0];
  return `
    <article data-convocatoria-id="${c.id}" class="ultra-glass glass-card-interactive p-3 flex flex-col group relative overflow-hidden">
        <div class="glass-img-wrapper w-full mb-4" style="aspect-ratio: 1 / 1;">
            ${portada ? `<img src="${escapeHtml(portada)}" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" alt="${escapeHtml(c.titulo)}">` : `<div class="w-full h-full bg-white/5 flex items-center justify-center"><i class="fa-solid fa-people-group text-3xl text-white/20"></i></div>`}
        </div>
        <div class="px-3 pb-3 flex flex-col flex-grow justify-between">
            <div>
                <span class="text-brand-blue text-xs font-bold uppercase mb-2 block tracking-wider">${escapeHtml(TIPOS_CONVOCATORIA[c.tipo] || c.tipo)}</span>
                <h3 class="font-display text-xl font-bold text-white leading-tight">${escapeHtml(c.titulo)}</h3>
                ${c.descripcion ? `<p class="text-gray-300 text-sm mt-2 line-clamp-2">${escapeHtml(c.descripcion)}</p>` : ''}
                ${c.fecha_evento ? `<p class="text-gray-400 text-xs mt-2"><i class="fa-regular fa-calendar mr-1"></i> ${escapeHtml(c.fecha_evento.slice(0, 10))}</p>` : ''}
                ${bloqueFechasConvocatoria(c.fecha_apertura, c.fecha_cierre)}
                <div class="mt-2">${badgeCupos(c.cupos_tipo, c.cupos_cantidad)}</div>
            </div>
            <div class="mt-4 flex flex-wrap justify-between items-center gap-2 pt-3 border-t border-white/10">
                ${botonRegistrarmeOCerrada(c.form_url, c.convocatoria_cerrada)}
                <div class="flex gap-2">
                    <button type="button" class="btn-compartir" onclick="compartirArticulo('${escapeHtml(String(env.PUBLIC_SITE_URL || '').replace(/\/$/, ''))}/comunidad/${escapeHtml(c.slug)}', '${escapeHtml(c.titulo).replace(/'/g, '&#39;')}')"><i class="fa-solid fa-share-nodes"></i></button>
                    <button type="button" class="btn-compartir" onclick="abrirModalReporte(${c.id})"><i class="fa-solid fa-flag"></i></button>
                </div>
            </div>
        </div>
    </article>
  `;
}

function modalReporteYFormularioComunidad() {
  return `
    <div id="modal-reporte-convocatoria" class="modal-overlay">
        <div class="modal-box ultra-glass p-8">
            <button type="button" class="modal-cerrar-btn" onclick="cerrarModal('modal-reporte-convocatoria')"><i class="fa-solid fa-xmark"></i></button>
            <h3 class="font-display text-xl font-bold text-white mb-4">Reportar publicación</h3>
            <form id="form-reporte-convocatoria" class="space-y-4">
                <input type="hidden" name="convocatoria_id" id="input-reporte-convocatoria-id">
                <textarea name="motivo" placeholder="¿Por qué quieres reportar esta publicación? (opcional)" maxlength="400" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white" rows="3"></textarea>
                <div class="flex gap-3">
                    <button type="submit" class="flex-grow px-6 py-3 rounded-xl font-bold bg-red-500/20 text-red-300">Enviar reporte</button>
                    <button type="button" onclick="cerrarModal('modal-reporte-convocatoria')" class="px-6 py-3 rounded-xl font-bold bg-white/10 text-white">Cancelar</button>
                </div>
            </form>
        </div>
    </div>
    <div id="modal-subir-convocatoria" class="modal-overlay">
        <div class="modal-box ultra-glass p-8">
            <button type="button" class="modal-cerrar-btn" onclick="cerrarModal('modal-subir-convocatoria')"><i class="fa-solid fa-xmark"></i></button>
            <h3 class="font-display text-xl font-bold text-white mb-4">Publicar en Comunidad</h3>
            <form id="form-subir-convocatoria" class="space-y-4">
                <select required name="tipo" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                    <option value="voluntariado">Voluntariado</option>
                    <option value="evento">Evento</option>
                    <option value="mun">MUN</option>
                </select>
                <input required name="titulo" placeholder="Título" maxlength="150" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                <textarea name="descripcion" placeholder="Descripción" maxlength="600" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white" rows="3"></textarea>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Fecha del evento</label>
                    <input name="fecha_evento" type="date" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                </div>
                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria abre</label>
                        <input name="fecha_apertura" type="date" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                    </div>
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria cierra</label>
                        <input name="fecha_cierre" type="date" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                    </div>
                </div>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Cupos</label>
                    <select name="cupos_tipo" id="select-cupos-tipo-comunidad" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                        <option value="ilimitado">Ilimitado</option>
                        <option value="personalizado">Personalizado</option>
                    </select>
                    <input name="cupos_cantidad" id="input-cupos-cantidad-comunidad" type="number" min="1" placeholder="Cantidad de cupos" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white mt-2 hidden">
                </div>
                <input required name="form_url" type="url" placeholder="https://... (link del formulario de registro)" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Fotos (hasta 5)</label>
                    <input name="fotos" type="file" accept="image/*" multiple class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                </div>
                <input required name="contacto_nombre" placeholder="Tu nombre" maxlength="120" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                <input required name="contacto_telefono" placeholder="Tu teléfono de contacto" maxlength="20" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white">
                <button type="submit" class="w-full px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Publicar</button>
            </form>
        </div>
    </div>
    <script>
        document.getElementById('select-cupos-tipo-comunidad').addEventListener('change', (e) => {
            document.getElementById('input-cupos-cantidad-comunidad').classList.toggle('hidden', e.target.value !== 'personalizado');
        });
        function abrirModalReporte(id) {
            document.getElementById('input-reporte-convocatoria-id').value = id;
            abrirModal('modal-reporte-convocatoria');
        }
        document.getElementById('form-reporte-convocatoria').addEventListener('submit', async (e) => {
            e.preventDefault();
            const datos = Object.fromEntries(new FormData(e.target));
            try {
                const r = await fetch('/api/publico/convocatorias/' + datos.convocatoria_id + '/reportar', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ motivo: datos.motivo }) });
                const data = await r.json();
                if (data.ok) { mostrarToast('Reporte enviado, gracias', 'exito'); cerrarModal('modal-reporte-convocatoria'); e.target.reset(); }
                else { mostrarToast(data.error || 'Error al reportar', 'error'); }
            } catch (err) { mostrarToast('Error de conexión', 'error'); }
        });
        document.getElementById('form-subir-convocatoria').addEventListener('submit', async (e) => {
            e.preventDefault();
            const datos = new FormData(e.target);
            try {
                const r = await fetch('/api/publico/convocatorias', { method: 'POST', body: datos });
                const data = await r.json();
                if (data.ok) { mostrarToast('Publicado en Comunidad', 'exito'); cerrarModal('modal-subir-convocatoria'); e.target.reset(); setTimeout(() => window.location.reload(), 1000); }
                else { mostrarToast(data.error || 'Error al publicar', 'error'); }
            } catch (err) { mostrarToast('Error de conexión', 'error'); }
        });
    <\/script>
  `;
}

async function paginaConvocatoriaIndividual(env, slug) {
  const convocatoria = await env.DB.prepare(
    `SELECT * FROM convocatorias WHERE slug = ? AND estado = 'publicado'`
  ).bind(slug).first();

  if (!convocatoria) {
    return paginaBase(env, {
      titulo: 'No encontrado',
      activo: 'comunidad',
      contenido: `<div class="ultra-glass p-10 text-center text-gray-400">Esta publicación no existe o no está disponible.</div>`,
    });
  }

  const fotos = urlsPublicasR2(env, convocatoria.fotos_keys);
  const portada = fotos[0];

  return paginaBase(env, {
    titulo: convocatoria.titulo,
    activo: 'comunidad',
    descripcion: convocatoria.descripcion || '',
    contenido: `
    <article class="fade-up max-w-3xl mx-auto">
        <span class="text-brand-blue font-bold text-sm uppercase tracking-widest mb-4 block">${escapeHtml(TIPOS_CONVOCATORIA[convocatoria.tipo] || convocatoria.tipo)}</span>
        <h1 class="font-display text-3xl md:text-6xl font-extrabold text-white mb-6 leading-tight">${escapeHtml(convocatoria.titulo)}</h1>
        ${portada ? `<div class="glass-img-wrapper mb-8" style="aspect-ratio:1/1; max-width:500px; margin-left:auto; margin-right:auto;"><img src="${escapeHtml(portada)}" class="w-full h-full object-cover" alt="${escapeHtml(convocatoria.titulo)}"></div>` : ''}
        <div class="ultra-glass p-6 md:p-10 space-y-4">
            <p class="text-gray-300 leading-relaxed">${escapeHtml(convocatoria.descripcion || '')}</p>
            ${convocatoria.fecha_evento ? `<p class="text-brand-blue font-bold">${escapeHtml(convocatoria.fecha_evento.slice(0, 10))}</p>` : ''}
            ${bloqueFechasConvocatoria(convocatoria.fecha_apertura, convocatoria.fecha_cierre)}
<div>${badgeCupos(convocatoria.cupos_tipo, convocatoria.cupos_cantidad)}</div>
            ${botonRegistrarmeOCerrada(convocatoria.form_url, convocatoria.convocatoria_cerrada, 'inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 transition-all items-center gap-2 mt-4')}
        </div>
    </article>
    ` + scriptCompartir(),
  });
}

async function paginaComunidad(env) {
  const rows = await env.DB.prepare(
    `SELECT * FROM convocatorias WHERE estado = 'publicado' ORDER BY creado_en DESC LIMIT 60`
  ).all();
  const lista = rows.results || [];

  return paginaBase(env, {
    titulo: 'Comunidad',
    activo: 'comunidad',
    urlCanonica: '/comunidad',
    descripcion: "Voluntariados, eventos y MUN en República Dominicana publicados por la comunidad de To' Revuelto. Encuentra oportunidades para jóvenes dominicanos.",
    contenido: `
        <header class="flex flex-col md:flex-row md:items-center justify-between gap-4 fade-up">
            <div>
                <h1 class="font-display text-4xl md:text-6xl font-extrabold text-white mb-4">Comunidad</h1>
                <p class="text-gray-400 max-w-xl">Voluntariados, eventos y MUNs publicados por cualquier persona. Comparte el tuyo.</p>
            </div>
            <button onclick="abrirModal('modal-subir-convocatoria')" class="px-6 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 transition-all whitespace-nowrap">Publicar algo</button>
        </header>
        <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8 fade-up">
            ${lista.length ? lista.map((c) => tarjetaConvocatoria(env, c)).join('') : `<div class="col-span-full ultra-glass p-10 text-center text-gray-400">Nada publicado todavía. ¡Sé el primero!</div>`}
        </section>
    ` + scriptCompartir() + modalReporteYFormularioComunidad(),
  });
}

async function paginaVoluntariado(env) {
  return paginaBase(env, {
    titulo: 'Voluntariado',
    activo: 'voluntariado',
    urlCanonica: '/voluntariado',
    descripcion: "Únete al voluntariado de To' Revuelto en República Dominicana: redacción, comunicación y difusión. Voluntariado juvenil dominicano para escribir, diseñar y crear contenido.",
    contenido: `
        <section class="fade-up max-w-3xl mx-auto text-center">
            <div class="logo-neon-wrap w-24 h-24 mx-auto mb-6">
                <div class="logo-neon-glow"></div>
                <img src="${escapeHtml(env.LOGO_URL)}" alt="Logo To' Revuelto" class="logo-neon-img w-24 h-24 object-contain">
            </div>
            <h1 class="font-display text-4xl md:text-6xl font-extrabold text-white mb-4">TO' <span class="text-brand-blue">REVUELTO</span></h1>
            <p class="text-brand-blue font-bold tracking-[0.3em] uppercase text-xs mb-6">Formulario de Voluntarios</p>
            <button type="button" onclick="abrirModal('modal-que-es-torevuelto')" class="mb-10 bg-white/10 hover:bg-white/20 text-white px-6 py-2 rounded-full font-bold text-xs uppercase tracking-widest border border-white/10 transition inline-flex items-center gap-2">
                <i class="fa-solid fa-circle-question text-brand-yellow"></i> ¿Qué es To' Revuelto?
            </button>
        </section>

        <div id="modal-que-es-torevuelto" class="modal-overlay">
            <div class="modal-box ultra-glass p-8">
                <button type="button" class="modal-cerrar-btn" onclick="cerrarModal('modal-que-es-torevuelto')"><i class="fa-solid fa-xmark"></i></button>
                <h3 class="font-display text-2xl font-bold text-brand-yellow mb-4">¿Qué es To' Revuelto?</h3>
                <div class="text-sm text-gray-300 space-y-4 leading-relaxed text-left">
                    <p>To' Revuelto es un proyecto juvenil dominicano que funciona como un periódico digital y comunidad creativa, hecho por jóvenes y para jóvenes, con el objetivo de darles un espacio donde puedan expresarse libremente, compartir ideas y generar impacto positivo.</p>
                    <p>Es más que una página de contenido: es una plataforma donde se combinan la comunicación, la creatividad y la formación, permitiendo que los jóvenes desarrollen su voz, pensamiento crítico y talento en distintos formatos.</p>
                    <p>Dentro de To' Revuelto, los participantes pueden escribir artículos, diseñar contenido visual, manejar redes sociales y formar parte de iniciativas como <strong class="text-white">Diplomacy Lab</strong>, que los prepara en habilidades como debate, oratoria y liderazgo a través de los Modelos de Naciones Unidas (MUN).</p>
                    <p>El proyecto promueve valores como el respeto, la inclusión, la responsabilidad social y la libertad de expresión, siempre cuidando que el contenido no discrimine y respete los derechos de autor y la imagen personal.</p>
                    <p class="text-brand-blue font-bold">En esencia, To' Revuelto es un espacio para crear, opinar, aprender y conectar, donde las ideas de los jóvenes no solo se escuchan, sino que tienen el poder de influir y generar cambio.</p>
                </div>
                <button type="button" onclick="cerrarModal('modal-que-es-torevuelto')" class="w-full mt-6 py-3 rounded-xl font-bold bg-brand-blue text-black uppercase tracking-widest text-sm">Entendido</button>
            </div>
        </div>

        <div id="modal-postulacion-enviada" class="modal-overlay">
            <div class="modal-box ultra-glass p-8 md:p-10 text-center">
                <div class="w-16 h-16 rounded-full bg-brand-yellow/15 flex items-center justify-center mx-auto mb-5">
                    <i class="fa-solid fa-champagne-glasses text-3xl text-brand-yellow"></i>
                </div>
                <h3 class="font-display text-2xl font-bold text-white mb-3">¡Postulación enviada!</h3>
                <p class="text-gray-300 leading-relaxed mb-8">Gracias por querer formar parte de To' Revuelto. Revisaremos tu postulación y te contactaremos por WhatsApp o correo pronto. ¡Mantente pendiente!</p>
                <a href="/" class="inline-flex w-full justify-center px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black hover:scale-[1.02] transition-all items-center gap-2">
                    Volver a la página principal <i class="fa-solid fa-house"></i>
                </a>
            </div>
        </div>

        <section class="fade-up max-w-3xl mx-auto">
            <div class="ultra-glass p-6 md:p-10">
                <form id="form-postulacion-voluntariado" class="space-y-5">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Nombre completo *</label>
                            <input required name="nombre_completo" placeholder="Ej: Juan Pérez" maxlength="120" class="campo-form">
                        </div>
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Edad *</label>
                            <input required type="number" name="edad" min="10" max="99" placeholder="Tu edad" class="campo-form">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Ciudad / Provincia *</label>
                            <input required name="ciudad" placeholder="Tu ubicación" maxlength="120" class="campo-form">
                        </div>
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Correo electrónico *</label>
                            <input required type="email" name="correo" placeholder="correo@ejemplo.com" maxlength="254" class="campo-form">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Usuario de Instagram *</label>
                            <input required name="instagram" placeholder="@usuario" maxlength="60" class="campo-form">
                        </div>
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Número de teléfono (WhatsApp) *</label>
                            <input required type="tel" name="telefono" placeholder="809-000-0000" maxlength="20" class="campo-form">
                            <p class="text-xs text-gray-500 mt-1">Número dominicano (809/829/849). Aquí recibirás noticias sobre tu postulación.</p>
                        </div>
                    </div>

                    <div class="pt-2 border-t border-white/10">
                        <label class="text-xs text-brand-blue uppercase tracking-wider font-bold mb-2 block">Sobre tu participación</label>
                        <button type="button" onclick="abrirModal('modal-que-es-torevuelto')" class="text-xs bg-brand-blue/20 text-brand-blue hover:bg-brand-blue hover:text-black px-3 py-1 rounded-lg font-bold transition whitespace-nowrap"><i class="fa-solid fa-eye mr-1"></i>¿Cuál sería mi rol?</button>
                    </div>

                    <div>
                        <label class="text-xs text-white uppercase tracking-wider mb-1 block">¿Por qué te interesa formar parte de To' Revuelto? *</label>
                        <textarea required name="interes_area" placeholder="Escribe aquí..." class="campo-form" rows="3"></textarea>
                    </div>
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">¿Tienes experiencia redactando, diseñando o creando contenido? (Opcional)</label>
                        <textarea name="experiencia" placeholder="Explica brevemente..." class="campo-form" rows="3"></textarea>
                    </div>
                    <div>
                        <label class="text-xs text-white uppercase tracking-wider mb-1 block">Menciona 3 habilidades que aportas a To' Revuelto *</label>
                        <textarea required name="habilidades" placeholder="1... 2... 3..." class="campo-form" rows="3"></textarea>
                    </div>
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">¿Has participado en proyectos similares? ¿Cuáles? (Opcional)</label>
                        <textarea name="proyectos_similares" placeholder="Menciona tus proyectos..." class="campo-form" rows="3"></textarea>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-white/10">
                        <div>
                            <label class="text-xs text-white uppercase tracking-wider mb-1 block">¿Estás dispuesto/a a trabajar en equipo y cumplir con responsabilidades? *</label>
                            <select required name="trabajo_equipo" class="campo-form cursor-pointer">
                                <option value="">Selecciona...</option>
                                <option value="Sí">Sí</option>
                                <option value="No">No</option>
                            </select>
                        </div>
                        <div>
                            <label class="text-xs text-white uppercase tracking-wider mb-1 block">¿Estás de acuerdo con mantener un contenido respetuoso, que no discrimine y respete derechos? *</label>
                            <select required name="acuerdo_contenido" class="campo-form cursor-pointer">
                                <option value="">Selecciona...</option>
                                <option value="Sí">Sí</option>
                                <option value="No">No</option>
                            </select>
                        </div>
                    </div>

                    <div class="bg-brand-blue/10 p-4 rounded-2xl border border-brand-blue/30">
                        <label class="text-xs text-brand-blue uppercase tracking-wider mb-1 block font-bold">¿Qué tipo de contenido te gustaría crear? Redacción, memes, historias, posts... (Opcional)</label>
                        <textarea name="tipo_contenido" placeholder="Tus ideas creativas..." class="campo-form" rows="3"></textarea>
                    </div>

                    <div>
                        <label class="text-xs text-white uppercase tracking-wider mb-1 block">¿Por qué deberíamos seleccionarte para To' Revuelto? *</label>
                        <textarea required name="porque_seleccionar" placeholder="Convéncenos..." class="campo-form" rows="4"></textarea>
                    </div>
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">¿Hay algo más que quieras agregar? (Opcional)</label>
                        <textarea name="algo_mas" placeholder="Comentarios adicionales..." class="campo-form" rows="2"></textarea>
                    </div>

                    <button type="submit" class="w-full bg-brand-yellow text-black py-4 mt-4 rounded-2xl font-black uppercase tracking-widest hover:scale-[1.01] transition-all text-sm">
                        Enviar Postulación
                    </button>
                </form>
            </div>
        </section>
    ` + `
    <script>
        (function() {
            const inputTelefono = document.querySelector('#form-postulacion-voluntariado [name="telefono"]');
            inputTelefono.addEventListener('input', function (e) {
                let x = e.target.value.replace(/\\D/g, '').match(/(\\d{0,3})(\\d{0,3})(\\d{0,4})/);
                e.target.value = !x[2] ? x[1] : '(' + x[1] + ') ' + x[2] + (x[3] ? '-' + x[3] : '');
            });
        })();

        document.getElementById('form-postulacion-voluntariado').addEventListener('submit', async (e) => {
            e.preventDefault();
            const boton = e.target.querySelector('button[type="submit"]');
            boton.disabled = true; boton.textContent = 'Enviando...';
            const datos = Object.fromEntries(new FormData(e.target));
            try {
                const r = await fetch('/api/publico/postulaciones-voluntariado', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(datos) });
                const data = await r.json();
                if (data.ok) {
                    e.target.reset();
                    document.getElementById('campo-tipo-contenido-postulacion').classList.add('hidden');
                    abrirModal('modal-postulacion-enviada');
                } else {
                    mostrarToast(data.error || 'Error al enviar la postulación', 'error');
                }
            } catch (err) {
                mostrarToast('Error de conexión', 'error');
            }
            boton.disabled = false; boton.textContent = 'Enviar Postulación';
        });
    <\/script>
  `,
  });
}

async function paginaEventos(env) {
  const eventos = await env.DB.prepare(
    `SELECT * FROM eventos WHERE estado = 'aprobado' ORDER BY fecha_evento ASC`
  ).all();

  const lista = eventos.results || [];

  const tarjetas = lista.map((e) => {
    const imagen = urlPublicaR2(env, e.imagen_key);
    return `
    <article class="ultra-glass glass-card-interactive p-3 flex flex-col group overflow-hidden">
        <a href="/eventos/${escapeHtml(e.slug)}" class="glass-img-wrapper w-full mb-4 block" style="aspect-ratio: 1 / 1;">
            ${imagen ? `<img src="${escapeHtml(imagen)}" class="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" alt="${escapeHtml(e.titulo)}">` : `<div class="w-full h-full bg-white/5 flex items-center justify-center"><i class="fa-solid fa-calendar-days text-3xl text-white/20"></i></div>`}
        </a>
        <div class="px-3 pb-3 flex flex-col flex-grow">
            <a href="/eventos/${escapeHtml(e.slug)}"><h3 class="font-display text-xl font-bold text-white mb-2 hover:text-brand-yellow transition-colors">${escapeHtml(e.titulo)}</h3></a>
            <p class="text-gray-400 text-sm mb-1">${escapeHtml((e.fecha_evento || '').slice(0, 10))} ${e.lugar ? '· ' + escapeHtml(e.lugar) : ''}</p>
            ${bloqueFechasConvocatoria(e.fecha_apertura, e.fecha_cierre)}
            <div class="my-2">${badgeCupos(e.cupos_tipo, e.cupos_cantidad)}</div>
            <p class="text-gray-300 text-sm mb-4 flex-grow line-clamp-3">${escapeHtml(e.descripcion || '')}</p>
            <div class="flex items-center justify-between gap-2 mt-auto pt-4 border-t border-white/10">
                ${botonRegistrarmeOCerrada(e.form_url, e.convocatoria_cerrada)}
                <button type="button" class="btn-compartir" onclick="compartirArticulo('${escapeHtml(String(env.PUBLIC_SITE_URL || '').replace(/\/$/, ''))}/eventos/${escapeHtml(e.slug)}', '${escapeHtml(e.titulo).replace(/'/g, '&#39;')}')"><i class="fa-solid fa-share-nodes"></i> Compartir</button>
            </div>
        </div>
    </article>
    `;
  }).join('');

  return paginaBase(env, {
    titulo: 'Eventos',
    activo: 'eventos',
    urlCanonica: '/eventos',
    descripcion: "Eventos, actividades y encuentros juveniles en República Dominicana organizados por To' Revuelto.",
    contenido: `
        <header class="fade-up"><h1 class="font-display text-4xl md:text-6xl font-extrabold text-white mb-4">Eventos</h1></header>
        <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8 fade-up">
            ${lista.length ? tarjetas : `<div class="col-span-full ultra-glass p-10 text-center text-gray-400">No hay eventos programados por el momento.</div>`}
        </section>
    ` + scriptCompartir(),
  });
}

async function paginaEventoIndividual(env, slug) {
  const evento = await env.DB.prepare(
    `SELECT * FROM eventos WHERE slug = ? AND estado = 'aprobado'`
  ).bind(slug).first();

  if (!evento) {
    return paginaBase(env, { titulo: 'No encontrado', activo: 'eventos', contenido: `<div class="ultra-glass p-10 text-center text-gray-400">Evento no encontrado.</div>` });
  }

  const imagen = urlPublicaR2(env, evento.imagen_key);

  return paginaBase(env, {
    titulo: evento.titulo,
    activo: 'eventos',
    contenido: `
    <article class="fade-up max-w-3xl mx-auto">
        <h1 class="font-display text-3xl md:text-6xl font-extrabold text-white mb-6">${escapeHtml(evento.titulo)}</h1>
        ${imagen ? `<div class="glass-img-wrapper mb-8"><img src="${escapeHtml(imagen)}" class="w-full h-auto max-h-[450px] object-cover"></div>` : ''}
        <div class="ultra-glass p-8 space-y-4">
            <p class="text-gray-300 leading-relaxed">${escapeHtml(evento.descripcion || '')}</p>
            <p class="text-brand-blue font-bold">${escapeHtml((evento.fecha_evento || '').slice(0, 10))} ${evento.lugar ? '· ' + escapeHtml(evento.lugar) : ''}</p>
            ${bloqueFechasConvocatoria(evento.fecha_apertura, evento.fecha_cierre)}
            <div>${badgeCupos(evento.cupos_tipo, evento.cupos_cantidad)}</div>
            ${evento.asistentes_texto ? `<div class="pt-4 border-t border-white/10"><p class="text-white font-bold mb-2">Confirmados:</p><div class="prose prose-invert prose-sm max-w-none text-gray-300" style="max-height:none; overflow:visible;">${sanitizarHtmlArticulo(evento.asistentes_texto)}</div></div>` : ''}
            ${botonRegistrarmeOCerrada(evento.form_url, evento.convocatoria_cerrada, 'inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 transition-all items-center gap-2 mt-4')}
        </div>
    </article>
    ` + scriptCompartir(),
  });
}

async function paginaTareaPublica(env, id, request) {
  const tarea = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE id = ?`).bind(id).first();

  if (!tarea) {
    return paginaBase(env, {
      titulo: 'Tarea no encontrada',
      activo: '',
      contenido: `<div class="ultra-glass p-10 text-center text-gray-400 max-w-xl mx-auto">Esta tarea no existe.</div>`,
    });
  }

  const usuarioActual = await requiereAuth(request, env);
  const miembros = await env.DB.prepare(`SELECT username FROM tareas_difusion_miembros WHERE tarea_id = ?`).bind(id).all();
  const esGrupal = (miembros.results || []).length > 0;
  const nombresGrupo = [];
  if (esGrupal) {
    for (const m of miembros.results) {
      const u = await obtenerUsuario(env, m.username);
      if (u) nombresGrupo.push(u.nombre_completo);
    }
  }

  const coloresEstado = {
    pendiente: 'bg-gray-500/20 text-gray-300',
    enviada: 'bg-brand-blue/20 text-brand-blue',
    aprobada: 'bg-green-500/20 text-green-300',
    publicada: 'bg-green-500/20 text-green-300',
    rechazada: 'bg-red-500/20 text-red-300',
  };

  const puedeEntregar = usuarioActual && (
    usuarioActual.username === tarea.asignado_a_username ||
    (esGrupal && miembros.results.some((m) => m.username === usuarioActual.username))
  );

  const botonAccion = puedeEntregar && tarea.estado === 'pendiente'
    ? `<a href="/admin#tareas" class="inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 transition-all items-center gap-2">Ir a entregar mi trabajo <i class="fa-solid fa-arrow-right"></i></a>`
    : !usuarioActual
    ? `<a href="/admin?volver=${encodeURIComponent('tarea/' + id)}" class="inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 transition-all items-center gap-2">Iniciar sesión para entregar <i class="fa-solid fa-arrow-right-to-bracket"></i></a>`
    : usuarioActual && !puedeEntregar
    ? `<div class="p-4 rounded-xl bg-white/5 border border-white/10"><p class="text-gray-300 text-sm"><i class="fa-solid fa-circle-info text-brand-blue mr-2"></i>Esta tarea no te corresponde a ti. Está asignada a otro usuario o grupo.</p></div>`
    : '';

  return paginaBase(env, {
    titulo: tarea.titulo,
    activo: '',
    contenido: `
    <article class="fade-up max-w-2xl mx-auto">
        <span class="text-brand-blue font-bold text-sm uppercase tracking-widest mb-4 block">${escapeHtml(tarea.tipo)}${esGrupal ? ' · Tarea grupal' : ''}</span>
        <h1 class="font-display text-3xl md:text-5xl font-extrabold text-white mb-6 leading-tight">${escapeHtml(tarea.titulo)}</h1>
        <div class="ultra-glass p-6 md:p-10 space-y-6">
            <div class="flex items-center gap-3">
                <span class="badge-estado ${coloresEstado[tarea.estado] || 'bg-gray-500/20 text-gray-300'}" style="padding:0.25rem 0.75rem; border-radius:9999px; font-size:0.7rem; font-weight:700; text-transform:uppercase;">${escapeHtml(tarea.estado.replace(/_/g, ' '))}</span>
            </div>
            ${tarea.descripcion ? `<p class="text-gray-300 leading-relaxed">${escapeHtml(tarea.descripcion)}</p>` : ''}
            ${esGrupal ? `<div><p class="text-white font-bold text-sm mb-2">Integrantes del grupo:</p><p class="text-gray-400 text-sm">${nombresGrupo.map(escapeHtml).join(', ')}</p></div>` : ''}
            ${botonAccion}
        </div>
    </article>
    `,
  });
}

async function paginaAvisoPublico(env, id) {
  const aviso = await env.DB.prepare(`SELECT * FROM avisos_generales WHERE id = ?`).bind(id).first();

  if (!aviso) {
    return paginaBase(env, {
      titulo: 'Aviso no encontrado',
      activo: '',
      contenido: `<div class="ultra-glass p-10 text-center text-gray-400 max-w-xl mx-auto">Este aviso no existe.</div>`,
    });
  }

  return paginaBase(env, {
    titulo: aviso.asunto,
    activo: '',
    urlCanonica: `/aviso/${aviso.id}`,
    descripcion: aviso.mensaje.slice(0, 200),
    contenido: `
    <article class="fade-up max-w-2xl mx-auto">
        <span class="text-brand-blue font-bold text-sm uppercase tracking-widest mb-4 block">Aviso General</span>
        <h1 class="font-display text-3xl md:text-5xl font-extrabold text-white mb-6 leading-tight">${escapeHtml(aviso.asunto)}</h1>
        <div class="ultra-glass p-6 md:p-10 space-y-4">
            <p class="text-gray-300 leading-relaxed whitespace-pre-line">${escapeHtml(aviso.mensaje)}</p>
            <p class="text-gray-500 text-xs pt-4 border-t border-white/10">Publicado el ${escapeHtml((aviso.creado_en || '').slice(0, 10))}</p>
        </div>
    </article>
    `,
  });
}

async function paginaBienvenidaPostulante(env, id) {
  const postulante = await env.DB.prepare(
    `SELECT id, nombre_completo, area, estado, username_creado, credencial_temporal FROM postulantes_voluntariado WHERE id = ?`
  ).bind(id).first();

  if (!postulante || postulante.estado !== 'aceptado' || !postulante.username_creado) {
    return paginaBase(env, {
      titulo: 'Enlace no disponible',
      activo: '',
      contenido: `<div class="ultra-glass p-10 text-center text-gray-400 max-w-xl mx-auto">Este enlace de bienvenida no está disponible.</div>`,
    });
  }

  const areaNombre = NOMBRES_AREA_VISIBLE[postulante.area] || postulante.area;
  const linkGrupoWhatsapp = obtenerLinkGrupoWhatsapp(env);
  const linkPanel = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin`;

  return paginaBase(env, {
    titulo: '¡Bienvenido al equipo!',
    activo: 'voluntariado',
    urlCanonica: `/bienvenida/${postulante.id}`,
    descripcion: `¡Felicidades! Fuiste aceptado en To' Revuelto en el área de ${areaNombre}.`,
    contenido: `
    <article class="fade-up max-w-2xl mx-auto">
        <div class="text-center mb-8">
            <i class="fa-solid fa-champagne-glasses text-5xl text-brand-yellow mb-4"></i>
            <span class="text-brand-blue font-bold text-sm uppercase tracking-widest mb-2 block">¡Bienvenido al equipo!</span>
            <h1 class="font-display text-3xl md:text-5xl font-extrabold text-white leading-tight">Hola, ${escapeHtml(postulante.nombre_completo)}</h1>
        </div>
        <div class="ultra-glass p-6 md:p-10 space-y-6">
            <p class="text-gray-200 text-base md:text-lg leading-relaxed">¡Felicidades! Tu postulación a To' Revuelto fue <strong class="text-brand-yellow">aceptada</strong> en el área de <strong class="text-brand-blue">${escapeHtml(areaNombre)}</strong>.</p>

            <div>
                <p class="text-white font-bold mb-3">Estos son tus próximos pasos:</p>
                <ol class="space-y-3 text-gray-300 text-sm leading-relaxed list-decimal list-inside">
                    <li>Únete al grupo de WhatsApp de tu área: ${linkGrupoWhatsapp ? `<a href="${escapeHtml(linkGrupoWhatsapp)}" target="_blank" rel="noopener noreferrer" class="text-brand-blue underline font-bold">Entrar al grupo</a>` : 'Pronto recibirás el enlace.'}</li>
                    <li>Regístrate en la web con el usuario y contraseña de abajo, y espera la aprobación del director.</li>
                </ol>
            </div>

            <div class="bg-black/30 border border-white/10 rounded-2xl p-5 space-y-3">
                <div>
                    <p class="text-gray-400 text-xs uppercase tracking-wider mb-1">Usuario</p>
                    <p class="text-white font-bold text-lg">${escapeHtml(postulante.username_creado)}</p>
                </div>
                ${postulante.credencial_temporal ? `
                <div>
                    <p class="text-gray-400 text-xs uppercase tracking-wider mb-1">Contraseña temporal</p>
                    <p class="text-white font-bold text-lg">${escapeHtml(postulante.credencial_temporal)}</p>
                </div>
                ` : `
                <p class="text-gray-400 text-xs">Ya iniciaste sesión antes o cambiaste tu contraseña; usa la que configuraste.</p>
                `}
            </div>
            <p class="text-gray-500 text-xs">Puedes cambiar tu contraseña en cualquier momento desde "Mi Perfil" dentro del panel.</p>

            <a href="${escapeHtml(linkPanel)}" class="inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 hover:shadow-[0_0_20px_rgba(247,213,47,0.4)] transition-all items-center gap-2">
                Entrar al panel <i class="fa-solid fa-arrow-right"></i>
            </a>
        </div>
    </article>
    `,
  });
}

async function paginaArticuloAsignadoPublico(env, id, request) {
  const articulo = await env.DB.prepare(`SELECT * FROM articulos WHERE id = ?`).bind(id).first();

  if (!articulo) {
    return paginaBase(env, {
      titulo: 'Artículo no encontrado',
      activo: '',
      contenido: `<div class="ultra-glass p-10 text-center text-gray-400 max-w-xl mx-auto">Este artículo no existe.</div>`,
    });
  }

  if (articulo.estado === 'publicado') {
    return new Response(null, { status: 302, headers: { 'Location': `/articulo/${articulo.slug}` } });
  }

  const usuarioActual = await requiereAuth(request, env);
  const esElAutor = usuarioActual && usuarioActual.username === (articulo.autor_username || articulo.asignado_a_username);

  const coloresEstadoArticulo = {
    borrador: 'bg-gray-500/20 text-gray-300',
    enviado: 'bg-brand-blue/20 text-brand-blue',
    aprobado_redaccion: 'bg-brand-blue/20 text-brand-blue',
    en_diseno: 'bg-purple-500/20 text-purple-300',
    aprobado_diseno: 'bg-brand-yellow/20 text-brand-yellow',
    rechazado: 'bg-red-500/20 text-red-300',
  };

  const botonAccionArticulo = esElAutor
    ? `<a href="/admin#mis-articulos" class="inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 transition-all items-center gap-2">Ir a mis artículos <i class="fa-solid fa-arrow-right"></i></a>`
    : !usuarioActual
    ? `<a href="/admin?volver=${encodeURIComponent('tarea/a-' + id)}" class="inline-flex px-8 py-3 rounded-full font-bold bg-brand-yellow text-black hover:scale-105 transition-all items-center gap-2">Iniciar sesión para ver mi tema <i class="fa-solid fa-arrow-right-to-bracket"></i></a>`
    : `<div class="p-4 rounded-xl bg-white/5 border border-white/10"><p class="text-gray-300 text-sm"><i class="fa-solid fa-circle-info text-brand-blue mr-2"></i>Este artículo no te corresponde a ti.</p></div>`;

  return paginaBase(env, {
    titulo: articulo.titulo,
    activo: '',
    contenido: `
    <article class="fade-up max-w-2xl mx-auto">
        <span class="text-brand-blue font-bold text-sm uppercase tracking-widest mb-4 block">${escapeHtml(articulo.seccion || 'Tema asignado')}</span>
        <h1 class="font-display text-3xl md:text-5xl font-extrabold text-white mb-6 leading-tight">${escapeHtml(articulo.titulo)}</h1>
        <div class="ultra-glass p-6 md:p-10 space-y-6">
            <div class="flex items-center gap-3">
                <span class="badge-estado ${coloresEstadoArticulo[articulo.estado] || 'bg-gray-500/20 text-gray-300'}" style="padding:0.25rem 0.75rem; border-radius:9999px; font-size:0.7rem; font-weight:700; text-transform:uppercase;">${escapeHtml(articulo.estado.replace(/_/g, ' '))}</span>
                ${articulo.fecha_asignada ? `<span class="text-gray-400 text-xs">Fecha asignada: ${escapeHtml(articulo.fecha_asignada.slice(0, 10))}</span>` : ''}
            </div>
            ${botonAccionArticulo}
        </div>
    </article>
    `,
  });
}

function paginaLoginAdmin(env, mensajeError, volverParam) {
  const volverSeguro = (volverParam && /^tarea\/(a-)?\d+$/.test(volverParam)) ? volverParam : '';
  return `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel Interno | To' Revuelto</title>
    <link rel="icon" href="${escapeHtml(env.LOGO_URL)}" type="image/png">
    <link rel="apple-touch-icon" href="${escapeHtml(env.LOGO_URL)}">
    ${estilosBase()}
</head>
<body class="relative min-h-screen antialiased flex items-center justify-center px-4">
    ${fondoOrbes()}
    <div class="w-full max-w-md ultra-glass p-8 md:p-10 fade-up visible">
        <div class="flex justify-center mb-6">
            <div class="logo-neon-wrap w-16 h-16">
                <div class="logo-neon-glow"></div>
                <img src="${escapeHtml(env.LOGO_URL)}" alt="Logo" class="logo-neon-img w-14 h-14 object-contain">
            </div>
        </div>
        <h1 class="font-display text-2xl font-bold text-white text-center mb-2">Panel Interno</h1>
        <p class="text-gray-400 text-sm text-center mb-8">Acceso exclusivo para el equipo de To' Revuelto</p>

        <div class="flex gap-2 mb-6 p-1 bg-white/5 rounded-full border border-white/10">
            <button onclick="mostrarTab('login')" id="tab-login" class="flex-1 py-2 rounded-full text-sm font-bold bg-white text-black transition-all">Iniciar sesión</button>
            <button onclick="mostrarTab('registro')" id="tab-registro" class="flex-1 py-2 rounded-full text-sm font-bold text-gray-300 transition-all">Registrarme</button>
        </div>

        ${mensajeError ? `<div class="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm">${escapeHtml(mensajeError)}</div>` : ''}

        <form id="form-login" method="POST" action="/admin/login" class="space-y-4">
            <input type="hidden" name="volver" value="${escapeHtml(volverSeguro)}">
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Usuario</label>
                <input required name="username" type="text" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue transition-colors" placeholder="Tu usuario">
            </div>
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Contraseña</label>
                <input required name="password" type="password" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue transition-colors" placeholder="••••••••">
            </div>
            <button type="submit" class="w-full py-3 rounded-xl font-bold bg-brand-yellow text-black hover:scale-[1.02] transition-all">Entrar</button>
        </form>

        <form id="form-registro" method="POST" action="/admin/registro" class="space-y-4 hidden">
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Rol solicitado</label>
                <select required name="rol_solicitado" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue">
                    <option value="">Selecciona un rol</option>
                    <option value="voluntario">Voluntario</option>
                    <option value="subdirectora_general">Sub-Directora General</option>
                </select>
            </div>
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Nombre completo</label>
                <input required name="nombre_completo" type="text" maxlength="120" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue">
            </div>
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Usuario</label>
                <input required name="username" type="text" pattern="[a-zA-Z0-9_.]{3,32}" maxlength="32" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue" placeholder="Solo letras, números, punto o guión bajo">
            </div>
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Teléfono (WhatsApp)</label>
                <input required name="telefono" type="tel" maxlength="20" placeholder="809-000-0000" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue">
                <p class="text-xs text-gray-500 mt-1">Número dominicano (809/829/849). Aquí recibirás tus tareas por WhatsApp.</p>
            </div>
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Correo</label>
                <input name="correo" type="email" maxlength="254" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue">
            </div>
            <div>
                <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Contraseña</label>
                <input required name="password" type="password" minlength="6" maxlength="128" class="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-brand-blue">
            </div>
            <button type="submit" class="w-full py-3 rounded-xl font-bold bg-brand-blue text-black hover:scale-[1.02] transition-all">Enviar solicitud</button>
            <p class="text-xs text-gray-500 text-center">Tu solicitud quedará pendiente de aprobación por el director correspondiente.</p>
        </form>

        ${volverSeguro ? `<div class="mt-4 p-3 rounded-xl bg-brand-blue/10 border border-brand-blue/30 text-center"><p class="text-brand-blue text-xs">Después de iniciar sesión volverás directo a tu tarea.</p></div>` : ''}

        <div class="text-center mt-6">
            <a href="/" class="text-xs text-gray-500 hover:text-white transition-colors"><i class="fa-solid fa-arrow-left mr-1"></i> Volver al sitio</a>
        </div>
    </div>
    ${scriptToastYModal()}
    <script>
        function mostrarTab(tab) {
            document.getElementById('form-login').classList.toggle('hidden', tab !== 'login');
            document.getElementById('form-registro').classList.toggle('hidden', tab !== 'registro');
            document.getElementById('tab-login').className = 'flex-1 py-2 rounded-full text-sm font-bold transition-all ' + (tab === 'login' ? 'bg-white text-black' : 'text-gray-300');
            document.getElementById('tab-registro').className = 'flex-1 py-2 rounded-full text-sm font-bold transition-all ' + (tab === 'registro' ? 'bg-white text-black' : 'text-gray-300');
        }
        document.getElementById('form-registro').addEventListener('submit', function(e) {
            e.preventDefault();
            const datos = new FormData(this);
            fetch('/admin/registro', { method: 'POST', body: datos }).then(r => r.json()).then(data => {
                if (data.ok) { mostrarToast('Solicitud enviada, espera aprobación', 'exito'); this.reset(); }
                else { mostrarToast(data.error || 'Error al registrar', 'error'); }
            }).catch(() => mostrarToast('Error de conexión', 'error'));
        });
    <\/script>
</body>
</html>`;
}

async function shellAdmin(env, usuario) {
  const prefs = await obtenerPreferenciasUsuario(env, usuario.username);
  const esAccesoTotal = ROLES_CON_ACCESO_TOTAL.includes(usuario.rol);
  const esAltaDireccion = ROLES_ALTA_DIRECCION.includes(usuario.rol);
  const esVoluntario = usuario.rol === ROLES.VOLUNTARIO;

  const pestañas = [];
  pestañas.push({ id: 'resumen', texto: 'Resumen', icono: 'fa-gauge' });

  if (esVoluntario || esAltaDireccion) pestañas.push({ id: 'mis-articulos', texto: 'Mis Artículos', icono: 'fa-pen' });
  pestañas.push({ id: 'tareas', texto: 'Tareas', icono: 'fa-images' });
  if (usuario.rol === ROLES.DIRECTOR_GENERAL) pestañas.push({ id: 'publicar-articulo', texto: 'Publicar Artículo', icono: 'fa-newspaper' });
  if (esAccesoTotal) pestañas.push({ id: 'directiva-admin', texto: 'Directiva del Sitio', icono: 'fa-users' });
  if (esAccesoTotal) pestañas.push({ id: 'eventos-admin', texto: 'Eventos', icono: 'fa-calendar-days' });
  if (esAccesoTotal) pestañas.push({ id: 'comunidad-admin', texto: 'Comunidad (reportes)', icono: 'fa-flag' });
  if (esAccesoTotal) pestañas.push({ id: 'postulantes', texto: 'Postulantes', icono: 'fa-user-plus' });
  if (esAccesoTotal) pestañas.push({ id: 'usuarios', texto: 'Usuarios', icono: 'fa-user-group' });
  pestañas.push({ id: 'rachas', texto: 'Rachas', icono: 'fa-fire' });
  if (usuario.rol === ROLES.DIRECTOR_GENERAL) pestañas.push({ id: 'contactos-directiva', texto: 'Contactos Directiva', icono: 'fa-address-book' });
  if (esAccesoTotal) pestañas.push({ id: 'aviso-general', texto: 'Aviso General', icono: 'fa-bullhorn' });
  pestañas.push({ id: 'apariencia', texto: 'Apariencia', icono: 'fa-palette' });
  pestañas.push({ id: 'mi-perfil', texto: 'Mi Perfil', icono: 'fa-id-badge' });

  if (prefs.orden_tabs && prefs.orden_tabs.length) {
    const mapaOrden = new Map(prefs.orden_tabs.map((id, i) => [id, i]));
    pestañas.sort((a, b) => {
      const posA = mapaOrden.has(a.id) ? mapaOrden.get(a.id) : 999;
      const posB = mapaOrden.has(b.id) ? mapaOrden.get(b.id) : 999;
      return posA - posB;
    });
  }

  const tabsHtml = pestañas.map((p) => `
    <button onclick="cambiarTab('${p.id}')" data-tab-btn="${p.id}" class="tab-btn w-full flex items-center gap-3 px-4 py-3 rounded-2xl text-sm font-medium text-gray-300 hover:bg-white/10 transition-all">
        <i class="fa-solid ${p.icono} w-5 text-center"></i> <span>${p.texto}</span>
    </button>
  `).join('');

  return `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel | To' Revuelto</title>
    <link rel="icon" href="${escapeHtml(env.LOGO_URL)}" type="image/png">
    <link rel="apple-touch-icon" href="${escapeHtml(env.LOGO_URL)}">
    ${estilosBase()}
    <style>
        .tab-btn.activo { background: rgba(247,213,47,0.15); color: #F7D52F; border: 1px solid rgba(247,213,47,0.3); }
        .sidebar-admin { width: 280px; flex-shrink: 0; }
        @media (max-width: 1024px) {
            .sidebar-admin { position: fixed; top: 0; left: 0; bottom: 0; z-index: 60; transform: translateX(-100%); transition: transform 0.3s; }
            .sidebar-admin.abierta { transform: translateX(0); }
        }
        .campo-form { width: 100%; background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1); border-radius: 0.75rem; padding: 0.75rem 1rem; color: white; }
        .campo-form:focus { outline: none; border-color: #75BCE1; }
        .badge-estado { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
        .editor-toolbar button { width: 2.25rem; height: 2.25rem; border-radius: 0.5rem; display: inline-flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #e5e7eb; }
        .editor-toolbar button:hover { background: rgba(247,213,47,0.15); color: #F7D52F; }
        .editor-cuerpo { min-height: 220px; max-height: 420px; overflow-y: auto; background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1); border-radius: 0.75rem; padding: 1rem; color: white; }
        .editor-cuerpo:focus { outline: none; border-color: #75BCE1; }
        .editor-cuerpo-asistentes { min-height: 100px; max-height: 260px; }
        :root { --acento-usuario: ${escapeHtml((TEMAS_DISPONIBLES[prefs.tema] || TEMAS_DISPONIBLES.azul).acento)}; }
        .tab-btn.activo { background: color-mix(in srgb, var(--acento-usuario) 15%, transparent) !important; color: var(--acento-usuario) !important; border-color: color-mix(in srgb, var(--acento-usuario) 30%, transparent) !important; }
        .widget-colapsable.colapsado .widget-contenido { display: none; }
    </style>
</head>
<body class="relative min-h-screen antialiased">
    ${fondoOrbes()}
    <div class="flex min-h-screen">
        <aside class="sidebar-admin ultra-glass m-4 p-4 flex flex-col gap-2 overflow-y-auto" id="sidebar-admin">
            <div class="flex items-center gap-3 px-2 py-4 mb-2 border-b border-white/10">
                ${urlPublicaR2(env, usuario.foto_key) ? `<img src="${escapeHtml(urlPublicaR2(env, usuario.foto_key))}" class="w-10 h-10 rounded-full object-cover border-2 border-brand-yellow">` : `<div class="logo-neon-wrap w-10 h-10"><div class="logo-neon-glow"></div><img src="${escapeHtml(env.LOGO_URL)}" class="logo-neon-img w-9 h-9 object-contain"></div>`}
                <div>
                    <p class="text-white font-bold text-sm">${escapeHtml(usuario.nombre_completo)}</p>
                    <p class="text-brand-blue text-xs">${escapeHtml(NOMBRES_ROLES[usuario.rol] || usuario.rol)}</p>
                </div>
            </div>
            <div class="flex-grow flex flex-col gap-1">
                ${tabsHtml}
            </div>
            <form method="POST" action="/admin/logout" class="mt-4 border-t border-white/10 pt-4">
                <button type="submit" class="w-full flex items-center gap-3 px-4 py-3 rounded-2xl text-sm font-medium text-red-400 hover:bg-red-500/10 transition-all">
                    <i class="fa-solid fa-right-from-bracket w-5 text-center"></i> Cerrar sesión
                </button>
            </form>
        </aside>

        <div class="flex-grow p-4 md:p-8 overflow-x-hidden">
            <button onclick="document.getElementById('sidebar-admin').classList.toggle('abierta')" class="lg:hidden w-10 h-10 rounded-full bg-white/10 text-white flex items-center justify-center mb-4">
                <i class="fa-solid fa-bars"></i>
            </button>
            <div id="contenido-tab" class="space-y-6"></div>
        </div>
    </div>
    ${scriptToastYModal()}
    <script>
        const USUARIO_ACTUAL = ${JSON.stringify(usuarioPublico(usuario))};
        const ROL_ACTUAL = USUARIO_ACTUAL.rol;
        const PREFS_ACTUALES = ${JSON.stringify(prefs)};
        const TABS_DISPONIBLES = ${JSON.stringify(pestañas)};

        function cambiarTab(id) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('activo'));
            const btn = document.querySelector('[data-tab-btn="' + id + '"]');
            if (btn) btn.classList.add('activo');
            document.getElementById('sidebar-admin').classList.remove('abierta');
            cargarTab(id);
            history.replaceState(null, '', '#' + id);
        }

        async function cargarTab(id) {
            const cont = document.getElementById('contenido-tab');
            cont.innerHTML = '<div class="ultra-glass p-10 text-center text-gray-400">Cargando...</div>';
            try {
                const modulo = await import('/admin/tabs/' + id + '.js');
                await modulo.render(cont);
            } catch (e) {
                cont.innerHTML = '<div class="ultra-glass p-10 text-center text-red-400">Error al cargar esta sección.</div>';
                console.error(e);
            }
        }

        const tabInicial = window.location.hash ? window.location.hash.slice(1) : 'resumen';
        cambiarTab(tabInicial);
    <\/script>
</body>
</html>`;
}

function utilidadesClienteJs() {
  return `
    export function el(html) {
        const div = document.createElement('div');
        div.innerHTML = html.trim();
        return div.firstElementChild;
    }
    export async function apiGet(url) {
        const r = await fetch(url);
        return r.json();
    }
    export async function apiPost(url, body, esFormData) {
        const opciones = { method: 'POST' };
        if (esFormData) { opciones.body = body; }
        else { opciones.headers = { 'Content-Type': 'application/json' }; opciones.body = JSON.stringify(body); }
        const r = await fetch(url, opciones);
        return r.json();
    }
    export function convertirABlobWebp(archivo, calidad) {
        calidad = calidad || 0.85;
        return new Promise((resolve) => {
            if (!archivo || !archivo.type || !archivo.type.startsWith('image/')) { resolve(archivo); return; }
            if (typeof HTMLCanvasElement === 'undefined' || !HTMLCanvasElement.prototype.toBlob) { resolve(archivo); return; }
            const imagen = new Image();
            const url = URL.createObjectURL(archivo);
            imagen.onload = () => {
                try {
                    const canvas = document.createElement('canvas');
                    const maxLado = 1800;
                    let ancho = imagen.width, alto = imagen.height;
                    if (ancho > maxLado || alto > maxLado) {
                        const escala = maxLado / Math.max(ancho, alto);
                        ancho = Math.round(ancho * escala);
                        alto = Math.round(alto * escala);
                    }
                    canvas.width = ancho; canvas.height = alto;
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(imagen, 0, 0, ancho, alto);
                    canvas.toBlob((blob) => {
                        URL.revokeObjectURL(url);
                        if (!blob) { resolve(archivo); return; }
                        const nombreBase = archivo.name ? archivo.name.replace(/\.[^.]+$/, '') : 'imagen';
                        resolve(new File([blob], nombreBase + '.webp', { type: 'image/webp' }));
                    }, 'image/webp', calidad);
                } catch (e) { URL.revokeObjectURL(url); resolve(archivo); }
            };
            imagen.onerror = () => { URL.revokeObjectURL(url); resolve(archivo); };
            imagen.src = url;
        });
    }

    export function abrirRecortador(archivo, aspecto) {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay activo';
            overlay.style.zIndex = '300';
            overlay.innerHTML = \`
                <div class="modal-box ultra-glass p-6" style="max-width: 32rem;">
                    <h3 class="font-display text-lg font-bold text-white mb-4">Ajusta la imagen</h3>
                    <div id="marco-recorte" style="position:relative; width:100%; aspect-ratio: \${aspecto}; overflow:hidden; border-radius:1rem; background:#000; touch-action:none; cursor:grab;">
                        <img id="img-recorte" style="position:absolute; top:0; left:0; max-width:none; user-select:none; pointer-events:none;">
                    </div>
                    <input type="range" id="zoom-recorte" min="1" max="3" step="0.01" value="1" class="w-full mt-4">
                    <div class="flex gap-3 mt-4">
                        <button id="btn-confirmar-recorte" class="flex-grow px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Usar esta imagen</button>
                        <button id="btn-cancelar-recorte" class="px-6 py-3 rounded-xl font-bold bg-white/10 text-white">Cancelar</button>
                    </div>
                </div>
            \`;
            document.body.appendChild(overlay);

            const marco = overlay.querySelector('#marco-recorte');
            const img = overlay.querySelector('#img-recorte');
            const rangoZoom = overlay.querySelector('#zoom-recorte');
            const url = URL.createObjectURL(archivo);
            let escalaBase = 1, escalaZoom = 1, posX = 0, posY = 0, anchoNatural = 0, altoNatural = 0;
            let arrastrando = false, inicioX = 0, inicioY = 0;

            function aplicarTransformacion() {
                const escalaFinal = escalaBase * escalaZoom;
                img.style.width = (anchoNatural * escalaFinal) + 'px';
                img.style.height = (altoNatural * escalaFinal) + 'px';
                const anchoMarco = marco.clientWidth, altoMarco = marco.clientHeight;
                const anchoImg = anchoNatural * escalaFinal, altoImg = altoNatural * escalaFinal;
                posX = Math.min(0, Math.max(posX, anchoMarco - anchoImg));
                posY = Math.min(0, Math.max(posY, altoMarco - altoImg));
                img.style.transform = 'translate(' + posX + 'px,' + posY + 'px)';
            }

            img.onload = () => {
                anchoNatural = img.naturalWidth; altoNatural = img.naturalHeight;
                const anchoMarco = marco.clientWidth, altoMarco = marco.clientHeight;
                escalaBase = Math.max(anchoMarco / anchoNatural, altoMarco / altoNatural);
                posX = (anchoMarco - anchoNatural * escalaBase) / 2;
                posY = (altoMarco - altoNatural * escalaBase) / 2;
                aplicarTransformacion();
            };
            img.src = url;

            rangoZoom.addEventListener('input', () => { escalaZoom = parseFloat(rangoZoom.value); aplicarTransformacion(); });

            function iniciarArrastre(x, y) { arrastrando = true; inicioX = x - posX; inicioY = y - posY; marco.style.cursor = 'grabbing'; }
            function moverArrastre(x, y) { if (!arrastrando) return; posX = x - inicioX; posY = y - inicioY; aplicarTransformacion(); }
            function terminarArrastre() { arrastrando = false; marco.style.cursor = 'grab'; }

            marco.addEventListener('mousedown', (e) => iniciarArrastre(e.clientX, e.clientY));
            window.addEventListener('mousemove', (e) => moverArrastre(e.clientX, e.clientY));
            window.addEventListener('mouseup', terminarArrastre);
            marco.addEventListener('touchstart', (e) => { const t = e.touches[0]; iniciarArrastre(t.clientX, t.clientY); });
            marco.addEventListener('touchmove', (e) => { const t = e.touches[0]; moverArrastre(t.clientX, t.clientY); });
            marco.addEventListener('touchend', terminarArrastre);

            function limpiar() { URL.revokeObjectURL(url); overlay.remove(); }

            overlay.querySelector('#btn-cancelar-recorte').addEventListener('click', () => { limpiar(); resolve(archivo); });

            overlay.querySelector('#btn-confirmar-recorte').addEventListener('click', () => {
                const anchoMarco = marco.clientWidth, altoMarco = marco.clientHeight;
                const escalaFinal = escalaBase * escalaZoom;
                const canvas = document.createElement('canvas');
                canvas.width = anchoMarco; canvas.height = altoMarco;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, -posX / escalaFinal, -posY / escalaFinal, anchoMarco / escalaFinal, altoMarco / escalaFinal, 0, 0, anchoMarco, altoMarco);
                canvas.toBlob((blob) => {
                    limpiar();
                    if (!blob) { resolve(archivo); return; }
                    const nombreBase = archivo.name ? archivo.name.replace(/\.[^.]+$/, '') : 'imagen';
                    resolve(new File([blob], nombreBase + '-recortada.webp', { type: 'image/webp' }));
                }, 'image/webp', 0.9);
            });
        });
    }

    export async function prepararFormDataConImagen(formData, nombreCampo) {
        const archivo = formData.get(nombreCampo);
        if (archivo && archivo.size > 0) {
            const convertido = await convertirABlobWebp(archivo);
            formData.set(nombreCampo, convertido);
        }
        return formData;
    }

    export function badgeEstado(estado) {
        const colores = {
            enviado: 'bg-gray-500/20 text-gray-300', aprobado_redaccion: 'bg-brand-blue/20 text-brand-blue',
            asignado_difusion: 'bg-purple-500/20 text-purple-300', en_diseno: 'bg-purple-500/20 text-purple-300',
            aprobado_diseno: 'bg-brand-yellow/20 text-brand-yellow', publicado: 'bg-green-500/20 text-green-300',
            rechazado: 'bg-red-500/20 text-red-300', pendiente: 'bg-gray-500/20 text-gray-300',
            aprobada: 'bg-green-500/20 text-green-300', activo: 'bg-green-500/20 text-green-300',
            suspendido: 'bg-yellow-500/20 text-yellow-300', baneado: 'bg-red-500/20 text-red-300',
        };
        return '<span class="badge-estado ' + (colores[estado] || 'bg-gray-500/20 text-gray-300') + '">' + estado.replace(/_/g, ' ') + '</span>';
    }
  `;
}

const TABS_JS = {
  resumen: () => `
    import { el, apiGet, apiPost } from '/admin/tabs/_util.js';
    function envolverColapsable(id, tituloHtml, contenidoEl) {
        const colapsado = (PREFS_ACTUALES.widgets_resumen_colapsados || []).includes(id);
        const wrap = el('<div class="ultra-glass p-6 widget-colapsable' + (colapsado ? ' colapsado' : '') + '" data-widget-id="' + id + '"><div class="flex items-center justify-between gap-3 mb-2 widget-cabecera" style="cursor:pointer;">' + tituloHtml + '<button class="btn-toggle-widget text-gray-400"><i class="fa-solid ' + (colapsado ? 'fa-chevron-down' : 'fa-chevron-up') + '"></i></button></div><div class="widget-contenido"></div></div>');
        wrap.querySelector('.widget-contenido').appendChild(contenidoEl);
        wrap.querySelector('.widget-cabecera').addEventListener('click', async () => {
            wrap.classList.toggle('colapsado');
            const icono = wrap.querySelector('.btn-toggle-widget i');
            const ahoraColapsado = wrap.classList.contains('colapsado');
            icono.className = 'fa-solid ' + (ahoraColapsado ? 'fa-chevron-down' : 'fa-chevron-up');
            let lista = (PREFS_ACTUALES.widgets_resumen_colapsados || []).slice();
            if (ahoraColapsado && !lista.includes(id)) lista.push(id);
            if (!ahoraColapsado) lista = lista.filter(x => x !== id);
            PREFS_ACTUALES.widgets_resumen_colapsados = lista;
            await apiPost('/admin/api/mis-preferencias', { widgets_resumen_colapsados: lista });
        });
        return wrap;
    }
    export async function render(cont) {
        const data = await apiGet('/admin/api/resumen');
        if (!data.ok) { cont.innerHTML = '<div class="ultra-glass p-8 text-red-400">' + (data.error || 'Error') + '</div>'; return; }
        cont.innerHTML = '';
        const grid = el('<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6"></div>');
        const tarjetas = [
            { label: 'Artículos publicados', valor: data.total_publicados, icono: 'fa-newspaper', color: 'text-brand-yellow' },
            { label: 'Pendientes de revisión', valor: data.total_pendientes, icono: 'fa-hourglass-half', color: 'text-brand-blue' },
            { label: 'Voluntarios activos', valor: data.total_voluntarios, icono: 'fa-user-group', color: 'text-white' },
            { label: 'Tu racha actual', valor: data.mi_racha, icono: 'fa-fire', color: 'text-red-400' },
        ];
        tarjetas.forEach(t => {
            grid.appendChild(el('<div class="ultra-glass p-6"><i class="fa-solid ' + t.icono + ' text-2xl ' + t.color + ' mb-3"></i><p class="text-3xl font-display font-bold text-white">' + t.valor + '</p><p class="text-gray-400 text-sm mt-1">' + t.label + '</p></div>'));
        });
        cont.appendChild(grid);

        if (data.top3_redaccion || data.top3_difusion) {
            const topSection = el('<div class="grid grid-cols-1 md:grid-cols-2 gap-6"></div>');
            [['top3', 'Top 3 Redacción', data.top3_redaccion], ['top3d', 'Top 3 Difusión', data.top3_difusion]].forEach(([wid, titulo, lista]) => {
                const ul = el('<div class="space-y-3"></div>');
                (lista || []).forEach((u, i) => {
                    ul.appendChild(el('<div class="flex items-center gap-3"><span class="w-6 h-6 rounded-full bg-brand-yellow text-black text-xs font-bold flex items-center justify-center">' + (i+1) + '</span>' + (u.foto_url ? '<img src="' + u.foto_url + '" class="w-9 h-9 rounded-full object-cover">' : '<div class="w-9 h-9 rounded-full bg-white/10"></div>') + '<span class="text-white text-sm flex-grow">' + u.nombre_completo + '</span><span class="text-brand-blue font-bold text-sm">' + u.total + ' pts</span></div>'));
                });
                topSection.appendChild(envolverColapsable(wid, '<h3 class="font-display text-lg font-bold text-white">' + titulo + '</h3>', ul));
            });
            cont.appendChild(topSection);
        }

        if (data.mis_asignaciones && data.mis_asignaciones.length) {
            const ul = el('<div class="space-y-2"></div>');
            data.mis_asignaciones.forEach(a => {
                ul.appendChild(el('<div class="flex justify-between items-center p-3 rounded-xl bg-white/5"><span class="text-gray-200 text-sm">' + a.titulo + '</span><span class="text-brand-yellow text-xs font-bold">' + a.fecha_asignada + '</span></div>'));
            });
            cont.appendChild(envolverColapsable('mis-asignaciones', '<h3 class="font-display text-lg font-bold text-white">Tus temas asignados</h3>', ul));
        }
    }
  `,

  'publicar-articulo': () => `
    import { el, apiGet, apiPost, badgeEstado } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Publicar Artículo</h2>'));
        cont.appendChild(el('<p class="text-gray-400 text-sm -mt-4">Escribe y publica un artículo directamente, o revisa los que el equipo de redacción ya envió.</p>'));

        const formBox = el('<div class="ultra-glass p-6"></div>');
        formBox.innerHTML = \`
            <h3 class="font-display text-lg font-bold text-white mb-4">Nuevo artículo</h3>
            <form id="form-publicar-articulo" class="space-y-4">
                <input required name="titulo" placeholder="Título" maxlength="150" class="campo-form">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input required name="categoria" placeholder="Categoría" maxlength="60" class="campo-form">
                    <select required name="seccion" id="select-seccion-publicar" class="campo-form"><option value="">Cargando secciones...</option></select>
                </div>
                <textarea name="extracto" placeholder="Extracto corto (opcional)" maxlength="220" class="campo-form" rows="2"></textarea>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-2 block">Imagen de portada (opcional)</label>
                    <input type="file" name="portada" accept="image/*" class="campo-form">
                </div>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-2 block">Cuerpo del artículo (máx. 500 palabras)</label>
                    <div class="editor-toolbar flex gap-2 mb-2 flex-wrap">
                        <button type="button" data-cmd="bold" title="Negrita"><i class="fa-solid fa-bold"></i></button>
                        <button type="button" data-cmd="italic" title="Cursiva"><i class="fa-solid fa-italic"></i></button>
                        <button type="button" data-cmd="underline" title="Subrayado"><i class="fa-solid fa-underline"></i></button>
                        <button type="button" data-cmd="justifyLeft" title="Alinear izquierda"><i class="fa-solid fa-align-left"></i></button>
                        <button type="button" data-cmd="justifyCenter" title="Centrar"><i class="fa-solid fa-align-center"></i></button>
                        <button type="button" data-cmd="justifyFull" title="Justificar"><i class="fa-solid fa-align-justify"></i></button>
                        <button type="button" data-cmd="insertUnorderedList" title="Lista"><i class="fa-solid fa-list-ul"></i></button>
                        <button type="button" data-cmd="insertOrderedList" title="Lista numerada"><i class="fa-solid fa-list-ol"></i></button>
                        <button type="button" data-cmd="formatBlock" data-val="h2" title="Subtítulo"><i class="fa-solid fa-heading"></i></button>
                    </div>
                    <div contenteditable="true" id="editor-publicar-cuerpo" class="editor-cuerpo"></div>
                    <p class="text-xs text-gray-500 mt-1"><span id="contador-palabras-publicar">0</span> / 500 palabras</p>
                </div>
                <button type="submit" class="w-full px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Publicar artículo</button>
            </form>
        \`;
        cont.appendChild(formBox);

        const respuestaSecciones = await apiGet('/admin/api/secciones');
        const selectSeccion = formBox.querySelector('#select-seccion-publicar');
        selectSeccion.innerHTML = '<option value="">Selecciona una sección</option>';
        if (respuestaSecciones.ok && respuestaSecciones.secciones.length) {
            respuestaSecciones.secciones.forEach(s => selectSeccion.appendChild(el('<option value="' + s.nombre + '">' + s.nombre + '</option>')));
        } else {
            selectSeccion.innerHTML = '<option value="">No hay secciones creadas todavía</option>';
        }

        const editor = formBox.querySelector('#editor-publicar-cuerpo');
        try { document.execCommand('defaultParagraphSeparator', false, 'p'); } catch (e) {}
        formBox.querySelectorAll('.editor-toolbar button[data-cmd]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                editor.focus();
                document.execCommand(btn.dataset.cmd, false, btn.dataset.val || null);
            });
        });
        editor.addEventListener('input', () => {
            const texto = editor.innerText.trim();
            const palabras = texto ? texto.split(/\\s+/).length : 0;
            formBox.querySelector('#contador-palabras-publicar').textContent = palabras;
        });

        const formPublicar = formBox.querySelector('#form-publicar-articulo');
        formPublicar.addEventListener('submit', async (e) => {
            e.preventDefault();
            const texto = editor.innerText.trim();
            const palabras = texto ? texto.split(/\\s+/).length : 0;
            if (palabras > 500) { mostrarToast('El artículo supera las 500 palabras', 'error'); return; }
            if (palabras === 0) { mostrarToast('El cuerpo del artículo no puede estar vacío', 'error'); return; }
            const boton = formPublicar.querySelector('button[type="submit"]');
            const textoOriginalBoton = boton.textContent;
            boton.disabled = true; boton.textContent = 'Publicando...';
            let datos = new FormData(formPublicar);
            datos.append('cuerpo_html', editor.innerHTML);
            const resultado = await apiPost('/admin/api/articulos', datos, true);
            boton.disabled = false; boton.textContent = textoOriginalBoton;
            if (resultado.ok) { mostrarToast('Artículo publicado', 'exito'); formPublicar.reset(); editor.innerHTML = ''; formBox.querySelector('#contador-palabras-publicar').textContent = '0'; cargarPublicados(); }
            else { mostrarToast(resultado.error || 'Error al publicar', 'error'); }
        });

        cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Artículos enviados por el equipo (pendientes de revisión)</h3>'));
        const listaEnviadosBox = el('<div id="lista-articulos-enviados" class="space-y-4"></div>');
        cont.appendChild(listaEnviadosBox);

        async function cargarEnviados() {
            const data = await apiGet('/admin/api/articulos?estado=enviado');
            listaEnviadosBox.innerHTML = '';
            if (!data.ok || !data.articulos.length) { listaEnviadosBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">No hay artículos pendientes de revisión.</div>')); return; }
            data.articulos.forEach(a => {
                const box = el(\`<div class="ultra-glass p-6 space-y-3">
                    <div class="flex justify-between items-start gap-3">
                        <div><p class="text-brand-blue text-xs uppercase font-bold">\${a.categoria} · \${a.seccion}</p><p class="text-white font-bold">\${a.titulo}</p><p class="text-gray-400 text-xs">Por \${a.autor_username}</p></div>
                        \${badgeEstado(a.estado)}
                    </div>
                    <div class="prose prose-invert prose-sm max-w-none text-gray-300 bg-black/20 p-4 rounded-xl" style="max-height:220px; overflow-y:auto;">\${a.cuerpo_html || ''}</div>
                    <div class="flex gap-3 flex-wrap">
                        <button class="btn-aprobar-articulo px-5 py-2 rounded-xl font-bold bg-green-500/20 text-green-300 text-sm" data-id="\${a.id}">Aprobar y publicar</button>
                        <button class="btn-rechazar-articulo px-5 py-2 rounded-xl font-bold bg-red-900/40 text-red-200 text-sm" data-id="\${a.id}">Rechazar</button>
                    </div>
                </div>\`);
                listaEnviadosBox.appendChild(box);
            });
            listaEnviadosBox.querySelectorAll('.btn-aprobar-articulo').forEach(b => b.addEventListener('click', async () => {
                b.disabled = true; b.textContent = 'Procesando...';
                const r = await apiPost('/admin/api/articulos/' + b.dataset.id + '/aprobar', {});
                if (r.ok) { mostrarToast('Artículo aprobado y publicado', 'exito'); cargarEnviados(); cargarPublicados(); } else { mostrarToast(r.error || 'Error', 'error'); b.disabled = false; b.textContent = 'Aprobar y publicar'; }
            }));
            listaEnviadosBox.querySelectorAll('.btn-rechazar-articulo').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Rechazar este artículo?')) return;
                b.disabled = true; b.textContent = 'Procesando...';
                const r = await apiPost('/admin/api/articulos/' + b.dataset.id + '/rechazar', {});
                if (r.ok) { mostrarToast('Artículo rechazado', 'info'); cargarEnviados(); } else { mostrarToast(r.error || 'Error', 'error'); b.disabled = false; b.textContent = 'Rechazar'; }
            }));
        }
        cargarEnviados();

        cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Artículos publicados</h3>'));
        const listaPublicadosBox = el('<div id="lista-articulos-publicados" class="space-y-3"></div>');
        cont.appendChild(listaPublicadosBox);

        async function cargarPublicados() {
            const data = await apiGet('/admin/api/articulos?estado=publicado');
            listaPublicadosBox.innerHTML = '';
            if (!data.ok || !data.articulos.length) { listaPublicadosBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">Aún no hay artículos publicados.</div>')); return; }
            data.articulos.forEach(a => {
                const box = el('<div class="ultra-glass p-5 flex flex-col md:flex-row md:items-center justify-between gap-3"><div><p class="text-white font-bold">' + a.titulo + '</p><p class="text-gray-400 text-xs">' + a.categoria + ' · ' + a.seccion + ' · ' + (a.autor_username || '') + '</p></div><div class="flex items-center gap-3">' + badgeEstado(a.estado) + '<button class="btn-eliminar-articulo-publicado px-4 py-2 rounded-xl font-bold bg-red-900/40 text-red-200 text-xs" data-id="' + a.id + '">Eliminar</button></div></div>');
                listaPublicadosBox.appendChild(box);
            });
            listaPublicadosBox.querySelectorAll('.btn-eliminar-articulo-publicado').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Eliminar este artículo publicado permanentemente?')) return;
                b.disabled = true; b.textContent = 'Eliminando...';
                const r = await apiPost('/admin/api/articulos/' + b.dataset.id + '/eliminar', {});
                if (r.ok) { mostrarToast('Eliminado', 'info'); cargarPublicados(); } else { mostrarToast(r.error || 'Error', 'error'); b.disabled = false; b.textContent = 'Eliminar'; }
            }));
        }
        cargarPublicados();
    }
  `,

  'mis-articulos': () => `
    import { el, apiGet, apiPost, prepararFormDataConImagen, abrirRecortador, badgeEstado } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        let portadaRecortada = null;
        let tareaArticuloActiva = null;
        let tareasArticuloPendientes = [];
        const dataTareas = await apiGet('/admin/api/mis-tareas');
        if (dataTareas.ok) {
            tareasArticuloPendientes = (dataTareas.tareas || []).filter(t => (t.tipo === 'articulo' || t.tipo === 'redaccion') && (t.mi_estado === 'pendiente' || t.disponible_para_tomar) && t.estado !== 'publicada');
        }
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Mis Artículos</h2>'));

        const pendientesBox = el('<div id="lista-articulos-pendientes" class="space-y-3"></div>');
        cont.appendChild(pendientesBox);
        if (!tareasArticuloPendientes.length) {
            pendientesBox.appendChild(el('<div class="ultra-glass p-6 text-gray-500 text-sm">No tienes ningún artículo asignado por redactar.</div>'));
        } else {
            tareasArticuloPendientes.forEach(t => {
                const tarjeta = el('<div class="ultra-glass p-5 flex flex-col md:flex-row md:items-center justify-between gap-3"><div><p class="text-white font-bold">' + t.titulo + '</p><p class="text-gray-400 text-xs">' + (t.descripcion || '') + '</p></div><button class="btn-redactar-articulo px-5 py-2 rounded-full font-bold bg-brand-yellow text-black text-sm whitespace-nowrap" data-id="' + t.id + '">Redactar</button></div>');
                pendientesBox.appendChild(tarjeta);
            });
        }

        const formBox = el('<div id="form-articulo-box" class="ultra-glass p-6 hidden"></div>');
        formBox.innerHTML = \`
            <h3 class="font-display text-lg font-bold text-white mb-4">Nuevo artículo</h3>
            <form id="form-articulo" class="space-y-4">
                <input required name="titulo" placeholder="Título" maxlength="150" class="campo-form">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input required name="categoria" placeholder="Categoría" maxlength="60" class="campo-form">
                    <select required name="seccion" id="select-seccion-articulo" class="campo-form"><option value="">Cargando secciones...</option></select>
                </div>
                <textarea name="extracto" placeholder="Extracto corto (opcional)" maxlength="220" class="campo-form" rows="2"></textarea>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-2 block">Cuerpo del artículo (máx. 500 palabras)</label>
                    <div class="editor-toolbar flex gap-2 mb-2 flex-wrap">
                        <button type="button" data-cmd="bold" title="Negrita"><i class="fa-solid fa-bold"></i></button>
                        <button type="button" data-cmd="italic" title="Cursiva"><i class="fa-solid fa-italic"></i></button>
                        <button type="button" data-cmd="underline" title="Subrayado"><i class="fa-solid fa-underline"></i></button>
                        <button type="button" data-cmd="justifyLeft" title="Alinear izquierda"><i class="fa-solid fa-align-left"></i></button>
                        <button type="button" data-cmd="justifyCenter" title="Centrar"><i class="fa-solid fa-align-center"></i></button>
                        <button type="button" data-cmd="justifyFull" title="Justificar"><i class="fa-solid fa-align-justify"></i></button>
                        <button type="button" data-cmd="insertUnorderedList" title="Lista"><i class="fa-solid fa-list-ul"></i></button>
                        <button type="button" data-cmd="insertOrderedList" title="Lista numerada"><i class="fa-solid fa-list-ol"></i></button>
                        <button type="button" data-cmd="formatBlock" data-val="h2" title="Subtítulo"><i class="fa-solid fa-heading"></i></button>
                    </div>
                    <div contenteditable="true" id="editor-cuerpo" class="editor-cuerpo"></div>
                    <p class="text-xs text-gray-500 mt-1"><span id="contador-palabras">0</span> / 500 palabras</p>
                </div>
                <div class="flex gap-3">
                    <button type="submit" class="px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Enviar a revisión</button>
                    <button type="button" id="btn-cancelar-articulo" class="px-6 py-3 rounded-xl font-bold bg-white/10 text-white">Cancelar</button>
                </div>
            </form>
        \`;
        cont.appendChild(formBox);

        const respuestaSecciones = await apiGet('/admin/api/secciones');
        const selectSeccion = formBox.querySelector('#select-seccion-articulo');
        selectSeccion.innerHTML = '<option value="">Selecciona una sección</option>';
        if (respuestaSecciones.ok && respuestaSecciones.secciones.length) {
            respuestaSecciones.secciones.forEach(s => selectSeccion.appendChild(el('<option value="' + s.nombre + '">' + s.nombre + '</option>')));
        } else {
            selectSeccion.innerHTML = '<option value="">No hay secciones creadas todavía</option>';
        }

        const editor = formBox.querySelector('#editor-cuerpo');
        try { document.execCommand('defaultParagraphSeparator', false, 'p'); } catch (e) {}
        formBox.querySelectorAll('.editor-toolbar button[data-cmd]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                editor.focus();
                document.execCommand(btn.dataset.cmd, false, btn.dataset.val || null);
            });
        });
        editor.addEventListener('input', () => {
            const texto = editor.innerText.trim();
            const palabras = texto ? texto.split(/\\s+/).length : 0;
            formBox.querySelector('#contador-palabras').textContent = palabras;
        });

        pendientesBox.querySelectorAll('.btn-redactar-articulo').forEach(btn => {
            btn.addEventListener('click', () => {
                tareaArticuloActiva = tareasArticuloPendientes.find(t => String(t.id) === btn.dataset.id) || null;
                formBox.querySelector('h3').textContent = tareaArticuloActiva ? ('Redactar: ' + tareaArticuloActiva.titulo) : 'Nuevo artículo';
                formBox.classList.remove('hidden');
                formBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        });
        formBox.querySelector('#btn-cancelar-articulo').addEventListener('click', () => formBox.classList.add('hidden'));

        formBox.querySelector('#form-articulo').addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!tareaArticuloActiva) { mostrarToast('No tienes una tarea de artículo activa', 'error'); return; }
            const texto = editor.innerText.trim();
            const palabras = texto ? texto.split(/\\s+/).length : 0;
            if (palabras > 500) { mostrarToast('El artículo supera las 500 palabras', 'error'); return; }
            if (palabras === 0) { mostrarToast('El cuerpo del artículo no puede estar vacío', 'error'); return; }
            let datos = new FormData(e.target);
            datos.append('cuerpo_html', editor.innerHTML);
            const resultado = await apiPost('/admin/api/tareas-difusion/' + tareaArticuloActiva.id + '/enviar-articulo', datos, true);
            if (resultado.ok) { mostrarToast('Redacción enviada, esperando asignación de portada', 'exito'); formBox.classList.add('hidden'); e.target.reset(); editor.innerHTML=''; render(cont); }
            else { mostrarToast(resultado.error || 'Error al enviar', 'error'); }
        });

        const listaBox = el('<div id="lista-mis-articulos" class="space-y-3"></div>');
        cont.appendChild(listaBox);

        async function cargarLista() {
            const data = await apiGet('/admin/api/mis-articulos');
            listaBox.innerHTML = '';
            if (!data.ok || !data.articulos.length) { listaBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">Aún no has enviado artículos.</div>')); return; }
            data.articulos.forEach(a => {
                listaBox.appendChild(el('<div class="ultra-glass p-5 flex flex-col md:flex-row md:items-center justify-between gap-3"><div><p class="text-white font-bold">' + a.titulo + '</p><p class="text-gray-400 text-xs">' + a.seccion + ' · ' + (a.creado_en || '').slice(0,16) + '</p></div>' + badgeEstado(a.estado) + '</div>'));
            });
        }
        cargarLista();
    }
  `,

tareas: () => `
    import { el, apiGet, apiPost, prepararFormDataConImagen, badgeEstado } from '/admin/tabs/_util.js';
    const ES_ALTA_DIRECCION_TAREAS = (ROL_ACTUAL === 'director_general' || ROL_ACTUAL === 'subdirectora_general' || ROL_ACTUAL === 'secretaria');
    const NOMBRES_TIPO_TAREA = { articulo: 'Artículo', redaccion: 'Redacción', meme: 'Meme', historia: 'Historia', post: 'Post', evento: 'Evento' };
    function nombreTipoTarea(tipo) { return NOMBRES_TIPO_TAREA[tipo] || tipo; }

    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Tareas</h2>'));

        const voluntarios = await apiGet('/admin/api/usuarios?rol=voluntario');
        function llenarSelectVoluntarios(select, incluirTodos) {
            if (incluirTodos) select.appendChild(el('<option value="">Disponible para cualquiera</option>'));
            if (voluntarios.ok) voluntarios.usuarios.forEach(u => select.appendChild(el('<option value="' + u.username + '">' + u.nombre_completo + '</option>')));
        }

        if (ES_ALTA_DIRECCION_TAREAS) {
            const ideaBox = el(\`<div class="ultra-glass p-6">
                <h3 class="font-display text-lg font-bold text-white mb-4">Generar idea con IA</h3>
                <div class="flex flex-col md:flex-row gap-3">
                    <select id="select-tipo-idea" class="campo-form md:w-48">
                        <option value="redaccion">Redacción</option>
                        <option value="meme">Meme</option>
                        <option value="historia">Historia</option>
                        <option value="post">Post</option>
                    </select>
                    <button id="btn-generar-idea" class="px-5 py-2 rounded-xl font-bold bg-brand-blue text-black text-sm">Generar idea única</button>
                </div>
                <div id="resultado-idea" class="mt-4 text-gray-200 text-sm hidden ultra-glass p-4"></div>
                <form id="form-crear-tarea-ia" class="hidden mt-4 space-y-3">
                    <input type="hidden" name="descripcion">
                    <input type="hidden" name="tipo">
                    <input name="titulo" placeholder="Título de la tarea" required class="campo-form">
                    <div class="flex items-center gap-2">
                        <input type="checkbox" id="checkbox-tarea-ia-grupal" class="w-4 h-4">
                        <label for="checkbox-tarea-ia-grupal" class="text-sm text-gray-300">Esta es una tarea grupal (varios voluntarios la entregan juntos)</label>
                    </div>
                    <div id="contenedor-ia-individual">
                        <select name="asignado_a_username" class="campo-form" id="select-ia-individual"><option value="">Disponible para cualquiera</option></select>
                    </div>
                    <div id="contenedor-ia-grupo" class="hidden">
                        <p class="text-xs text-gray-400 mb-2">Selecciona los integrantes del grupo (mantén Ctrl/Cmd para elegir varios):</p>
                        <select multiple id="select-ia-grupo" class="campo-form" style="min-height:120px;"></select>
                    </div>
                    <button type="submit" class="w-full px-5 py-2 rounded-xl font-bold bg-brand-yellow text-black text-sm">Crear tarea con esta idea</button>
                </form>
            </div>\`);
            cont.appendChild(ideaBox);

            ideaBox.querySelector('#checkbox-tarea-ia-grupal').addEventListener('change', (e) => {
                ideaBox.querySelector('#contenedor-ia-individual').classList.toggle('hidden', e.target.checked);
                ideaBox.querySelector('#contenedor-ia-grupo').classList.toggle('hidden', !e.target.checked);
            });

            llenarSelectVoluntarios(ideaBox.querySelector('#select-ia-individual'), false);
            llenarSelectVoluntarios(ideaBox.querySelector('#select-ia-grupo'), false);

            ideaBox.querySelector('#btn-generar-idea').addEventListener('click', async (e) => {
                e.target.disabled = true; e.target.textContent = 'Generando...';
                const tipo = ideaBox.querySelector('#select-tipo-idea').value;
                const r = await apiPost('/admin/api/ideas-ia', { tipo });
                e.target.disabled = false; e.target.textContent = 'Generar idea única';
                if (r.ok) {
                    ideaBox.querySelector('#resultado-idea').textContent = r.idea;
                    ideaBox.querySelector('#resultado-idea').classList.remove('hidden');
                    ideaBox.querySelector('#form-crear-tarea-ia').classList.remove('hidden');
                    ideaBox.querySelector('[name="descripcion"]').value = r.idea;
                    ideaBox.querySelector('[name="tipo"]').value = tipo;
                } else { mostrarToast(r.error || 'Error al generar idea', 'error'); }
            });

            ideaBox.querySelector('#form-crear-tarea-ia').addEventListener('submit', async (e) => {
                e.preventDefault();
                const esGrupal = ideaBox.querySelector('#checkbox-tarea-ia-grupal').checked;
                const datos = Object.fromEntries(new FormData(e.target));
                if (esGrupal) {
                    const seleccionados = Array.from(ideaBox.querySelector('#select-ia-grupo').selectedOptions).map(o => o.value);
                    if (seleccionados.length < 2) { mostrarToast('Selecciona al menos 2 integrantes para una tarea grupal', 'error'); return; }
                    datos.miembros_grupo = seleccionados;
                    delete datos.asignado_a_username;
                } else if (!datos.asignado_a_username) {
                    delete datos.asignado_a_username;
                }
                const r = await apiPost('/admin/api/tareas-difusion', datos);
                if (r.ok) { mostrarToast('Tarea creada', 'exito'); e.target.reset(); e.target.classList.add('hidden'); ideaBox.querySelector('#contenedor-ia-individual').classList.remove('hidden'); ideaBox.querySelector('#contenedor-ia-grupo').classList.add('hidden'); cargarDisponibles(); } else mostrarToast(r.error, 'error');
            });

            const manualBox = el(\`<div class="ultra-glass p-6">
                <h3 class="font-display text-lg font-bold text-white mb-4">Crear tarea manual</h3>
                <form id="form-tarea-manual" class="space-y-3">
                    <select name="tipo" id="select-tipo-manual" required class="campo-form">
                        <option value="redaccion">Redacción</option>
                        <option value="meme">Meme</option>
                        <option value="historia">Historia</option>
                        <option value="post">Post</option>
                        <option value="evento">Evento</option>
                        <option value="__personalizado__">Otro (escribir categoría)</option>
                    </select>
                    <input name="tipo_personalizado" id="input-tipo-personalizado" placeholder="Nombre de la categoría personalizada" maxlength="40" class="campo-form hidden">
                    <input name="titulo" placeholder="Título de la tarea" required maxlength="150" class="campo-form">
                    <textarea name="descripcion" placeholder="Descripción de lo que hay que hacer" maxlength="600" class="campo-form" rows="3"></textarea>
                    <div class="flex items-center gap-2">
                        <input type="checkbox" id="checkbox-tarea-manual-grupal" class="w-4 h-4">
                        <label for="checkbox-tarea-manual-grupal" class="text-sm text-gray-300">Esta es una tarea grupal</label>
                    </div>
                    <div id="contenedor-manual-individual">
                        <select name="asignado_a_username" class="campo-form" id="select-manual-individual"></select>
                    </div>
                    <div id="contenedor-manual-grupo" class="hidden">
                        <p class="text-xs text-gray-400 mb-2">Selecciona los integrantes del grupo:</p>
                        <select multiple id="select-manual-grupo" class="campo-form" style="min-height:120px;"></select>
                    </div>
                    <button type="submit" class="w-full px-5 py-2 rounded-xl font-bold bg-brand-blue text-black text-sm">Crear tarea</button>
                </form>
            </div>\`);
            cont.appendChild(manualBox);

            llenarSelectVoluntarios(manualBox.querySelector('#select-manual-individual'), true);
            llenarSelectVoluntarios(manualBox.querySelector('#select-manual-grupo'), false);

            manualBox.querySelector('#select-tipo-manual').addEventListener('change', (e) => {
                manualBox.querySelector('#input-tipo-personalizado').classList.toggle('hidden', e.target.value !== '__personalizado__');
            });

            manualBox.querySelector('#checkbox-tarea-manual-grupal').addEventListener('change', (e) => {
                manualBox.querySelector('#contenedor-manual-individual').classList.toggle('hidden', e.target.checked);
                manualBox.querySelector('#contenedor-manual-grupo').classList.toggle('hidden', !e.target.checked);
            });

            manualBox.querySelector('#form-tarea-manual').addEventListener('submit', async (e) => {
                e.preventDefault();
                const esGrupalManual = manualBox.querySelector('#checkbox-tarea-manual-grupal').checked;
                const datos = Object.fromEntries(new FormData(e.target));
                if (datos.tipo === '__personalizado__') {
                    if (!datos.tipo_personalizado || !datos.tipo_personalizado.trim()) { mostrarToast('Escribe el nombre de la categoría personalizada', 'error'); return; }
                    datos.tipo = datos.tipo_personalizado.trim();
                }
                delete datos.tipo_personalizado;
                if (esGrupalManual) {
                    const seleccionados = Array.from(manualBox.querySelector('#select-manual-grupo').selectedOptions).map(o => o.value);
                    if (seleccionados.length < 2) { mostrarToast('Selecciona al menos 2 integrantes para una tarea grupal', 'error'); return; }
                    datos.miembros_grupo = seleccionados;
                    delete datos.asignado_a_username;
                } else if (!datos.asignado_a_username) {
                    delete datos.asignado_a_username;
                }
                const r = await apiPost('/admin/api/tareas-difusion', datos);
                if (r.ok) { mostrarToast('Tarea creada', 'exito'); e.target.reset(); manualBox.querySelector('#contenedor-manual-individual').classList.remove('hidden'); manualBox.querySelector('#contenedor-manual-grupo').classList.add('hidden'); manualBox.querySelector('#input-tipo-personalizado').classList.add('hidden'); cargarDisponibles(); }
                else mostrarToast(r.error, 'error');
            });
        }

        cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Tareas disponibles y mis tareas</h3>'));
        const listaMisTareasBox = el('<div id="lista-mis-tareas" class="space-y-3"></div>');
        cont.appendChild(listaMisTareasBox);

        async function cargarDisponibles() {
            const data = await apiGet('/admin/api/mis-tareas');
            listaMisTareasBox.innerHTML = '';
            if (!data.ok) { listaMisTareasBox.appendChild(el('<div class="ultra-glass p-8 text-red-400">' + (data.error || 'Error') + '</div>')); return; }
            if (!data.tareas.length) { listaMisTareasBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">No hay tareas pendientes por el momento.</div>')); return; }

            data.tareas.forEach(t => {
                const esCompartida = t.es_grupal || t.es_todos;
                const esDisponible = t.mi_estado === 'disponible';
                const etiqueta = t.disponible_para_tomar ? ' · Disponible para tomar' : (t.es_todos ? ' · Todo el equipo' : (t.es_grupal ? ' · Grupal' : ''));
                let bloqueAccionTarea;
                if (t.portada_asignado_a_username === (typeof USUARIO_ACTUAL !== 'undefined' ? USUARIO_ACTUAL.username : '') && t.estado === 'portada_asignada') {
                    bloqueAccionTarea = '<form class="flex flex-col md:flex-row gap-3 items-start md:items-center form-subir-portada" data-id="' + t.id + '">' +
                        (t.articulo_cuerpo_html ? '<div class="prose prose-invert prose-sm max-w-none text-gray-300 bg-black/20 p-3 rounded-xl w-full" style="max-height:180px; overflow-y:auto;">' + t.articulo_cuerpo_html + '</div>' : '') +
                        '<input type="file" name="archivo" accept="image/*" required class="campo-form">' +
                        '<button type="submit" class="px-5 py-2 rounded-xl font-bold bg-brand-yellow text-black text-sm whitespace-nowrap">Entregar portada</button>' +
                        '</form>';
                } else if ((t.tipo === 'articulo' || t.tipo === 'redaccion') && (t.mi_estado === 'pendiente' || esDisponible)) {
                    bloqueAccionTarea = '<a href="/admin#mis-articulos" class="inline-flex px-5 py-2 rounded-xl font-bold bg-brand-yellow text-black text-sm">Ir a redactar en Mis Artículos</a>';
                } else if (t.mi_estado === 'pendiente' || t.mi_estado === 'rechazada' || esDisponible) {
                    bloqueAccionTarea = '<form class="flex flex-col md:flex-row gap-3 items-start md:items-center form-subir-tarea" data-id="' + t.id + '">' +
                        '<input type="file" name="archivo" accept="image/*,video/*" required class="campo-form">' +
                        '<button type="submit" class="px-5 py-2 rounded-xl font-bold bg-brand-yellow text-black text-sm whitespace-nowrap">' + (t.mi_estado === 'rechazada' ? 'Reenviar' : (esDisponible ? 'Tomar y entregar' : 'Entregar')) + '</button>' +
                        '</form>';
                } else {
                    bloqueAccionTarea = '<p class="text-xs text-gray-500">Ya entregaste tu versión de esta tarea.</p>';
                }
                const box = el('<div class="ultra-glass p-6 space-y-3"><div class="flex justify-between items-start gap-3"><div><p class="text-brand-blue text-xs uppercase font-bold">' + nombreTipoTarea(t.tipo) + etiqueta + '</p><p class="text-white font-bold text-lg">' + t.titulo + '</p></div>' + badgeEstado(esDisponible ? 'pendiente' : t.mi_estado) + '</div><p class="text-gray-300 text-sm">' + (t.descripcion || '') + '</p>' + (esCompartida ? '<p class="text-xs text-gray-500">Cada integrante entrega su propia versión de forma independiente.</p>' : '') + bloqueAccionTarea + '</div>');
                listaMisTareasBox.appendChild(box);
            });

            listaMisTareasBox.querySelectorAll('.form-subir-tarea').forEach(form => {
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const id = form.dataset.id;
                    let datos = new FormData(form);
                    datos = await prepararFormDataConImagen(datos, 'archivo');
                    const resultado = await apiPost('/admin/api/tareas-difusion/' + id + '/enviar', datos, true);
                    if (resultado.ok) { mostrarToast('Entrega enviada', 'exito'); cargarDisponibles(); }
                    else { mostrarToast(resultado.error || 'Error', 'error'); }
                });
            });
            listaMisTareasBox.querySelectorAll('.form-subir-portada').forEach(form => {
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const id = form.dataset.id;
                    let datos = new FormData(form);
                    datos = await prepararFormDataConImagen(datos, 'archivo');
                    const resultado = await apiPost('/admin/api/tareas-difusion/' + id + '/enviar-portada', datos, true);
                    if (resultado.ok) { mostrarToast('Portada enviada', 'exito'); cargarDisponibles(); }
                    else { mostrarToast(resultado.error || 'Error', 'error'); }
                });
            });
        }
        cargarDisponibles();

        if (ES_ALTA_DIRECCION_TAREAS) {
            cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Gestor de tareas (todas)</h3>'));
            const gestorBox = el(\`<div class="ultra-glass p-4">
                <select id="select-filtro-gestor-tareas" class="campo-form mb-4">
                    <option value="pendiente">Pendientes</option>
                    <option value="enviada_redaccion">Esperando asignar portada</option>
                    <option value="portada_asignada">Portada asignada</option>
                    <option value="portada_enviada">Lista para publicar</option>
                    <option value="publicada">Publicadas</option>
                    <option value="rechazada">Rechazadas</option>
                </select>
                <div id="lista-gestor-tareas" class="space-y-3"></div>
            </div>\`);
            cont.appendChild(gestorBox);

            async function cargarGestorTareas() {
                const estado = gestorBox.querySelector('#select-filtro-gestor-tareas').value;
                const data = await apiGet('/admin/api/tareas-difusion?estado=' + estado);
                const lista = gestorBox.querySelector('#lista-gestor-tareas');
                lista.innerHTML = '';
                if (!data.ok || !data.tareas.length) { lista.appendChild(el('<div class="p-6 text-center text-gray-400 text-sm">No hay tareas en este estado.</div>')); return; }
                data.tareas.forEach(t => {
                    lista.appendChild(el(\`<div class="p-4 rounded-xl bg-white/5 flex items-center justify-between gap-3">
                        <div><p class="text-white text-sm font-bold">\${t.titulo}</p><p class="text-gray-400 text-xs">\${nombreTipoTarea(t.tipo)} · \${t.asignado_nombre_completo || 'sin asignar'}</p></div>
                        <button class="btn-eliminar-gestor px-4 py-2 rounded-xl font-bold bg-red-900/40 text-red-200 text-xs" data-id="\${t.id}">Eliminar</button>
                    </div>\`));
                });
                lista.querySelectorAll('.btn-eliminar-gestor').forEach(b => b.addEventListener('click', async () => {
                    if (!confirm('¿Eliminar esta tarea permanentemente?')) return;
                    const r = await apiPost('/admin/api/tareas-difusion/' + b.dataset.id + '/eliminar', {});
                    if (r.ok) { mostrarToast('Eliminada', 'info'); cargarGestorTareas(); } else mostrarToast(r.error, 'error');
                }));
            }
            gestorBox.querySelector('#select-filtro-gestor-tareas').addEventListener('change', cargarGestorTareas);
            cargarGestorTareas();

cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Redacciones listas para asignar portada</h3>'));
            const listaRedaccionBox = el('<div id="lista-redaccion-lista" class="space-y-4"></div>');
            cont.appendChild(listaRedaccionBox);

            async function cargarRedaccionLista() {
                const data = await apiGet('/admin/api/tareas-difusion?estado=enviada_redaccion');
                listaRedaccionBox.innerHTML = '';
                if (!data.ok || !data.tareas.length) { listaRedaccionBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">No hay redacciones esperando portada.</div>')); return; }
                data.tareas.forEach(t => {
                    const box = el(\`<div class="ultra-glass p-6 space-y-3">
                        <div class="flex justify-between items-start gap-3">
                            <div><p class="text-brand-blue text-xs uppercase font-bold">\${nombreTipoTarea(t.tipo)}</p><p class="text-white font-bold">\${t.titulo}</p><p class="text-gray-400 text-xs">Redactado por \${t.asignado_a_username || '—'}</p></div>
                            \${badgeEstado(t.estado)}
                        </div>
                        \${t.archivo_url ? '<img src="' + t.archivo_url + '" class="rounded-xl max-h-64 object-cover">' : ''}
                        \${t.articulo_cuerpo_html ? '<div class="prose prose-invert prose-sm max-w-none text-gray-300 bg-black/20 p-4 rounded-xl" style="max-height:220px; overflow-y:auto;">' + t.articulo_cuerpo_html + '</div>' : ''}
                        <select class="campo-form select-voluntario-portada" data-id="\${t.id}"><option value="">Selecciona quién hará la portada...</option></select>
                        <div class="flex gap-3 flex-wrap">
                            <button class="btn-asignar-portada px-5 py-2 rounded-xl font-bold bg-brand-yellow text-black text-sm" data-id="\${t.id}">Asignar portada</button>
                            <button class="btn-comentar-tarea px-5 py-2 rounded-xl font-bold bg-white/10 text-white text-sm" data-id="\${t.id}">Comentar</button>
                            <button class="btn-eliminar-tarea px-5 py-2 rounded-xl font-bold bg-red-900/40 text-red-200 text-sm" data-id="\${t.id}">Eliminar</button>
                        </div>
                    </div>\`);
                    listaRedaccionBox.appendChild(box);
                });
                const voluntariosPortada = await apiGet('/admin/api/usuarios?rol=voluntario');
                listaRedaccionBox.querySelectorAll('.select-voluntario-portada').forEach(sel => {
                    if (voluntariosPortada.ok) voluntariosPortada.usuarios.forEach(u => sel.appendChild(el('<option value="' + u.username + '">' + u.nombre_completo + '</option>')));
                });
                listaRedaccionBox.querySelectorAll('.btn-asignar-portada').forEach(b => b.addEventListener('click', async () => {
                    const sel = listaRedaccionBox.querySelector('.select-voluntario-portada[data-id="' + b.dataset.id + '"]');
                    if (!sel.value) { mostrarToast('Elige un voluntario para la portada', 'error'); return; }
                    const r = await apiPost('/admin/api/tareas-difusion/' + b.dataset.id + '/asignar-portada', { portada_asignado_a_username: sel.value });
                    if (r.ok) { mostrarToast('Portada asignada', 'exito'); cargarRedaccionLista(); } else mostrarToast(r.error, 'error');
                }));
                listaRedaccionBox.querySelectorAll('.btn-eliminar-tarea').forEach(b => b.addEventListener('click', async () => {
                    if (!confirm('¿Eliminar esta tarea permanentemente?')) return;
                    const r = await apiPost('/admin/api/tareas-difusion/' + b.dataset.id + '/eliminar', {});
                    if (r.ok) { mostrarToast('Eliminada', 'info'); cargarRedaccionLista(); } else mostrarToast(r.error, 'error');
                }));
                listaRedaccionBox.querySelectorAll('.btn-comentar-tarea').forEach(b => b.addEventListener('click', async () => {
                    const r = await apiPost('/admin/api/comentarios', { tipo_objeto: 'tarea_difusion', objeto_id: b.dataset.id, mensaje: prompt('Comentario:') || '' });
                    if (r.ok) mostrarToast('Comentario enviado', 'exito'); else mostrarToast(r.error, 'error');
                }));
            }
            cargarRedaccionLista();

            cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Portadas listas para publicar</h3>'));
            const listaPortadaBox = el('<div id="lista-portada-lista" class="space-y-4"></div>');
            cont.appendChild(listaPortadaBox);

            async function cargarPortadaLista() {
                const data = await apiGet('/admin/api/tareas-difusion?estado=portada_enviada');
                listaPortadaBox.innerHTML = '';
                if (!data.ok || !data.tareas.length) { listaPortadaBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">No hay portadas listas para publicar.</div>')); return; }
                data.tareas.forEach(t => {
                    const box = el(\`<div class="ultra-glass p-6 space-y-3">
                        <div class="flex justify-between items-start gap-3">
                            <div><p class="text-brand-blue text-xs uppercase font-bold">\${nombreTipoTarea(t.tipo)}</p><p class="text-white font-bold">\${t.titulo}</p><p class="text-gray-400 text-xs">Redacción: \${t.asignado_a_username || '—'} · Portada: \${t.portada_asignado_a_username || '—'}</p></div>
                            \${badgeEstado(t.estado)}
                        </div>
                        \${t.portada_archivo_url ? '<img src="' + t.portada_archivo_url + '" class="rounded-xl max-h-64 object-cover">' : ''}
                        \${t.articulo_cuerpo_html ? '<div class="prose prose-invert prose-sm max-w-none text-gray-300 bg-black/20 p-4 rounded-xl" style="max-height:220px; overflow-y:auto;">' + t.articulo_cuerpo_html + '</div>' : ''}
                        <div class="flex gap-3 flex-wrap">
                            <button class="btn-publicar-tarea px-5 py-2 rounded-xl font-bold bg-green-500/20 text-green-300 text-sm" data-id="\${t.id}">Publicar</button>
                            \${t.portada_archivo_url ? '<a href="' + t.portada_archivo_url + '" target="_blank" class="px-5 py-2 rounded-xl font-bold bg-brand-blue/20 text-brand-blue text-sm">Descargar portada</a>' : ''}
                            <button class="btn-eliminar-tarea px-5 py-2 rounded-xl font-bold bg-red-900/40 text-red-200 text-sm" data-id="\${t.id}">Eliminar</button>
                        </div>
                    </div>\`);
                    listaPortadaBox.appendChild(box);
                });
                listaPortadaBox.querySelectorAll('.btn-publicar-tarea').forEach(b => b.addEventListener('click', async () => {
                    const r = await apiPost('/admin/api/tareas-difusion/' + b.dataset.id + '/publicar', {});
                    if (r.ok) { mostrarToast('Publicado', 'exito'); cargarPortadaLista(); } else mostrarToast(r.error, 'error');
                }));
                listaPortadaBox.querySelectorAll('.btn-eliminar-tarea').forEach(b => b.addEventListener('click', async () => {
                    if (!confirm('¿Eliminar esta tarea permanentemente?')) return;
                    const r = await apiPost('/admin/api/tareas-difusion/' + b.dataset.id + '/eliminar', {});
                    if (r.ok) { mostrarToast('Eliminada', 'info'); cargarPortadaLista(); } else mostrarToast(r.error, 'error');
                }));
            }
            cargarPortadaLista();
        }
    }
  `,

postulantes: () => `
    import { el, apiGet, apiPost } from '/admin/tabs/_util.js';
    const ETIQUETAS_PREGUNTAS_TAB = [
        ['interes_area', '¿Por qué le interesa esta área?'],
        ['experiencia', '¿Tiene experiencia en esta área?'],
        ['habilidades', '3 habilidades que aporta'],
        ['proyectos_similares', '¿Ha participado en proyectos similares?'],
        ['trabajo_equipo', '¿Dispuesto/a a trabajar en equipo?'],
        ['acuerdo_contenido', '¿De acuerdo con el contenido respetuoso?'],
        ['tipo_contenido', 'Ideas de contenido / memes'],
        ['porque_seleccionar', '¿Por qué deberíamos seleccionarlo/a?'],
        ['algo_mas', 'Algo más que agregar'],
    ];
    const NOMBRES_AREA_TAB_POST = { general: 'Voluntariado' };

    let _jsPDFCargando = null;
    function cargarJsPDF() {
        if (window.jspdf) return Promise.resolve();
        if (_jsPDFCargando) return _jsPDFCargando;
        _jsPDFCargando = new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js';
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
        return _jsPDFCargando;
    }

    async function generarPdfPostulante(p) {
        await cargarJsPDF();
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({ unit: 'pt', format: 'letter' });
        const anchoPagina = doc.internal.pageSize.getWidth();
        const altoPagina = doc.internal.pageSize.getHeight();
        const margenX = 50;
        const anchoContenido = anchoPagina - margenX * 2;
        let y = 0;

        function fondoOscuro() {
            doc.setFillColor(3, 5, 9);
            doc.rect(0, 0, anchoPagina, altoPagina, 'F');
        }
        function nuevaPagina() {
            doc.addPage();
            fondoOscuro();
            y = 60;
        }
        function asegurarEspacio(alturaNecesaria) {
            if (y + alturaNecesaria > altoPagina - 60) nuevaPagina();
        }

        fondoOscuro();

        // Cabecera de marca
        doc.setFillColor(247, 213, 47);
        doc.roundedRect(margenX, 40, anchoContenido, 3, 1.5, 1.5, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(11);
        doc.setTextColor(117, 188, 225);
        doc.text("TO' REVUELTO", margenX, 68);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(140, 140, 150);
        doc.text('Postulación de voluntariado', margenX, 82);

        y = 120;

        // Nombre y meta
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(22);
        doc.setTextColor(255, 255, 255);
        doc.text(p.nombre_completo, margenX, y);
        y += 26;

        y += 4;

        const metaLineas = [
            ['Edad', String(p.edad || '—')],
            ['Ciudad', p.ciudad || '—'],
            ['Instagram', p.instagram || '—'],
            ['Teléfono', p.telefono || '—'],
            ['Correo', p.correo || '—'],
        ];
        doc.setFontSize(9.5);
        metaLineas.forEach(([etiqueta, valor]) => {
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(160, 160, 170);
            doc.text(etiqueta + ':', margenX, y);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(220, 220, 225);
            doc.text(String(valor), margenX + 75, y);
            y += 15;
        });

        y += 15;
        doc.setDrawColor(255, 255, 255);
        doc.setLineWidth(0.5);
        doc.line(margenX, y, anchoPagina - margenX, y);
        y += 30;

        // Preguntas y respuestas
        ETIQUETAS_PREGUNTAS_TAB.forEach(([campo, etiqueta]) => {
            const valor = p[campo];
            if (!valor) return;

            asegurarEspacio(40);

            doc.setFillColor(117, 188, 225);
            doc.roundedRect(margenX, y - 10, 3, 12, 1, 1, 'F');
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(10);
            doc.setTextColor(247, 213, 47);
            const etiquetaLineas = doc.splitTextToSize(etiqueta.toUpperCase(), anchoContenido - 12);
            doc.text(etiquetaLineas, margenX + 12, y);
            y += etiquetaLineas.length * 12 + 8;

            doc.setFont('helvetica', 'normal');
            doc.setFontSize(10.5);
            doc.setTextColor(225, 225, 230);
            const respuestaLineas = doc.splitTextToSize(String(valor), anchoContenido - 12);
            respuestaLineas.forEach((linea) => {
                asegurarEspacio(16);
                doc.text(linea, margenX + 12, y);
                y += 15;
            });
            y += 18;
        });

        // Footer en cada página
        const totalPaginas = doc.internal.getNumberOfPages();
        for (let i = 1; i <= totalPaginas; i++) {
            doc.setPage(i);
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(8);
            doc.setTextColor(90, 90, 100);
            doc.text("To' Revuelto — documento generado automáticamente", margenX, altoPagina - 30);
            doc.text('Página ' + i + ' de ' + totalPaginas, anchoPagina - margenX - 60, altoPagina - 30);
        }

        const nombreArchivo = 'postulante-' + p.nombre_completo.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '.pdf';
        doc.save(nombreArchivo);
    }

    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Postulantes de Voluntariado</h2>'));

        const filtrosBox = el(\`<div class="ultra-glass p-4 flex flex-col md:flex-row gap-3">
            <select id="select-filtro-estado-postulantes" class="campo-form md:w-52">
                <option value="pendiente">Pendientes</option>
                <option value="aceptado">Aceptados</option>
                <option value="rechazado">Rechazados</option>
            </select>
        </div>\`);
        cont.appendChild(filtrosBox);

        const listaBox = el('<div id="lista-postulantes" class="space-y-3"></div>');
        cont.appendChild(listaBox);

        async function cargarLista() {
            const filtroEstado = filtrosBox.querySelector('#select-filtro-estado-postulantes').value || 'pendiente';
            const data = await apiGet('/admin/api/postulantes-voluntariado?estado=' + encodeURIComponent(filtroEstado));
            listaBox.innerHTML = '';
            if (!data.ok) { listaBox.appendChild(el('<div class="ultra-glass p-8 text-center text-red-400">' + (data.error || 'Error') + '</div>')); return; }

            if (!data.postulantes.length) { listaBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">No hay postulantes en este filtro.</div>')); return; }

            data.postulantes.forEach(p => {
                const box = el(\`<div class="ultra-glass p-5 space-y-3">
                    <div class="flex flex-col md:flex-row md:items-start justify-between gap-3">
                        <div>
                            <p class="text-white font-bold text-lg">\${p.nombre_completo} <span class="text-gray-500 text-xs font-normal">(\${p.edad} años)</span></p>
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-1 mt-2 text-xs text-gray-400">
                                <p><i class="fa-solid fa-location-dot mr-1"></i> \${p.ciudad}</p>
                                <p><i class="fa-brands fa-instagram mr-1"></i> \${p.instagram}</p>
                                <p><i class="fa-solid fa-phone mr-1"></i> \${p.telefono}</p>
                            </div>
                            <p class="text-xs text-gray-500 mt-1">\${p.correo}</p>
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-3 pt-2 border-t border-white/10">
                        <button class="btn-ver-respuestas px-4 py-2 rounded-xl font-bold bg-brand-blue/20 text-brand-blue text-xs" data-id="\${p.id}">Ver respuestas</button>
                        \${p.estado === 'pendiente' ? \`
                        <button class="btn-rechazar-postulante px-4 py-2 rounded-xl font-bold bg-red-500/20 text-red-300 text-xs" data-id="\${p.id}">Rechazar</button>
                        <button class="btn-aceptar-postulante px-4 py-2 rounded-xl font-bold bg-green-500/20 text-green-300 text-xs" data-id="\${p.id}">Aceptar</button>
                        \` : \`<span class="px-4 py-2 rounded-xl font-bold text-xs \${p.estado === 'aceptado' ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}">\${p.estado === 'aceptado' ? 'Aceptado' : 'Rechazado'}</span>\`}
                    </div>
                </div>\`);
                listaBox.appendChild(box);
            });

            listaBox.querySelectorAll('.btn-ver-respuestas').forEach(b => b.addEventListener('click', async (e) => {
                const boton = e.currentTarget;
                const textoOriginal = boton.innerHTML;
                boton.disabled = true;
                boton.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generando PDF...';
                try {
                    const data = await apiGet('/admin/api/postulantes-voluntariado/' + b.dataset.id);
                    if (!data.ok) { mostrarToast(data.error || 'Error', 'error'); return; }
                    await generarPdfPostulante(data.postulante);
                    mostrarToast('PDF descargado', 'exito');
                } catch (err) {
                    mostrarToast('No se pudo generar el PDF', 'error');
                } finally {
                    boton.disabled = false;
                    boton.innerHTML = textoOriginal;
                }
            }));

            listaBox.querySelectorAll('.btn-aceptar-postulante').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Aceptar a este postulante? Se creará su cuenta automáticamente y se le notificará por WhatsApp y correo.')) return;
                b.disabled = true; b.textContent = 'Procesando...';
                const r = await apiPost('/admin/api/postulantes-voluntariado/' + b.dataset.id + '/aceptar', {});
                if (r.ok) { mostrarToast('Postulante aceptado y notificado', 'exito'); cargarLista(); }
                else { mostrarToast(r.error || 'Error al aceptar', 'error'); b.disabled = false; b.textContent = 'Aceptar'; }
            }));

            listaBox.querySelectorAll('.btn-rechazar-postulante').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Rechazar a este postulante?')) return;
                const r = await apiPost('/admin/api/postulantes-voluntariado/' + b.dataset.id + '/rechazar', {});
                if (r.ok) { mostrarToast('Postulante rechazado', 'info'); cargarLista(); }
                else { mostrarToast(r.error || 'Error al rechazar', 'error'); }
            }));
        }

        filtrosBox.querySelector('#select-filtro-estado-postulantes').addEventListener('change', cargarLista);
        cargarLista();
    }
  `,

  'directiva-admin': () => `
    import { el, apiGet, apiPost, prepararFormDataConImagen } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Directiva del Sitio</h2>'));
        const formBox = el(\`<div class="ultra-glass p-6">
            <h3 class="font-display text-lg font-bold text-white mb-4">Agregar miembro de directiva</h3>
            <form id="form-directiva" class="space-y-3">
                <input name="nombre_completo" placeholder="Nombre completo" required maxlength="120" class="campo-form">
                <input name="cargo" placeholder="Cargo" required maxlength="80" class="campo-form">
                <textarea name="biografia" placeholder="Biografía" maxlength="600" class="campo-form" rows="3"></textarea>
                <input name="orden" type="number" placeholder="Orden (0 primero)" class="campo-form">
                <input type="file" name="foto" accept="image/*" required class="campo-form">
                <button type="submit" class="px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Guardar</button>
            </form>
        </div>\`);
        cont.appendChild(formBox);
        formBox.querySelector('#form-directiva').addEventListener('submit', async (e) => {
            e.preventDefault();
            let datos = new FormData(e.target);
            datos = await prepararFormDataConImagen(datos, 'foto');
            const r = await apiPost('/admin/api/directiva', datos, true);
            if (r.ok) { mostrarToast('Miembro agregado', 'exito'); e.target.reset(); cargarLista(); } else mostrarToast(r.error, 'error');
        });

        const modalEditarBox = el(\`<div id="modal-editar-directiva" class="modal-overlay">
            <div class="modal-box ultra-glass p-8">
                <button type="button" class="modal-cerrar-btn" onclick="cerrarModal('modal-editar-directiva')"><i class="fa-solid fa-xmark"></i></button>
                <h3 class="font-display text-lg font-bold text-white mb-4">Editar miembro de directiva</h3>
                <form id="form-editar-directiva" class="space-y-3">
                    <input type="hidden" name="id">
                    <input name="nombre_completo" placeholder="Nombre completo" required maxlength="120" class="campo-form">
                    <input name="cargo" placeholder="Cargo" required maxlength="80" class="campo-form">
                    <textarea name="biografia" placeholder="Biografía" maxlength="600" class="campo-form" rows="3"></textarea>
                    <input name="orden" type="number" placeholder="Orden (0 primero)" class="campo-form">
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Nueva foto (opcional, deja vacío para mantener la actual)</label>
                        <input type="file" name="foto" accept="image/*" class="campo-form">
                    </div>
                    <button type="submit" class="w-full px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Guardar cambios</button>
                </form>
            </div>
        </div>\`);
        cont.appendChild(modalEditarBox);
        modalEditarBox.querySelector('#form-editar-directiva').addEventListener('submit', async (e) => {
            e.preventDefault();
            const id = modalEditarBox.querySelector('[name="id"]').value;
            let datos = new FormData(e.target);
            datos = await prepararFormDataConImagen(datos, 'foto');
            const r = await apiPost('/admin/api/directiva/' + id + '/editar', datos, true);
            if (r.ok) { mostrarToast('Miembro actualizado', 'exito'); cerrarModal('modal-editar-directiva'); cargarLista(); } else mostrarToast(r.error, 'error');
        });

        const listaBox = el('<div id="lista-directiva" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>');
        cont.appendChild(listaBox);
        async function cargarLista() {
            const data = await apiGet('/admin/api/directiva');
            listaBox.innerHTML = '';
            (data.miembros || []).forEach(m => {
                const box = el(\`<div class="ultra-glass p-5 flex flex-col items-center text-center gap-2">
                    \${m.foto_url ? '<img src="' + m.foto_url + '" class="w-20 h-20 rounded-full object-cover border-2 border-brand-yellow">' : '<div class="w-20 h-20 rounded-full bg-white/10"></div>'}
                    <p class="text-white font-bold">\${m.nombre_completo}</p>
                    <p class="text-brand-blue text-xs">\${m.cargo}</p>
                    <div class="flex gap-2 mt-2">
                        <button class="btn-editar-directiva px-4 py-2 rounded-xl font-bold bg-brand-blue/20 text-brand-blue text-xs" data-miembro='\${JSON.stringify(m).replace(/'/g, "&#39;")}'>Editar</button>
                        <button class="btn-eliminar-directiva px-4 py-2 rounded-xl font-bold bg-red-500/20 text-red-300 text-xs" data-id="\${m.id}">Eliminar</button>
                    </div>
                </div>\`);
                listaBox.appendChild(box);
            });
            listaBox.querySelectorAll('.btn-editar-directiva').forEach(b => b.addEventListener('click', () => {
                const m = JSON.parse(b.dataset.miembro.replace(/&#39;/g, "'"));
                const formEditar = modalEditarBox.querySelector('#form-editar-directiva');
                formEditar.querySelector('[name="id"]').value = m.id;
                formEditar.querySelector('[name="nombre_completo"]').value = m.nombre_completo || '';
                formEditar.querySelector('[name="cargo"]').value = m.cargo || '';
                formEditar.querySelector('[name="biografia"]').value = m.biografia || '';
                formEditar.querySelector('[name="orden"]').value = m.orden || 0;
                formEditar.querySelector('[name="foto"]').value = '';
                abrirModal('modal-editar-directiva');
            }));
            listaBox.querySelectorAll('.btn-eliminar-directiva').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Eliminar este miembro de la directiva?')) return;
                const r = await apiPost('/admin/api/directiva/' + b.dataset.id + '/eliminar', {});
                if (r.ok) { mostrarToast('Eliminado', 'info'); cargarLista(); } else mostrarToast(r.error, 'error');
            }));
        }
        cargarLista();
    }
  `,

  'comunidad-admin': () => `
    import { el, apiGet, apiPost } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Comunidad — Publicaciones y reportes</h2>'));

        const modalEditarConv = el(\`<div id="modal-editar-convocatoria" class="modal-overlay">
            <div class="modal-box ultra-glass p-8">
                <button type="button" class="modal-cerrar-btn" onclick="cerrarModal('modal-editar-convocatoria')"><i class="fa-solid fa-xmark"></i></button>
                <h3 class="font-display text-lg font-bold text-white mb-4">Editar publicación</h3>
                <form id="form-editar-convocatoria" class="space-y-3">
                    <input type="hidden" name="id">
                    <input name="titulo" placeholder="Título" required maxlength="150" class="campo-form">
                    <textarea name="descripcion" placeholder="Descripción" maxlength="600" class="campo-form" rows="3"></textarea>
                    <input name="fecha_evento" type="date" class="campo-form">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria abre</label>
                            <input name="fecha_apertura" type="date" class="campo-form">
                        </div>
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria cierra</label>
                            <input name="fecha_cierre" type="date" class="campo-form">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <select name="cupos_tipo" id="select-cupos-tipo-editar-conv" class="campo-form">
                            <option value="ilimitado">Cupos ilimitados</option>
                            <option value="personalizado">Cupos personalizados</option>
                        </select>
                        <input name="cupos_cantidad" id="input-cupos-cantidad-editar-conv" type="number" min="1" placeholder="Cantidad de cupos" class="campo-form hidden">
                    </div>
                    <input name="form_url" type="url" placeholder="https://... (link del formulario de registro)" required class="campo-form">
                    <div class="flex items-center gap-2 p-3 rounded-xl bg-white/5">
                        <input type="checkbox" name="convocatoria_cerrada" id="checkbox-cerrar-editar-conv" class="w-4 h-4">
                        <label for="checkbox-cerrar-editar-conv" class="text-sm text-gray-300">Cerrar convocatoria (oculta el botón de registro al público)</label>
                    </div>
                    <button type="submit" class="w-full px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Guardar cambios</button>
                </form>
            </div>
        </div>\`);
        cont.appendChild(modalEditarConv);
        modalEditarConv.querySelector('#select-cupos-tipo-editar-conv').addEventListener('change', (e) => {
            modalEditarConv.querySelector('#input-cupos-cantidad-editar-conv').classList.toggle('hidden', e.target.value !== 'personalizado');
        });
        modalEditarConv.querySelector('#form-editar-convocatoria').addEventListener('submit', async (e) => {
            e.preventDefault();
            const datos = Object.fromEntries(new FormData(e.target));
            datos.convocatoria_cerrada = modalEditarConv.querySelector('#checkbox-cerrar-editar-conv').checked;
            const r = await apiPost('/admin/api/convocatorias/' + datos.id + '/editar', datos);
            if (r.ok) { mostrarToast('Publicación actualizada', 'exito'); cerrarModal('modal-editar-convocatoria'); cargarLista(); } else mostrarToast(r.error, 'error');
        });

        const listaBox = el('<div id="lista-convocatorias-admin" class="space-y-3"></div>');
        cont.appendChild(listaBox);
        async function cargarLista() {
            const data = await apiGet('/admin/api/convocatorias');
            listaBox.innerHTML = '';
            if (!data.ok || !data.convocatorias.length) { listaBox.appendChild(el('<div class="ultra-glass p-8 text-center text-gray-400">No hay publicaciones todavía.</div>')); return; }
            data.convocatorias.forEach(c => {
                const box = el(\`<div class="ultra-glass p-5 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div><p class="text-white font-bold">\${c.titulo}</p><p class="text-gray-400 text-xs">\${c.tipo} · por \${c.contacto_nombre} (\${c.contacto_telefono})</p>\${c.reportes_count > 0 ? '<p class="text-red-400 text-xs font-bold mt-1">' + c.reportes_count + ' reporte(s)</p>' : ''}</div>
                    <div class="flex gap-2">
                        <button class="btn-editar-convocatoria px-4 py-2 rounded-xl font-bold bg-brand-blue/20 text-brand-blue text-xs" data-conv='\${JSON.stringify(c).replace(/'/g, "&#39;")}'>Editar</button>
                        <button class="btn-eliminar-convocatoria px-4 py-2 rounded-xl font-bold bg-red-500/20 text-red-300 text-xs" data-id="\${c.id}">Eliminar</button>
                    </div>
                </div>\`);
                listaBox.appendChild(box);
            });
            listaBox.querySelectorAll('.btn-editar-convocatoria').forEach(b => b.addEventListener('click', () => {
                const c = JSON.parse(b.dataset.conv.replace(/&#39;/g, "'"));
                const formEditar = modalEditarConv.querySelector('#form-editar-convocatoria');
                formEditar.querySelector('[name="id"]').value = c.id;
                formEditar.querySelector('[name="titulo"]').value = c.titulo || '';
                formEditar.querySelector('[name="descripcion"]').value = c.descripcion || '';
                formEditar.querySelector('[name="fecha_evento"]').value = (c.fecha_evento || '').slice(0, 10);
                formEditar.querySelector('[name="fecha_apertura"]').value = (c.fecha_apertura || '').slice(0, 10);
                formEditar.querySelector('[name="fecha_cierre"]').value = (c.fecha_cierre || '').slice(0, 10);
                formEditar.querySelector('[name="form_url"]').value = c.form_url || '';
                formEditar.querySelector('[name="cupos_tipo"]').value = c.cupos_tipo || 'ilimitado';
                formEditar.querySelector('[name="cupos_cantidad"]').value = c.cupos_cantidad || '';
                formEditar.querySelector('#input-cupos-cantidad-editar-conv').classList.toggle('hidden', (c.cupos_tipo || 'ilimitado') !== 'personalizado');
                formEditar.querySelector('#checkbox-cerrar-editar-conv').checked = !!c.convocatoria_cerrada;
                abrirModal('modal-editar-convocatoria');
            }));
            listaBox.querySelectorAll('.btn-eliminar-convocatoria').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Eliminar esta publicación permanentemente?')) return;
                const r = await apiPost('/admin/api/convocatorias/' + b.dataset.id + '/eliminar', {});
                if (r.ok) { mostrarToast('Eliminada', 'info'); cargarLista(); } else mostrarToast(r.error, 'error');
            }));
        }
        cargarLista();
    }
  `,

  'eventos-admin': () => `
    import { el, apiGet, apiPost, prepararFormDataConImagen, abrirRecortador, badgeEstado } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Eventos</h2>'));
        let imagenRecortada = null;
        const formBox = el(\`<div class="ultra-glass p-6">
            <h3 class="font-display text-lg font-bold text-white mb-4">Crear evento</h3>
            <form id="form-evento" class="space-y-3">
                <input name="titulo" placeholder="Título" required maxlength="150" class="campo-form">
                <textarea name="descripcion" placeholder="Descripción" maxlength="600" class="campo-form" rows="3"></textarea>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <input name="fecha_evento" type="date" required class="campo-form">
                    <input name="lugar" placeholder="Lugar" maxlength="150" class="campo-form">
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria abre</label>
                        <input name="fecha_apertura" type="date" class="campo-form">
                    </div>
                    <div>
                        <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria cierra</label>
                        <input name="fecha_cierre" type="date" class="campo-form">
                    </div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <select name="cupos_tipo" id="select-cupos-tipo-evento" class="campo-form">
                        <option value="ilimitado">Cupos ilimitados</option>
                        <option value="personalizado">Cupos personalizados</option>
                    </select>
                    <input name="cupos_cantidad" id="input-cupos-cantidad-evento" type="number" min="1" placeholder="Cantidad de cupos" class="campo-form hidden">
                </div>
                <input name="form_url" type="url" placeholder="https://... (link del formulario de registro)" required class="campo-form">
                <div>
                    <input type="file" name="imagen" id="input-imagen-evento" accept="image/*" class="campo-form">
                    <div id="previsualizacion-imagen-evento" class="mt-2"></div>
                </div>
                <button type="submit" class="px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Crear (pendiente de aprobación)</button>
            </form>
        </div>\`);
        cont.appendChild(formBox);

        const modalEditarBox = el(\`<div id="modal-editar-evento" class="modal-overlay">
            <div class="modal-box ultra-glass p-8">
                <button type="button" class="modal-cerrar-btn" onclick="cerrarModal('modal-editar-evento')"><i class="fa-solid fa-xmark"></i></button>
                <h3 class="font-display text-lg font-bold text-white mb-4">Editar evento</h3>
                <form id="form-editar-evento" class="space-y-3">
                    <input type="hidden" name="id">
                    <input name="titulo" placeholder="Título" required maxlength="150" class="campo-form">
                    <textarea name="descripcion" placeholder="Descripción" maxlength="600" class="campo-form" rows="3"></textarea>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <input name="fecha_evento" type="date" required class="campo-form">
                        <input name="lugar" placeholder="Lugar" maxlength="150" class="campo-form">
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria abre</label>
                            <input name="fecha_apertura" type="date" class="campo-form">
                        </div>
                        <div>
                            <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Convocatoria cierra</label>
                            <input name="fecha_cierre" type="date" class="campo-form">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <select name="cupos_tipo" id="select-cupos-tipo-editar-evento" class="campo-form">
                            <option value="ilimitado">Cupos ilimitados</option>
                            <option value="personalizado">Cupos personalizados</option>
                        </select>
                        <input name="cupos_cantidad" id="input-cupos-cantidad-editar-evento" type="number" min="1" placeholder="Cantidad de cupos" class="campo-form hidden">
                    </div>
                    <input name="form_url" type="url" placeholder="https://... (link del formulario de registro)" required class="campo-form">
                    <div class="flex items-center gap-2 p-3 rounded-xl bg-white/5">
                        <input type="checkbox" name="convocatoria_cerrada" id="checkbox-cerrar-editar-evento" class="w-4 h-4">
                        <label for="checkbox-cerrar-editar-evento" class="text-sm text-gray-300">Cerrar convocatoria (oculta el botón de registro al público)</label>
                    </div>
                    <button type="submit" class="w-full px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Guardar cambios</button>
                </form>
            </div>
        </div>\`);
        cont.appendChild(modalEditarBox);
        modalEditarBox.querySelector('#select-cupos-tipo-editar-evento').addEventListener('change', (e) => {
            modalEditarBox.querySelector('#input-cupos-cantidad-editar-evento').classList.toggle('hidden', e.target.value !== 'personalizado');
        });

        formBox.querySelector('#select-cupos-tipo-evento').addEventListener('change', (e) => {
            formBox.querySelector('#input-cupos-cantidad-evento').classList.toggle('hidden', e.target.value !== 'personalizado');
        });

        formBox.querySelector('#input-imagen-evento').addEventListener('change', async (e) => {
            const archivo = e.target.files[0];
            if (!archivo) return;
            imagenRecortada = await abrirRecortador(archivo, '1/1');
            const previa = formBox.querySelector('#previsualizacion-imagen-evento');
            previa.innerHTML = '';
            const imgPreview = document.createElement('img');
            imgPreview.src = URL.createObjectURL(imagenRecortada);
            imgPreview.style.cssText = 'width:100%; max-height:200px; object-fit:cover; border-radius:0.75rem;';
            previa.appendChild(imgPreview);
        });

        formBox.querySelector('#form-evento').addEventListener('submit', async (e) => {
            e.preventDefault();
            let datos = new FormData(e.target);
            if (imagenRecortada) datos.set('imagen', imagenRecortada);
            datos = await prepararFormDataConImagen(datos, 'imagen');
            const r = await apiPost('/admin/api/eventos', datos, true);
            if (r.ok) { mostrarToast('Evento creado', 'exito'); e.target.reset(); imagenRecortada = null; formBox.querySelector('#previsualizacion-imagen-evento').innerHTML = ''; cargarLista(); } else mostrarToast(r.error, 'error');
        });

        const listaBox = el('<div id="lista-eventos-admin" class="space-y-3"></div>');
        cont.appendChild(listaBox);
        async function cargarLista() {
            const data = await apiGet('/admin/api/eventos');
            listaBox.innerHTML = '';
            (data.eventos || []).forEach(ev => {
                const box = el(\`<div class="ultra-glass p-5 space-y-3">
                    <div class="flex justify-between items-start gap-3">
                        <div><p class="text-white font-bold">\${ev.titulo}</p><p class="text-gray-400 text-xs">\${ev.fecha_evento}</p></div>
                        \${badgeEstado(ev.estado)}
                    </div>
                    \${ev.estado === 'pendiente' ? \`<div class="flex gap-3"><button class="btn-aprobar-evento px-5 py-2 rounded-xl font-bold bg-green-500/20 text-green-300 text-sm" data-id="\${ev.id}">Aprobar y publicar</button><button class="btn-rechazar-evento px-5 py-2 rounded-xl font-bold bg-red-500/20 text-red-300 text-sm" data-id="\${ev.id}">Rechazar</button></div>\` : ''}
                    <button class="btn-abrir-editar-evento px-4 py-2 rounded-xl font-bold bg-brand-blue/20 text-brand-blue text-xs" data-evento='\${JSON.stringify(ev).replace(/'/g, "&#39;")}'>Editar evento</button>
                    \${ev.estado === 'aprobado' ? \`
                    <div class="space-y-2">
                        <label class="text-xs text-gray-400 uppercase tracking-wider block">Asistentes confirmados</label>
                        <div class="editor-toolbar flex gap-2">
                            <button type="button" class="btn-editor-asistentes" data-cmd="bold" data-id="\${ev.id}"><i class="fa-solid fa-bold"></i></button>
                            <button type="button" class="btn-editor-asistentes" data-cmd="italic" data-id="\${ev.id}"><i class="fa-solid fa-italic"></i></button>
                            <button type="button" class="btn-editor-asistentes" data-cmd="underline" data-id="\${ev.id}"><i class="fa-solid fa-underline"></i></button>
                            <button type="button" class="btn-editor-asistentes" data-cmd="insertUnorderedList" data-id="\${ev.id}"><i class="fa-solid fa-list-ul"></i></button>
                            <button type="button" class="btn-editor-asistentes" data-cmd="insertOrderedList" data-id="\${ev.id}"><i class="fa-solid fa-list-ol"></i></button>
                        </div>
                        <div contenteditable="true" class="editor-cuerpo editor-cuerpo-asistentes asistentes-evento" data-id="\${ev.id}">\${ev.asistentes_texto || ''}</div>
                        <button class="btn-guardar-asistentes px-5 py-2 rounded-xl font-bold bg-brand-blue text-black text-sm" data-id="\${ev.id}">Guardar asistentes</button>
                    </div>
                    \` : ''}
                    <button class="btn-eliminar-evento px-4 py-2 rounded-xl font-bold bg-red-900/40 text-red-200 text-xs" data-id="\${ev.id}">Eliminar permanentemente</button>
                </div>\`);
                listaBox.appendChild(box);
            });
            listaBox.querySelectorAll('.btn-aprobar-evento').forEach(b => b.addEventListener('click', async () => {
                const r = await apiPost('/admin/api/eventos/' + b.dataset.id + '/aprobar', {});
                if (r.ok) { mostrarToast('Evento aprobado', 'exito'); cargarLista(); } else mostrarToast(r.error, 'error');
            }));
            listaBox.querySelectorAll('.btn-rechazar-evento').forEach(b => b.addEventListener('click', async () => {
                const r = await apiPost('/admin/api/eventos/' + b.dataset.id + '/rechazar', {});
                if (r.ok) { mostrarToast('Evento rechazado', 'info'); cargarLista(); } else mostrarToast(r.error, 'error');
            }));
            listaBox.querySelectorAll('.btn-eliminar-evento').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Eliminar este evento permanentemente? Esta acción no se puede deshacer.')) return;
                const r = await apiPost('/admin/api/eventos/' + b.dataset.id + '/eliminar', {});
                if (r.ok) { mostrarToast('Evento eliminado', 'info'); cargarLista(); } else mostrarToast(r.error, 'error');
            }));
            listaBox.querySelectorAll('.btn-abrir-editar-evento').forEach(b => b.addEventListener('click', () => {
                const ev = JSON.parse(b.dataset.evento.replace(/&#39;/g, "'"));
                const formEditar = modalEditarBox.querySelector('#form-editar-evento');
                formEditar.querySelector('[name="id"]').value = ev.id;
                formEditar.querySelector('[name="titulo"]').value = ev.titulo || '';
                formEditar.querySelector('[name="descripcion"]').value = ev.descripcion || '';
                formEditar.querySelector('[name="fecha_evento"]').value = (ev.fecha_evento || '').slice(0, 10);
                formEditar.querySelector('[name="lugar"]').value = ev.lugar || '';
                formEditar.querySelector('[name="fecha_apertura"]').value = (ev.fecha_apertura || '').slice(0, 10);
                formEditar.querySelector('[name="fecha_cierre"]').value = (ev.fecha_cierre || '').slice(0, 10);
                formEditar.querySelector('[name="form_url"]').value = ev.form_url || '';
                formEditar.querySelector('[name="cupos_tipo"]').value = ev.cupos_tipo || 'ilimitado';
                formEditar.querySelector('[name="cupos_cantidad"]').value = ev.cupos_cantidad || '';
                formEditar.querySelector('#input-cupos-cantidad-editar-evento').classList.toggle('hidden', (ev.cupos_tipo || 'ilimitado') !== 'personalizado');
                formEditar.querySelector('#checkbox-cerrar-editar-evento').checked = !!ev.convocatoria_cerrada;
                abrirModal('modal-editar-evento');
            }));
            modalEditarBox.querySelector('#form-editar-evento').addEventListener('submit', async (e) => {
                e.preventDefault();
                const datos = Object.fromEntries(new FormData(e.target));
                datos.convocatoria_cerrada = modalEditarBox.querySelector('#checkbox-cerrar-editar-evento').checked;
                const r = await apiPost('/admin/api/eventos/' + datos.id + '/editar', datos);
                if (r.ok) { mostrarToast('Evento actualizado', 'exito'); cerrarModal('modal-editar-evento'); cargarLista(); } else mostrarToast(r.error, 'error');
            });
            listaBox.querySelectorAll('.btn-editor-asistentes').forEach(b => b.addEventListener('click', () => {
                const editor = listaBox.querySelector('.asistentes-evento[data-id="' + b.dataset.id + '"]');
                editor.focus();
                document.execCommand(b.dataset.cmd);
            }));
            listaBox.querySelectorAll('.btn-guardar-asistentes').forEach(b => b.addEventListener('click', async () => {
                const editor = listaBox.querySelector('.asistentes-evento[data-id="' + b.dataset.id + '"]');
                const r = await apiPost('/admin/api/eventos/' + b.dataset.id + '/asistentes', { asistentes_texto: editor.innerHTML });
                if (r.ok) mostrarToast('Guardado', 'exito'); else mostrarToast(r.error, 'error');
            }));
        }
        cargarLista();
    }
  `,

  usuarios: () => `
    import { el, apiGet, apiPost, badgeEstado } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Usuarios</h2>'));

        const modalMensajeBox = el(\`<div id="modal-mensaje-whatsapp-usuario" class="modal-overlay">
            <div class="modal-box ultra-glass p-8">
                <button type="button" class="modal-cerrar-btn" onclick="cerrarModal('modal-mensaje-whatsapp-usuario')"><i class="fa-solid fa-xmark"></i></button>
                <h3 class="font-display text-lg font-bold text-white mb-1">Escribir por WhatsApp</h3>
                <p class="text-gray-400 text-sm mb-4">Para: <span id="nombre-destino-mensaje-whatsapp" class="text-brand-blue font-bold"></span></p>
                <form id="form-mensaje-whatsapp-usuario" class="space-y-3">
                    <input type="hidden" name="username_destino">
                    <textarea name="mensaje" placeholder="Escribe tu mensaje..." required maxlength="900" class="campo-form" rows="4"></textarea>
                    <button type="submit" class="w-full px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Enviar por WhatsApp</button>
                </form>
            </div>
        </div>\`);
        cont.appendChild(modalMensajeBox);
        modalMensajeBox.querySelector('#form-mensaje-whatsapp-usuario').addEventListener('submit', async (e) => {
            e.preventDefault();
            const datos = Object.fromEntries(new FormData(e.target));
            const boton = e.target.querySelector('button[type="submit"]');
            boton.disabled = true; boton.textContent = 'Enviando...';
            const r = await apiPost('/admin/api/usuarios/' + datos.username_destino + '/mensaje-whatsapp', { mensaje: datos.mensaje });
            boton.disabled = false; boton.textContent = 'Enviar por WhatsApp';
            if (r.ok) { mostrarToast('Mensaje enviado', 'exito'); cerrarModal('modal-mensaje-whatsapp-usuario'); e.target.reset(); }
            else { mostrarToast(r.error || 'Error al enviar', 'error'); }
        });

        const solicitudesBox = el('<div><h3 class="font-display text-lg font-bold text-white mb-3">Solicitudes pendientes</h3><div id="lista-solicitudes" class="space-y-3"></div></div>');
        cont.appendChild(solicitudesBox);
        async function cargarSolicitudes() {
            const data = await apiGet('/admin/api/solicitudes-registro');
            const listaBox = solicitudesBox.querySelector('#lista-solicitudes');
            listaBox.innerHTML = '';
            if (!data.ok || !data.solicitudes.length) { listaBox.appendChild(el('<div class="ultra-glass p-6 text-center text-gray-400">No hay solicitudes pendientes.</div>')); return; }
            data.solicitudes.forEach(s => {
                listaBox.appendChild(el(\`<div class="ultra-glass p-5 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div><p class="text-white font-bold">\${s.nombre_completo} <span class="text-gray-500 text-xs">@\${s.username}</span></p><p class="text-brand-blue text-xs">\${s.rol_solicitado}</p></div>
                    <div class="flex gap-3">
                        <button class="btn-aprobar-sol px-5 py-2 rounded-xl font-bold bg-green-500/20 text-green-300 text-sm" data-id="\${s.id}">Aprobar</button>
                        <button class="btn-rechazar-sol px-5 py-2 rounded-xl font-bold bg-red-500/20 text-red-300 text-sm" data-id="\${s.id}">Rechazar</button>
                    </div>
                </div>\`));
            });
            listaBox.querySelectorAll('.btn-aprobar-sol').forEach(b => b.addEventListener('click', async () => {
                const r = await apiPost('/admin/api/solicitudes-registro/' + b.dataset.id + '/aprobar', {});
                if (r.ok) { mostrarToast('Usuario aprobado', 'exito'); cargarSolicitudes(); cargarUsuarios(); } else mostrarToast(r.error, 'error');
            }));
            listaBox.querySelectorAll('.btn-rechazar-sol').forEach(b => b.addEventListener('click', async () => {
                const r = await apiPost('/admin/api/solicitudes-registro/' + b.dataset.id + '/rechazar', {});
                if (r.ok) { mostrarToast('Solicitud rechazada', 'info'); cargarSolicitudes(); } else mostrarToast(r.error, 'error');
            }));
        }
        cargarSolicitudes();

        cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Lista de usuarios</h3>'));
        const listaUsuariosBox = el('<div id="lista-usuarios" class="space-y-3"></div>');
        cont.appendChild(listaUsuariosBox);

        async function cargarUsuarios() {
            const data = await apiGet('/admin/api/usuarios');
            listaUsuariosBox.innerHTML = '';
            if (!data.ok) { listaUsuariosBox.appendChild(el('<div class="ultra-glass p-6 text-red-400">' + data.error + '</div>')); return; }
            data.usuarios.forEach(u => {
                const box = el(\`<div class="ultra-glass p-5 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div><p class="text-white font-bold">\${u.nombre_completo} <span class="text-gray-500 text-xs">@\${u.username}</span></p><p class="text-brand-blue text-xs">\${u.rol}</p></div>
                    <div class="flex gap-2 items-center flex-wrap">
                        \${badgeEstado(u.estado)}
                        \${u.telefono ? '<button class="btn-mensaje-whatsapp-usuario px-4 py-2 rounded-xl font-bold bg-green-500/20 text-green-300 text-xs" data-username="' + u.username + '" data-nombre="' + u.nombre_completo.replace(/"/g, '&quot;') + '"><i class="fa-brands fa-whatsapp mr-1"></i>Escribir</button>' : ''}
                        \${data.puede_gestionar ? \`
                        <button class="btn-suspender-usuario px-4 py-2 rounded-xl font-bold bg-yellow-500/20 text-yellow-300 text-xs" data-id="\${u.username}">Suspender</button>
                        <button class="btn-desbanear-usuario px-4 py-2 rounded-xl font-bold bg-green-500/20 text-green-300 text-xs" data-id="\${u.username}">Reactivar</button>
                        <button class="btn-eliminar-usuario px-4 py-2 rounded-xl font-bold bg-red-500/20 text-red-300 text-xs" data-id="\${u.username}">Eliminar</button>
                        \` : ''}
                    </div>
                </div>\`);
                listaUsuariosBox.appendChild(box);
            });
            listaUsuariosBox.querySelectorAll('.btn-mensaje-whatsapp-usuario').forEach(b => b.addEventListener('click', () => {
                modalMensajeBox.querySelector('[name="username_destino"]').value = b.dataset.username;
                modalMensajeBox.querySelector('#nombre-destino-mensaje-whatsapp').textContent = b.dataset.nombre;
                modalMensajeBox.querySelector('[name="mensaje"]').value = '';
                abrirModal('modal-mensaje-whatsapp-usuario');
            }));
            listaUsuariosBox.querySelectorAll('.btn-suspender-usuario').forEach(b => b.addEventListener('click', async () => {
                const r = await apiPost('/admin/api/usuarios/' + b.dataset.id + '/suspender', {});
                if (r.ok) { mostrarToast('Usuario suspendido', 'info'); cargarUsuarios(); } else mostrarToast(r.error, 'error');
            }));
            listaUsuariosBox.querySelectorAll('.btn-desbanear-usuario').forEach(b => b.addEventListener('click', async () => {
                const r = await apiPost('/admin/api/usuarios/' + b.dataset.id + '/reactivar', {});
                if (r.ok) { mostrarToast('Usuario reactivado', 'exito'); cargarUsuarios(); } else mostrarToast(r.error, 'error');
            }));
            listaUsuariosBox.querySelectorAll('.btn-eliminar-usuario').forEach(b => b.addEventListener('click', async () => {
                if (!confirm('¿Eliminar permanentemente este usuario?')) return;
                const r = await apiPost('/admin/api/usuarios/' + b.dataset.id + '/eliminar', {});
                if (r.ok) { mostrarToast('Usuario eliminado', 'info'); cargarUsuarios(); } else mostrarToast(r.error, 'error');
            }));
        }
        cargarUsuarios();
    }
  `,

  rachas: () => `
    import { el, apiGet, apiPost } from '/admin/tabs/_util.js';
    function graficoBarrasSvg(ranking) {
        if (!ranking.length) return '<p class="text-gray-400 text-sm text-center py-8">Todavía no hay puntos registrados.</p>';
        const anchoBarra = 44, espacio = 18, altoMax = 220, margenInferior = 70, margenSuperior = 20;
        const maxAbs = Math.max(1, ...ranking.map(u => Math.abs(u.total)));
        const cero = margenSuperior + altoMax / 2;
        const anchoSvg = ranking.length * (anchoBarra + espacio) + espacio;
        const altoSvg = altoMax + margenSuperior + margenInferior;
        let barras = '';
        ranking.forEach((u, i) => {
            const x = espacio + i * (anchoBarra + espacio);
            const alturaBarra = Math.max(2, (Math.abs(u.total) / maxAbs) * (altoMax / 2 - 10));
            const y = u.total >= 0 ? cero - alturaBarra : cero;
            const color = u.total > 0 ? '#4ade80' : (u.total < 0 ? '#f87171' : '#75BCE1');
            const nombreCorto = u.nombre_completo.length > 10 ? u.nombre_completo.slice(0, 9) + '…' : u.nombre_completo;
            barras += '<g>' +
                '<rect x="' + x + '" y="' + y + '" width="' + anchoBarra + '" height="' + alturaBarra + '" fill="' + color + '" rx="6"></rect>' +
                '<text x="' + (x + anchoBarra / 2) + '" y="' + (u.total >= 0 ? y - 8 : y + alturaBarra + 16) + '" fill="#e5e7eb" font-size="12" font-weight="700" text-anchor="middle">' + u.total + '</text>' +
                '<text x="' + (x + anchoBarra / 2) + '" y="' + (altoSvg - 30) + '" fill="#9ca3af" font-size="10" text-anchor="middle" transform="rotate(-35 ' + (x + anchoBarra / 2) + ' ' + (altoSvg - 30) + ')">' + nombreCorto + '</text>' +
                '</g>';
        });
        return '<svg viewBox="0 0 ' + anchoSvg + ' ' + altoSvg + '" style="width:100%; height:auto; max-height:280px;">' +
            '<line x1="0" y1="' + cero + '" x2="' + anchoSvg + '" y2="' + cero + '" stroke="rgba(255,255,255,0.15)" stroke-width="1"></line>' +
            barras + '</svg>';
    }

    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Rachas</h2>'));

        const data = await apiGet('/admin/api/rachas');
        if (!data.ok) { cont.appendChild(el('<div class="ultra-glass p-6 text-red-400">' + data.error + '</div>')); return; }

        if (data.puede_otorgar) {
            const formBox = el(\`<div class="ultra-glass p-6">
                <h3 class="font-display text-lg font-bold text-white mb-4">Dar o quitar puntos</h3>
                <form id="form-punto" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <select name="username" required class="campo-form md:col-span-2" id="select-usuario-punto"><option value="">Voluntario...</option></select>
                    <select name="puntos" required class="campo-form"><option value="1">+1</option><option value="-1">-1</option></select>
                    <button type="submit" class="px-5 py-2 rounded-xl font-bold bg-brand-yellow text-black text-sm">Aplicar</button>
                    <input name="motivo" placeholder="Motivo (opcional)" class="campo-form md:col-span-4">
                </form>
            </div>\`);
            cont.appendChild(formBox);
            const select = formBox.querySelector('#select-usuario-punto');
            (data.mis_voluntarios || []).forEach(u => select.appendChild(el('<option value="' + u.username + '">' + u.nombre_completo + '</option>')));
            formBox.querySelector('#form-punto').addEventListener('submit', async (e) => {
                e.preventDefault();
                const datos = Object.fromEntries(new FormData(e.target));
                const r = await apiPost('/admin/api/rachas/punto', datos);
                if (r.ok) { mostrarToast('Punto aplicado', 'exito'); render(cont); } else mostrarToast(r.error, 'error');
            });
        }

        const graficoBox = el('<div class="ultra-glass p-6"><h3 class="font-display text-lg font-bold text-white mb-4">Ranking de voluntarios</h3><div id="grafico-rachas"></div></div>');
        cont.appendChild(graficoBox);
        graficoBox.querySelector('#grafico-rachas').innerHTML = graficoBarrasSvg((data.ranking || []).slice(0, 15));

        if ((data.ranking || []).length) {
            cont.appendChild(el('<h3 class="font-display text-lg font-bold text-white pt-4">Detalle</h3>'));
            const detalleBox = el('<div class="space-y-2"></div>');
            data.ranking.forEach((u, i) => {
                const colorRacha = u.total <= -5 ? 'text-red-400' : u.total < 0 ? 'text-yellow-400' : 'text-green-400';
                detalleBox.appendChild(el('<div class="ultra-glass p-4 flex items-center justify-between gap-3"><div class="flex items-center gap-3"><span class="w-6 h-6 rounded-full bg-brand-yellow text-black text-xs font-bold flex items-center justify-center">' + (i+1) + '</span>' + (u.foto_url ? '<img src="' + u.foto_url + '" class="w-8 h-8 rounded-full object-cover">' : '') + '<span class="text-white text-sm">' + u.nombre_completo + '</span></div><span class="font-bold ' + colorRacha + '">' + u.total + ' pts</span></div>'));
            });
            cont.appendChild(detalleBox);
        }
    }
  `,

  'contactos-directiva': () => `
    import { el, apiGet } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Contactos de la Directiva</h2>'));
        const data = await apiGet('/admin/api/contactos-directiva');
        if (!data.ok) { cont.appendChild(el('<div class="ultra-glass p-6 text-red-400">' + data.error + '</div>')); return; }
        const tabla = el('<div class="ultra-glass p-4 overflow-x-auto"><table class="w-full text-sm text-left"><thead><tr class="text-gray-400 border-b border-white/10"><th class="p-3">Nombre</th><th class="p-3">Rol</th><th class="p-3">Correo</th><th class="p-3">Teléfono</th></tr></thead><tbody id="tbody-contactos"></tbody></table></div>');
        cont.appendChild(tabla);
        const tbody = tabla.querySelector('#tbody-contactos');
        data.usuarios.forEach(u => {
            tbody.insertAdjacentHTML('beforeend', '<tr class="border-b border-white/5"><td class="p-3 text-white">' + u.nombre_completo + '</td><td class="p-3 text-brand-blue">' + u.rol + '</td><td class="p-3 text-gray-300">' + (u.correo || '—') + '</td><td class="p-3 text-gray-300">' + (u.telefono || '—') + '</td></tr>');
        });
    }
  `,

  'aviso-general': () => `
    import { el, apiPost } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Aviso General</h2>'));
        cont.appendChild(el('<p class="text-gray-400 text-sm -mt-4">Este mensaje se enviará por correo a todos los usuarios activos del equipo (redacción y difusión).</p>'));

        const box = el(\`<div class="ultra-glass p-6">
            <form id="form-aviso-general" class="space-y-4">
                <input name="asunto" placeholder="Asunto del correo" required maxlength="150" class="campo-form">
                <textarea name="mensaje" placeholder="Escribe el mensaje del aviso" required maxlength="2000" class="campo-form" rows="6"></textarea>
                <button type="submit" class="w-full px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Enviar aviso a todo el equipo</button>
            </form>
        </div>\`);
        cont.appendChild(box);

        box.querySelector('#form-aviso-general').addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!confirm('¿Enviar este aviso por correo a TODOS los usuarios activos? Esta acción no se puede deshacer.')) return;
            const datos = Object.fromEntries(new FormData(e.target));
            const boton = e.target.querySelector('button[type="submit"]');
            boton.disabled = true; boton.textContent = 'Enviando...';
            const r = await apiPost('/admin/api/aviso-general', datos);
            boton.disabled = false; boton.textContent = 'Enviar aviso a todo el equipo';
            if (r.ok) { mostrarToast('Aviso enviado a ' + r.total_enviados + ' usuarios', 'exito'); e.target.reset(); }
            else { mostrarToast(r.error || 'Error al enviar el aviso', 'error'); }
        });
    }
  `,

  apariencia: () => `
    import { el, apiPost } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Apariencia y Personalización</h2>'));

        const temaBox = el(\`<div class="ultra-glass p-6">
            <h3 class="font-display text-lg font-bold text-white mb-4">Tema de color</h3>
            <div class="grid grid-cols-2 md:grid-cols-3 gap-3" id="opciones-tema"></div>
        </div>\`);
        cont.appendChild(temaBox);

        const temas = { azul: '#75BCE1', amarillo: '#F7D52F', morado: '#9d4edd', verde: '#4ade80', rojo: '#f87171' };
        const nombresTemas = { azul: 'Azul (predeterminado)', amarillo: 'Amarillo', morado: 'Morado', verde: 'Verde', rojo: 'Rojo' };
        const contenedorTemas = temaBox.querySelector('#opciones-tema');
        Object.keys(temas).forEach(t => {
            const activo = PREFS_ACTUALES.tema === t;
            const btn = el('<button type="button" class="btn-tema px-4 py-3 rounded-xl border flex items-center gap-3 text-sm font-medium ' + (activo ? 'border-white text-white' : 'border-white/10 text-gray-300') + '" data-tema="' + t + '"><span style="width:1.25rem; height:1.25rem; border-radius:9999px; background:' + temas[t] + '; display:inline-block;"></span>' + nombresTemas[t] + '</button>');
            btn.addEventListener('click', async () => {
                const r = await apiPost('/admin/api/mis-preferencias', { tema: t });
                if (r.ok) { mostrarToast('Tema actualizado, recargando...', 'exito'); setTimeout(() => window.location.reload(), 800); }
                else mostrarToast(r.error, 'error');
            });
            contenedorTemas.appendChild(btn);
        });

        const ordenBox = el(\`<div class="ultra-glass p-6">
            <h3 class="font-display text-lg font-bold text-white mb-2">Orden del menú lateral</h3>
            <p class="text-gray-400 text-sm mb-4">Usa las flechas para reordenar tus pestañas del panel.</p>
            <div id="lista-orden-tabs" class="space-y-2"></div>
            <button id="btn-guardar-orden" class="mt-4 px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Guardar orden</button>
        </div>\`);
        cont.appendChild(ordenBox);

        let ordenActual = (PREFS_ACTUALES.orden_tabs && PREFS_ACTUALES.orden_tabs.length)
            ? PREFS_ACTUALES.orden_tabs.filter(id => TABS_DISPONIBLES.some(t => t.id === id))
            : TABS_DISPONIBLES.map(t => t.id);
        TABS_DISPONIBLES.forEach(t => { if (!ordenActual.includes(t.id)) ordenActual.push(t.id); });

        function renderizarOrden() {
            const lista = ordenBox.querySelector('#lista-orden-tabs');
            lista.innerHTML = '';
            ordenActual.forEach((id, i) => {
                const tab = TABS_DISPONIBLES.find(t => t.id === id);
                if (!tab) return;
                const fila = el('<div class="flex items-center justify-between gap-3 p-3 rounded-xl bg-white/5"><span class="text-white text-sm"><i class="fa-solid ' + tab.icono + ' mr-2 text-brand-blue"></i>' + tab.texto + '</span><div class="flex gap-1"><button class="btn-subir-tab px-3 py-1 rounded-lg bg-white/10 text-white text-xs" data-idx="' + i + '">↑</button><button class="btn-bajar-tab px-3 py-1 rounded-lg bg-white/10 text-white text-xs" data-idx="' + i + '">↓</button></div></div>');
                lista.appendChild(fila);
            });
            lista.querySelectorAll('.btn-subir-tab').forEach(b => b.addEventListener('click', () => {
                const idx = parseInt(b.dataset.idx, 10);
                if (idx === 0) return;
                [ordenActual[idx - 1], ordenActual[idx]] = [ordenActual[idx], ordenActual[idx - 1]];
                renderizarOrden();
            }));
            lista.querySelectorAll('.btn-bajar-tab').forEach(b => b.addEventListener('click', () => {
                const idx = parseInt(b.dataset.idx, 10);
                if (idx === ordenActual.length - 1) return;
                [ordenActual[idx + 1], ordenActual[idx]] = [ordenActual[idx], ordenActual[idx + 1]];
                renderizarOrden();
            }));
        }
        renderizarOrden();

        ordenBox.querySelector('#btn-guardar-orden').addEventListener('click', async () => {
            const r = await apiPost('/admin/api/mis-preferencias', { orden_tabs: ordenActual });
            if (r.ok) { mostrarToast('Orden guardado, recargando...', 'exito'); setTimeout(() => window.location.reload(), 800); }
            else mostrarToast(r.error, 'error');
        });
    }
  `,

  'mi-perfil': () => `
    import { el, apiGet, apiPost, prepararFormDataConImagen } from '/admin/tabs/_util.js';
    export async function render(cont) {
        cont.innerHTML = '';
        cont.appendChild(el('<h2 class="font-display text-2xl font-bold text-white">Mi Perfil</h2>'));
        const box = el(\`<div class="ultra-glass p-6 max-w-lg space-y-4">
            <form id="form-perfil" class="space-y-4">
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Foto de perfil</label>
                    <input type="file" name="foto" accept="image/*" class="campo-form">
                </div>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Nombre completo</label>
                    <input name="nombre_completo" value="\${USUARIO_ACTUAL.nombre_completo}" class="campo-form" maxlength="120">
                </div>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Nuevo usuario (opcional)</label>
                    <input name="username" value="\${USUARIO_ACTUAL.username}" class="campo-form" pattern="[a-zA-Z0-9_.]{3,32}">
                </div>
                <div>
                    <label class="text-xs text-gray-400 uppercase tracking-wider mb-1 block">Nueva contraseña (opcional)</label>
                    <input name="password" type="password" minlength="6" class="campo-form" placeholder="Dejar en blanco para no cambiar">
                </div>
                <button type="submit" class="px-6 py-3 rounded-xl font-bold bg-brand-yellow text-black">Guardar cambios</button>
            </form>
        </div>\`);
        cont.appendChild(box);
        box.querySelector('#form-perfil').addEventListener('submit', async (e) => {
            e.preventDefault();
            const datos = await prepararFormDataConImagen(new FormData(e.target), 'foto');
            const r = await apiPost('/admin/api/mi-perfil', datos, true);
            if (r.ok) { mostrarToast('Perfil actualizado', 'exito'); if (r.requiere_relogin) { setTimeout(() => window.location.href = '/admin', 1200); } }
            else mostrarToast(r.error, 'error');
        });
    }
  `,
};

async function manejarRobotsTxt(env) {
  const siteUrl = String(env.PUBLIC_SITE_URL || 'https://web.torevueltopj.workers.dev').replace(/\/$/, '');
  const contenido = `User-agent: *
Allow: /
Disallow: /admin
Disallow: /admin/
Disallow: /api/
Disallow: /whatsapp
Disallow: /tarea/

Sitemap: ${siteUrl}/sitemap.xml
`;
  return new Response(contenido, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}

function xmlEscape(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

async function manejarSitemapXml(env) {
  const siteUrl = String(env.PUBLIC_SITE_URL || 'https://web.torevueltopj.workers.dev').replace(/\/$/, '');
  const urls = [];

  const paginasEstaticas = [
    { loc: '/', prioridad: '1.0', frecuencia: 'daily' },
    { loc: '/secciones', prioridad: '0.8', frecuencia: 'daily' },
    { loc: '/directiva', prioridad: '0.5', frecuencia: 'monthly' },
    { loc: '/voluntariado', prioridad: '0.9', frecuencia: 'weekly' },
    { loc: '/eventos', prioridad: '0.8', frecuencia: 'daily' },
    { loc: '/comunidad', prioridad: '0.8', frecuencia: 'daily' },
  ];
  for (const p of paginasEstaticas) {
    urls.push(`  <url>\n    <loc>${xmlEscape(siteUrl + p.loc)}</loc>\n    <changefreq>${p.frecuencia}</changefreq>\n    <priority>${p.prioridad}</priority>\n  </url>`);
  }

  try {
    const articulos = await env.DB.prepare(
      `SELECT slug, fecha_publicacion FROM articulos WHERE estado = 'publicado' ORDER BY fecha_publicacion DESC LIMIT 5000`
    ).all();
    for (const a of (articulos.results || [])) {
      const lastmod = a.fecha_publicacion ? String(a.fecha_publicacion).slice(0, 10) : '';
      urls.push(`  <url>\n    <loc>${xmlEscape(siteUrl + '/articulo/' + a.slug)}</loc>${lastmod ? `\n    <lastmod>${lastmod}</lastmod>` : ''}\n    <changefreq>monthly</changefreq>\n    <priority>0.7</priority>\n  </url>`);
    }
  } catch (e) {}

  try {
    const eventos = await env.DB.prepare(
      `SELECT slug, creado_en FROM eventos WHERE estado = 'aprobado' ORDER BY creado_en DESC LIMIT 2000`
    ).all();
    for (const ev of (eventos.results || [])) {
      const lastmod = ev.creado_en ? String(ev.creado_en).slice(0, 10) : '';
      urls.push(`  <url>\n    <loc>${xmlEscape(siteUrl + '/eventos/' + ev.slug)}</loc>${lastmod ? `\n    <lastmod>${lastmod}</lastmod>` : ''}\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>`);
    }
  } catch (e) {}

  try {
    const convocatorias = await env.DB.prepare(
      `SELECT slug, creado_en FROM convocatorias WHERE estado = 'publicado' ORDER BY creado_en DESC LIMIT 2000`
    ).all();
    for (const c of (convocatorias.results || [])) {
      const lastmod = c.creado_en ? String(c.creado_en).slice(0, 10) : '';
      urls.push(`  <url>\n    <loc>${xmlEscape(siteUrl + '/comunidad/' + c.slug)}</loc>${lastmod ? `\n    <lastmod>${lastmod}</lastmod>` : ''}\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>`);
    }
  } catch (e) {}

  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>`;

  return new Response(xml, {
    status: 200,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=1800',
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      if (path === '/robots.txt' && request.method === 'GET') {
        return await manejarRobotsTxt(env);
      }

      if (path === '/sitemap.xml' && request.method === 'GET') {
        return await manejarSitemapXml(env);
      }

      if (path === '/' && request.method === 'GET') return htmlResponse(await paginaInicio(env));
      if (path === '/secciones' && request.method === 'GET') return htmlResponse(await paginaSecciones(env, request));
      if (path === '/directiva' && request.method === 'GET') return htmlResponse(await paginaDirectiva(env));
      if (path === '/voluntariado' && request.method === 'GET') return htmlResponse(await paginaVoluntariado(env));
      if (path === '/eventos' && request.method === 'GET') return htmlResponse(await paginaEventos(env));
      if (path === '/comunidad' && request.method === 'GET') return htmlResponse(await paginaComunidad(env));

      const matchArticulo = path.match(/^\/articulo\/([a-zA-Z0-9-]+)$/);
      if (matchArticulo && request.method === 'GET') return htmlResponse(await paginaArticulo(env, matchArticulo[1]));

      const matchEvento = path.match(/^\/eventos\/([a-zA-Z0-9-]+)$/);
      if (matchEvento && request.method === 'GET') return htmlResponse(await paginaEventoIndividual(env, matchEvento[1]));

      const matchConvocatoriaIndividual = path.match(/^\/comunidad\/([a-zA-Z0-9-]+)$/);
      if (matchConvocatoriaIndividual && request.method === 'GET') return htmlResponse(await paginaConvocatoriaIndividual(env, matchConvocatoriaIndividual[1]));

      const matchTareaPublica = path.match(/^\/tarea\/(\d+)$/);
      if (matchTareaPublica && request.method === 'GET') return htmlResponse(await paginaTareaPublica(env, matchTareaPublica[1], request));

      const matchAvisoPublico = path.match(/^\/aviso\/(\d+)$/);
      if (matchAvisoPublico && request.method === 'GET') return htmlResponse(await paginaAvisoPublico(env, matchAvisoPublico[1]));

      const matchBienvenidaPostulante = path.match(/^\/bienvenida\/(\d+)$/);
      if (matchBienvenidaPostulante && request.method === 'GET') return htmlResponse(await paginaBienvenidaPostulante(env, matchBienvenidaPostulante[1]));

      const matchArticuloPublico = path.match(/^\/tarea\/a-(\d+)$/);
      if (matchArticuloPublico && request.method === 'GET') return htmlResponse(await paginaArticuloAsignadoPublico(env, matchArticuloPublico[1], request));

      if (path === '/api/publico/conteo-articulos' && request.method === 'GET') {
        const row = await env.DB.prepare(`SELECT COUNT(*) as total FROM articulos WHERE estado = 'publicado'`).first();
        return jsonResponse({ ok: true, total: row ? row.total : 0 });
      }

      if (path === '/api/publico/suscribirse' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const correo = String(body.correo || '').trim().toLowerCase();
        if (!validarCorreo(correo) || !correo) return errorResponse('Correo inválido.');
        await agregarSuscriptor(env, correo);
        return jsonResponse({ ok: true });
      }

      if (path === '/api/publico/convocatorias' && request.method === 'POST') {
        const form = await request.formData();
        const tipo = String(form.get('tipo') || '');
        const titulo = String(form.get('titulo') || '').trim();
        const descripcion = String(form.get('descripcion') || '').trim();
        const fecha_evento = String(form.get('fecha_evento') || '');
        const fecha_apertura = String(form.get('fecha_apertura') || '');
        const fecha_cierre = String(form.get('fecha_cierre') || '');
        const cupos_tipo = String(form.get('cupos_tipo') || 'ilimitado');
        const cupos_cantidad_crudo = String(form.get('cupos_cantidad') || '');
        const form_url = String(form.get('form_url') || '').trim();
        const contacto_nombre = String(form.get('contacto_nombre') || '').trim();
        const contacto_telefono = String(form.get('contacto_telefono') || '').trim();
        const fotos = form.getAll('fotos');

        if (!Object.keys(TIPOS_CONVOCATORIA).includes(tipo)) return errorResponse('Tipo inválido.');
        if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');
        if (!/^https?:\/\//i.test(form_url)) return errorResponse('El link del formulario debe ser una URL válida.');
        if (!contacto_nombre || contacto_nombre.length > 120) return errorResponse('Nombre de contacto inválido.');
        if (!validarTelefono(contacto_telefono)) return errorResponse('Teléfono de contacto inválido.');
        if (fecha_evento && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_evento)) return errorResponse('Fecha del evento inválida.');
        if (fecha_apertura && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_apertura)) return errorResponse('Fecha de apertura inválida.');
        if (fecha_cierre && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_cierre)) return errorResponse('Fecha de cierre inválida.');
        if (fecha_apertura && fecha_cierre && fecha_apertura > fecha_cierre) return errorResponse('La fecha de cierre no puede ser antes que la de apertura.');
        if (!['ilimitado', 'personalizado'].includes(cupos_tipo)) return errorResponse('Tipo de cupos inválido.');
        let cupos_cantidad = null;
        if (cupos_tipo === 'personalizado') {
          cupos_cantidad = parseInt(cupos_cantidad_crudo, 10);
          if (!Number.isInteger(cupos_cantidad) || cupos_cantidad < 1) return errorResponse('Debes indicar una cantidad de cupos válida.');
        }
        if (fotos.length > 5) return errorResponse('Máximo 5 fotos.');

        let slug = slugify(titulo);
        const existeSlug = await env.DB.prepare(`SELECT id FROM convocatorias WHERE slug = ?`).bind(slug).first();
        if (existeSlug) slug = `${slug}-${generarIdAleatorio(4)}`;

        let fotos_keys = null;
        const archivosValidos = fotos.filter((f) => f && f.size > 0);
        if (archivosValidos.length) {
          for (const f of archivosValidos) {
            if (f.size > 8 * 1024 * 1024) return errorResponse('Cada foto debe pesar máximo 8MB.');
          }
          let keys;
          try {
            keys = await subirMultiplesImagenesR2(env, archivosValidos, 'comunidad', slug);
          } catch (e) {
            return errorResponse(e.message || 'No se pudo subir una de las fotos.');
          }
          fotos_keys = JSON.stringify(keys);
        }

        await env.DB.prepare(
          `INSERT INTO convocatorias (tipo, titulo, descripcion, fecha_evento, fecha_apertura, fecha_cierre, cupos_tipo, cupos_cantidad, form_url, fotos_keys, contacto_nombre, contacto_telefono, slug) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(tipo, titulo, descripcion || null, fecha_evento || null, fecha_apertura || null, fecha_cierre || null, cupos_tipo, cupos_cantidad, form_url, fotos_keys, contacto_nombre, contacto_telefono, slug).run();

        await notificarSuscriptoresNuevaPublicacion(env, titulo, TIPOS_CONVOCATORIA[tipo] || tipo, `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/comunidad/${slug}`);
        await notificarDireccionGeneral(env, `To' Revuelto: se publicó algo nuevo en Comunidad — "${titulo}" (${TIPOS_CONVOCATORIA[tipo] || tipo}), por ${contacto_nombre}.`, {
          link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/comunidad/${slug}`,
          asunto: "Nueva publicación en Comunidad — To' Revuelto",
          etiquetaBoton: 'Ver publicación',
          tituloSuperior: 'Nueva publicación',
        });

        return jsonResponse({ ok: true });
      }

      const matchReportarConvocatoria = path.match(/^\/api\/publico\/convocatorias\/(\d+)\/reportar$/);
      if (matchReportarConvocatoria && request.method === 'POST') {
        const id = matchReportarConvocatoria[1];
        const body = await request.json().catch(() => ({}));
        const motivo = String(body.motivo || '').trim().slice(0, 400);

        const convocatoria = await env.DB.prepare(`SELECT * FROM convocatorias WHERE id = ?`).bind(id).first();
        if (!convocatoria) return errorResponse('Publicación no encontrada.', 404);

        await env.DB.prepare(`INSERT INTO convocatorias_reportes (convocatoria_id, motivo) VALUES (?, ?)`).bind(id, motivo || null).run();
        await env.DB.prepare(`UPDATE convocatorias SET reportes_count = reportes_count + 1 WHERE id = ?`).bind(id).run();

        await notificarReporteConvocatoria(env, convocatoria, motivo);

        return jsonResponse({ ok: true });
      }

if (path === '/api/publico/postulaciones-voluntariado' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const nombre_completo = String(body.nombre_completo || '').trim();
        const edadCruda = parseInt(body.edad, 10);
        const ciudad = String(body.ciudad || '').trim();
        const correo = String(body.correo || '').trim().toLowerCase();
        const instagram = String(body.instagram || '').trim();
        const telefono = String(body.telefono || '').trim();
        const interes_area = String(body.interes_area || '').trim();
        const experiencia = String(body.experiencia || '').trim();
        const habilidades = String(body.habilidades || '').trim();
        const proyectos_similares = String(body.proyectos_similares || '').trim();
        const trabajo_equipo = String(body.trabajo_equipo || '');
        const acuerdo_contenido = String(body.acuerdo_contenido || '');
        const tipo_contenido = String(body.tipo_contenido || '').trim();
        const porque_seleccionar = String(body.porque_seleccionar || '').trim();
        const algo_mas = String(body.algo_mas || '').trim();

        if (!nombre_completo || nombre_completo.length > 120) return errorResponse('Nombre completo inválido.');
        if (!Number.isInteger(edadCruda) || edadCruda < 10 || edadCruda > 99) return errorResponse('Edad inválida.');
        if (!ciudad || ciudad.length > 120) return errorResponse('Ciudad inválida.');
        if (!validarCorreo(correo) || !correo) return errorResponse('Correo inválido.');
        if (!instagram || instagram.length > 60) return errorResponse('Usuario de Instagram inválido.');
        if (!interes_area) return errorResponse('Debes explicar por qué te interesa formar parte del equipo.');
        if (!habilidades) return errorResponse('Debes mencionar tus habilidades.');
        if (!['Sí', 'No'].includes(trabajo_equipo)) return errorResponse('Respuesta de trabajo en equipo inválida.');
        if (!['Sí', 'No'].includes(acuerdo_contenido)) return errorResponse('Respuesta de acuerdo de contenido inválida.');
        if (!porque_seleccionar) return errorResponse('Debes explicar por qué deberíamos seleccionarte.');

        const telefonoNormalizado = normalizarTelefonoRD(telefono);
        if (!telefonoNormalizado) return errorResponse('El teléfono debe ser un número dominicano válido (ej: 809-000-0000).');

        const insercionPostulante = await env.DB.prepare(
          `INSERT INTO postulantes_voluntariado (nombre_completo, edad, ciudad, correo, instagram, telefono, area, interes_area, experiencia, habilidades, proyectos_similares, trabajo_equipo, acuerdo_contenido, tipo_contenido, porque_seleccionar, algo_mas)
           VALUES (?, ?, ?, ?, ?, ?, 'general', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          nombre_completo, edadCruda, ciudad, correo, instagram, telefonoNormalizado,
          interes_area, experiencia || null, habilidades, proyectos_similares || null,
          trabajo_equipo, acuerdo_contenido, tipo_contenido || null, porque_seleccionar, algo_mas || null
        ).run();

        await notificarDireccionGeneral(env, `To' Revuelto: nueva postulación de voluntariado de ${nombre_completo}. Revísala en el panel.`, {
          link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin#postulantes`,
          asunto: "Nueva postulación de voluntariado — To' Revuelto",
          etiquetaBoton: 'Ver postulante',
          tituloSuperior: 'Nueva postulación',
        });

        return jsonResponse({ ok: true });
      }

      if (path === '/whatsapp' && request.method === 'GET') {
        return verificarWebhookWhatsapp(url, env);
      }
      if (path === '/whatsapp' && request.method === 'POST') {
        return await manejarWebhookWhatsappEntrante(request, env);
      }

      if (path === '/admin' && request.method === 'GET') {
        const usuario = await requiereAuth(request, env);
        const volverParam = url.searchParams.get('volver') || '';
        if (usuario) {
          if (/^tarea\/(a-)?\d+$/.test(volverParam)) {
            return new Response(null, { status: 302, headers: { 'Location': '/' + volverParam } });
          }
          return htmlResponse(await shellAdmin(env, usuario));
        }
        return htmlResponse(paginaLoginAdmin(env, null, volverParam));
      }

      if (path === '/admin/registro' && request.method === 'POST') {
        const form = await request.formData();
        const rol_solicitado = String(form.get('rol_solicitado') || '');
        const nombre_completo = String(form.get('nombre_completo') || '').trim();
        const username = String(form.get('username') || '').trim();
        const telefono = String(form.get('telefono') || '').trim();
        const correo = String(form.get('correo') || '').trim();
        const password = String(form.get('password') || '');

        if (![ROLES.VOLUNTARIO, ROLES.SUBDIRECTORA_GENERAL].includes(rol_solicitado)) {
          return errorResponse('Rol solicitado inválido.');
        }
        if (!nombre_completo || nombre_completo.length > 120) return errorResponse('Nombre completo inválido.');
        if (!validarUsername(username)) return errorResponse('El usuario debe tener 3-32 caracteres alfanuméricos.');
        if (!validarPassword(password)) return errorResponse('La contraseña debe tener al menos 6 caracteres.');
        if (!validarCorreo(correo)) return errorResponse('Correo inválido.');
        if (!validarTelefono(telefono)) return errorResponse('Teléfono inválido.');

        const telefonoNormalizado = normalizarTelefonoRD(telefono);
        if (!telefonoNormalizado) return errorResponse('El teléfono debe ser un número dominicano válido (ej: 809-000-0000). Es obligatorio para recibir notificaciones de WhatsApp.');

        const usuarioExistente = await obtenerUsuario(env, username);
        if (usuarioExistente) return errorResponse('Ese usuario ya existe.');

        const solicitudExistente = await env.DB.prepare(`SELECT id FROM solicitudes_registro WHERE username = ?`).bind(username).first();
        if (solicitudExistente) return errorResponse('Ya existe una solicitud con ese usuario.');

        const telefonoYaUsado = await env.DB.prepare(`SELECT id FROM solicitudes_registro WHERE telefono = ? AND estado = 'pendiente'`).bind(telefonoNormalizado).first();
        if (telefonoYaUsado) return errorResponse('Ya hay una solicitud pendiente con ese número de teléfono.');

        const salt = generarSalt();
        const password_hash = await hashPassword(password, salt, env.PASSWORD_PEPPER);

        await env.DB.prepare(
          `INSERT INTO solicitudes_registro (username, nombre_completo, rol_solicitado, area, telefono, correo, password_hash, salt) VALUES (?, ?, ?, 'general', ?, ?, ?, ?)`
        ).bind(username, nombre_completo, rol_solicitado, telefonoNormalizado, correo || null, password_hash, salt).run();

        return jsonResponse({ ok: true });
      }

      if (path === '/admin/login' && request.method === 'POST') {
        const form = await request.formData();
        const username = String(form.get('username') || '').trim();
        const password = String(form.get('password') || '');
        const volverCrudo = String(form.get('volver') || '');
        const volverSeguro = /^tarea\/(a-)?\d+$/.test(volverCrudo) ? volverCrudo : '';
        const destinoFinal = volverSeguro ? '/' + volverSeguro : '/admin';

        if (!validarUsername(username) || !password) {
          return htmlResponse(paginaLoginAdmin(env, 'Usuario o contraseña inválidos.', volverSeguro), 400);
        }

        const filaDirectorGeneral = await env.DB.prepare(
          `SELECT * FROM director_general WHERE username = ?`
        ).bind(username).first();

        if (filaDirectorGeneral) {
          const passwordValidaDG = await verificarPassword(password, filaDirectorGeneral.salt, env.PASSWORD_PEPPER, filaDirectorGeneral.password_hash);
          if (!passwordValidaDG) return htmlResponse(paginaLoginAdmin(env, 'Usuario o contraseña incorrectos.', volverSeguro), 401);
          if (filaDirectorGeneral.estado === 'baneado') return htmlResponse(paginaLoginAdmin(env, 'Tu cuenta ha sido baneada.', volverSeguro), 403);
          if (filaDirectorGeneral.estado === 'suspendido') return htmlResponse(paginaLoginAdmin(env, 'Tu cuenta está suspendida.', volverSeguro), 403);

          let usuarioEnKv = await obtenerUsuario(env, username);
          if (!usuarioEnKv) {
            usuarioEnKv = {
              nombre_completo: filaDirectorGeneral.nombre_completo, username: filaDirectorGeneral.username,
              rol: ROLES.DIRECTOR_GENERAL, correo: filaDirectorGeneral.correo, telefono: filaDirectorGeneral.telefono,
              password_hash: filaDirectorGeneral.password_hash, salt: filaDirectorGeneral.salt,
              estado: filaDirectorGeneral.estado, foto_key: filaDirectorGeneral.foto_key,
              creado_en: filaDirectorGeneral.creado_en,
            };
            await guardarUsuario(env, usuarioEnKv);
            await agregarAIndiceUsuarios(env, username);
          }

          const tokenDG = await crearSesion(env, username);
          await registrarAuditoria(env, username, 'login', '');
          return new Response(null, { status: 302, headers: { 'Location': destinoFinal, 'Set-Cookie': cookieDeSesion(tokenDG) } });
        }

        const usuario = await obtenerUsuario(env, username);
        if (!usuario) return htmlResponse(paginaLoginAdmin(env, 'Usuario o contraseña incorrectos.', volverSeguro), 401);

        const passwordValida = await verificarPassword(password, usuario.salt, env.PASSWORD_PEPPER, usuario.password_hash);
        if (!passwordValida) return htmlResponse(paginaLoginAdmin(env, 'Usuario o contraseña incorrectos.', volverSeguro), 401);

        if (usuario.estado === 'baneado') return htmlResponse(paginaLoginAdmin(env, 'Tu cuenta ha sido baneada. Contacta a tu director.', volverSeguro), 403);
    if (usuario.estado === 'suspendido') return htmlResponse(paginaLoginAdmin(env, 'Tu cuenta está suspendida.', volverSeguro), 403);

    const token = await crearSesion(env, username);
        await registrarAuditoria(env, username, 'login', '');
        return new Response(null, { status: 302, headers: { 'Location': destinoFinal, 'Set-Cookie': cookieDeSesion(token) } });
      }

      if (path === '/admin/logout' && request.method === 'POST') {
        const sesion = await obtenerSesion(request, env);
        if (sesion) await destruirSesion(env, sesion.token);
        return new Response(null, { status: 302, headers: { 'Location': '/admin', 'Set-Cookie': cookieBorrarSesion() } });
      }

      if (path === '/admin/tabs/_util.js' && request.method === 'GET') {
        return new Response(utilidadesClienteJs(), { headers: { 'Content-Type': 'application/javascript; charset=utf-8' } });
      }
      const matchTab = path.match(/^\/admin\/tabs\/([a-zA-Z0-9_-]+)\.js$/);
      if (matchTab && request.method === 'GET') {
        const generador = TABS_JS[matchTab[1]];
        if (!generador) return new Response('// tab no encontrada', { status: 404, headers: { 'Content-Type': 'application/javascript' } });
        const usuario = await requiereAuth(request, env);
        if (!usuario) return new Response('// no autorizado', { status: 401, headers: { 'Content-Type': 'application/javascript' } });
        return new Response(generador(), { headers: { 'Content-Type': 'application/javascript; charset=utf-8' } });
      }

      if (path.startsWith('/admin/api/')) {
        const usuario = await requiereAuth(request, env);
        if (!usuario) return errorResponse('No autorizado.', 401);
        return await manejarApiAdmin(request, env, usuario, path);
      }

      return htmlResponse(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>404</title>${estilosBase()}</head><body class="bg-[#030509] text-white flex items-center justify-center min-h-screen"><div class="ultra-glass p-10 text-center"><h1 class="font-display text-4xl font-bold mb-4">404</h1><p class="text-gray-400 mb-6">Página no encontrada.</p><a href="/" class="text-brand-blue font-bold">Volver al inicio</a></div></body></html>`, 404);
    } catch (error) {
      return jsonResponse({ ok: false, error: 'Error interno del servidor.' }, 500);
    }
  },
};

async function manejarApiAdmin(request, env, usuario, path) {
  const method = request.method;
  const esAccesoTotal = ROLES_CON_ACCESO_TOTAL.includes(usuario.rol);
  const esAltaDireccion = ROLES_ALTA_DIRECCION.includes(usuario.rol);
  const esVoluntarioOAltaDireccion = usuario.rol === ROLES.VOLUNTARIO || esAltaDireccion;
  const puedeGestionarArticulosRedaccion = esVoluntarioOAltaDireccion;
  const puedeGestionarDifusion = esVoluntarioOAltaDireccion;

  if (path === '/admin/api/resumen' && method === 'GET') {
    const publicados = await env.DB.prepare(`SELECT COUNT(*) as total FROM articulos WHERE estado = 'publicado'`).first();
    const pendientes = await env.DB.prepare(`SELECT COUNT(*) as total FROM articulos WHERE estado NOT IN ('publicado','rechazado')`).first();
    const todosUsuarios = await listarUsuarios(env);
    const voluntariosActivos = todosUsuarios.filter((u) => u.estado === 'activo').length;
    const miRacha = await obtenerTotalRachaUsuario(env, usuario.username);

    const resultado = {
      ok: true,
      total_publicados: publicados.total,
      total_pendientes: pendientes.total,
      total_voluntarios: voluntariosActivos,
      mi_racha: miRacha,
    };

    resultado.ranking_top5 = await obtenerRankingVoluntarios(env, 5);

    if (usuario.rol === ROLES.VOLUNTARIO) {
      const asignaciones = await env.DB.prepare(
        `SELECT titulo, fecha_asignada FROM articulos WHERE asignado_a_username = ? AND estado NOT IN ('publicado') ORDER BY fecha_asignada ASC LIMIT 10`
      ).bind(usuario.username).all();
      resultado.mis_asignaciones = asignaciones.results;
    }

    return jsonResponse(resultado);
  }

  if (path === '/admin/api/articulos' && method === 'POST') {
    if (usuario.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(usuario.rol)) return errorResponse('No autorizado para enviar artículos.', 403);
    const form = await request.formData();
    const titulo = String(form.get('titulo') || '').trim();
    const categoria = String(form.get('categoria') || '').trim();
    const seccion = String(form.get('seccion') || '').trim();
    const extracto = String(form.get('extracto') || '').trim();
    const cuerpo_html_crudo = String(form.get('cuerpo_html') || '');
    const archivoPortada = form.get('portada');

    if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');
    if (!categoria || categoria.length > 60) return errorResponse('Categoría inválida.');
    if (!seccion || seccion.length > 60) return errorResponse('Sección inválida.');

    const cuerpo_html = sanitizarHtmlArticulo(cuerpo_html_crudo);
    const textoPlano = cuerpo_html.replace(/<[^>]+>/g, ' ').trim();
    const palabras = textoPlano ? textoPlano.split(/\s+/).length : 0;
    if (palabras === 0) return errorResponse('El cuerpo del artículo no puede estar vacío.');
    if (palabras > 500) return errorResponse('El artículo supera las 500 palabras.');

    let portada_key = null;
    if (archivoPortada && archivoPortada.size > 0) {
      if (archivoPortada.size > 8 * 1024 * 1024) return errorResponse('La imagen de portada es demasiado grande (máx 8MB).');
      const buffer = await archivoPortada.arrayBuffer();
      try {
        portada_key = await subirImagenR2(env, buffer, 'portadas', slugify(titulo).slice(0, 40));
      } catch (e) {
        return errorResponse(e.message || 'La imagen de portada no es válida. Usa JPG, PNG o WEBP.');
      }
    }

    let slug = slugify(titulo);
    const existeSlug = await env.DB.prepare(`SELECT id FROM articulos WHERE slug = ?`).bind(slug).first();
    if (existeSlug) slug = `${slug}-${generarIdAleatorio(4)}`;

    const esAltaDireccionCreando = ROLES_ALTA_DIRECCION.includes(usuario.rol);
    const estadoInicial = esAltaDireccionCreando ? 'publicado' : 'enviado';

    const resultado = await env.DB.prepare(
      `INSERT INTO articulos (titulo, categoria, seccion, autor_username, cuerpo_html, extracto, portada_key, estado, slug, creado_por, publicado_por, fecha_publicacion)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ${esAltaDireccionCreando ? "datetime('now')" : 'NULL'})`
    ).bind(titulo, categoria, seccion, usuario.username, cuerpo_html, extracto || null, portada_key, estadoInicial, slug, usuario.username, esAltaDireccionCreando ? usuario.username : null).run();

    const idArticuloNuevo = resultado.meta.last_row_id;

    if (esAltaDireccionCreando) {
      await registrarAuditoria(env, usuario.username, 'articulo_publicado_directo', `id=${idArticuloNuevo}`);
      await notificarSuscriptoresNuevaPublicacion(env, titulo, 'artículo', `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/articulo/${slug}`);
      return jsonResponse({ ok: true, id: idArticuloNuevo, publicado: true });
    }

    await registrarAuditoria(env, usuario.username, 'articulo_enviado', `id=${idArticuloNuevo}`);

    const enlaceArticuloNuevo = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${idArticuloNuevo}`;
    const revisoresDeArticulo = await listarUsuariosPorRoles(env, [ROLES.DIRECTOR_GENERAL, ROLES.SUBDIRECTORA_GENERAL]);
    for (const revisor of revisoresDeArticulo) {
      await notificarUsuarioCompleto(env, revisor.username, `To' Revuelto: ${usuario.nombre_completo} envió un artículo nuevo para revisar — "${titulo}".`, {
        link: enlaceArticuloNuevo,
        asunto: "Artículo nuevo para revisar — To' Revuelto",
        etiquetaBoton: 'Revisar artículo',
        tituloSuperior: 'Artículo para revisión',
        tipoObjeto: 'articulo',
        objetoId: idArticuloNuevo,
      });
    }

    return jsonResponse({ ok: true, id: idArticuloNuevo });
  }

  const matchEnviarArticuloTarea = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/enviar-articulo$/);
  if (matchEnviarArticuloTarea && method === 'POST') {
    if (usuario.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(usuario.rol)) return errorResponse('No autorizado.', 403);
    const id = matchEnviarArticuloTarea[1];
    const tarea = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE id = ? AND tipo IN ('articulo', 'redaccion')`).bind(id).first();
    if (!tarea) return errorResponse('Tarea de artículo no encontrada.', 404);
    if (tarea.asignado_a_username && tarea.asignado_a_username !== usuario.username) return errorResponse('Esta tarea no te pertenece.', 403);
    if (tarea.estado !== 'pendiente' && tarea.estado !== 'enviada_redaccion') return errorResponse('Esta tarea ya avanzó de etapa.', 400);

    const form = await request.formData();
    const titulo = String(form.get('titulo') || tarea.titulo || '').trim();
    const categoria = String(form.get('categoria') || '').trim();
    const seccion = String(form.get('seccion') || '').trim();
    const extracto = String(form.get('extracto') || '').trim();
    const cuerpo_html_crudo = String(form.get('cuerpo_html') || '');

    if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');
    if (!categoria || categoria.length > 60) return errorResponse('Categoría inválida.');
    if (!seccion || seccion.length > 60) return errorResponse('Sección inválida.');

    const cuerpo_html = sanitizarHtmlArticulo(cuerpo_html_crudo);
    const textoPlano = cuerpo_html.replace(/<[^>]+>/g, ' ').trim();
    const palabras = textoPlano ? textoPlano.split(/\s+/).length : 0;
    if (palabras === 0) return errorResponse('El cuerpo del artículo no puede estar vacío.');
    if (palabras > 500) return errorResponse('El artículo supera las 500 palabras.');

    await env.DB.prepare(
      `UPDATE tareas_difusion SET titulo = ?, articulo_cuerpo_html = ?, articulo_extracto = ?, articulo_categoria = ?, articulo_seccion = ?, asignado_a_username = ?, estado = 'enviada_redaccion', actualizado_en = datetime('now') WHERE id = ?`
    ).bind(titulo, cuerpo_html, extracto || null, categoria, seccion, usuario.username, id).run();

    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} entregó la redacción del artículo "${titulo}". Puedes asignar la portada desde el panel.`, {
      link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${id}`,
      asunto: "Redacción lista para portada — To' Revuelto",
      tituloSuperior: 'Entrega recibida',
    });

    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/mis-articulos' && method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT id, titulo, seccion, estado, creado_en FROM articulos WHERE autor_username = ? ORDER BY creado_en DESC LIMIT 50`
    ).bind(usuario.username).all();
    return jsonResponse({ ok: true, articulos: rows.results });
  }

  const matchArticulosLista = path === '/admin/api/articulos';
  if (matchArticulosLista && method === 'GET') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const url = new URL(request.url);
    const estado = url.searchParams.get('estado');
    const estadosPermitidos = ['enviado', 'publicado'];
    if (!estado || !estadosPermitidos.includes(estado)) return errorResponse('Estado no autorizado.', 403);

    async function articulosConFotoAutor(rows) {
      const resultado = [];
      for (const a of rows) {
        const autor = await obtenerUsuario(env, a.autor_username);
        resultado.push({ ...a, autor_foto_url: autor ? urlPublicaR2(env, autor.foto_key) : null });
      }
      return resultado;
    }
    const rows = await env.DB.prepare(`SELECT * FROM articulos WHERE estado = ? ORDER BY creado_en ASC LIMIT 100`).bind(estado).all();
    return jsonResponse({ ok: true, articulos: await articulosConFotoAutor(rows.results) });
  }

  const matchAprobarArticulo = path.match(/^\/admin\/api\/articulos\/(\d+)\/aprobar$/);
  if (matchAprobarArticulo && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchAprobarArticulo[1];
    const articulo = await env.DB.prepare(`SELECT * FROM articulos WHERE id = ? AND estado = 'enviado'`).bind(id).first();
    if (!articulo) return errorResponse('Artículo no encontrado o ya procesado.', 404);
    await env.DB.prepare(
      `UPDATE articulos SET estado = 'publicado', aprobado_por_redaccion = ?, publicado_por = ?, fecha_publicacion = datetime('now'), actualizado_en = datetime('now') WHERE id = ?`
    ).bind(usuario.username, usuario.username, id).run();
    await otorgarPuntoInterno(env, articulo.autor_username, 1, 'Artículo aprobado y publicado', usuario.username);
    await registrarAuditoria(env, usuario.username, 'articulo_aprobado_publicado', `id=${id}`);

    await notificarUsuarioCompleto(env, articulo.autor_username, `To' Revuelto: ¡tu artículo "${articulo.titulo}" fue aprobado y ya está publicado!`, {
      link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/articulo/${articulo.slug}`,
      asunto: "¡Tu artículo ya está en vivo! — To' Revuelto",
      etiquetaBoton: 'Ver artículo publicado',
      tituloSuperior: 'Artículo publicado',
    });

    await notificarSuscriptoresNuevaPublicacion(env, articulo.titulo, 'artículo', `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/articulo/${articulo.slug}`);

    return jsonResponse({ ok: true });
  }

  const matchRechazarArticulo = path.match(/^\/admin\/api\/articulos\/(\d+)\/rechazar$/);
  if (matchRechazarArticulo && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchRechazarArticulo[1];
    const articulo = await env.DB.prepare(`SELECT * FROM articulos WHERE id = ?`).bind(id).first();
    if (!articulo) return errorResponse('Artículo no encontrado.', 404);
    await env.DB.prepare(`UPDATE articulos SET estado = 'rechazado', actualizado_en = datetime('now') WHERE id = ?`).bind(id).run();
    await registrarAuditoria(env, usuario.username, 'articulo_rechazado', `id=${id}`);

    await notificarUsuarioCompleto(env, articulo.autor_username, `To' Revuelto: tu artículo "${articulo.titulo}" no fue aprobado esta vez. Puedes revisarlo con dirección general.`, {
      link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/admin#mis-articulos`,
      asunto: "Actualización sobre tu artículo — To' Revuelto",
      etiquetaBoton: 'Ver mis artículos',
      tituloSuperior: 'Artículo no aprobado',
    });

    return jsonResponse({ ok: true });
  }

  const matchEliminarArticulo = path.match(/^\/admin\/api\/articulos\/(\d+)\/eliminar$/);
  if (matchEliminarArticulo && method === 'POST') {
    const id = matchEliminarArticulo[1];
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    await env.DB.prepare(`DELETE FROM articulos WHERE id = ?`).bind(id).run();
    await registrarAuditoria(env, usuario.username, 'articulo_eliminado', `id=${id}`);
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/secciones' && method === 'GET') {
    const rows = await env.DB.prepare(`SELECT * FROM secciones ORDER BY orden ASC, nombre ASC`).all();
    return jsonResponse({ ok: true, secciones: rows.results });
  }

  if (path === '/admin/api/secciones' && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden crear secciones.', 403);
    const body = await request.json().catch(() => ({}));
    const nombre = String(body.nombre || '').trim();
    const orden = parseInt(body.orden, 10) || 0;
    if (!nombre || nombre.length > 60) return errorResponse('Nombre de sección inválido.');
    const existente = await env.DB.prepare(`SELECT id FROM secciones WHERE nombre = ?`).bind(nombre).first();
    if (existente) return errorResponse('Ya existe una sección con ese nombre.');
    await env.DB.prepare(`INSERT INTO secciones (nombre, orden) VALUES (?, ?)`).bind(nombre, orden).run();
    return jsonResponse({ ok: true });
  }

  const matchEliminarSeccion = path.match(/^\/admin\/api\/secciones\/(\d+)\/eliminar$/);
  if (matchEliminarSeccion && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    await env.DB.prepare(`DELETE FROM secciones WHERE id = ?`).bind(matchEliminarSeccion[1]).run();
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/temas-sugeridos-rd' && method === 'POST') {
    if (!puedeGestionarArticulosRedaccion) return errorResponse('No autorizado.', 403);
    try {
      const temas = await generarTemasSugeridosRD(env);
      return jsonResponse({ ok: true, temas });
    } catch (e) {
      return errorResponse('No se pudieron generar temas en este momento: ' + e.message, 502);
    }
  }

  if (path === '/admin/api/temas-asignados' && method === 'POST') {
    if (!puedeGestionarArticulosRedaccion) return errorResponse('No autorizado.', 403);
    const body = await request.json().catch(() => ({}));
    const asignado_a_username = String(body.asignado_a_username || '');
    const fecha_asignada = String(body.fecha_asignada || '');
    const titulo = String(body.titulo || '').trim();

    if (!validarUsername(asignado_a_username)) return errorResponse('Redactor inválido.');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha_asignada)) return errorResponse('Fecha inválida.');
    if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');

    const voluntario = await obtenerUsuario(env, asignado_a_username);
    if (!voluntario || (voluntario.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(voluntario.rol))) return errorResponse('Ese usuario no es un voluntario válido.');

    let slug = slugify(titulo) + '-tema-' + generarIdAleatorio(4);
    const insercionTema = await env.DB.prepare(
      `INSERT INTO articulos (titulo, categoria, seccion, autor_username, cuerpo_html, estado, asignado_a_username, fecha_asignada, slug, creado_por)
       VALUES (?, 'Tema asignado', 'Por definir', ?, '', 'borrador', ?, ?, ?, ?)`
    ).bind(titulo, asignado_a_username, asignado_a_username, fecha_asignada, slug, usuario.username).run();

    await registrarAuditoria(env, usuario.username, 'tema_asignado', `${asignado_a_username} - ${fecha_asignada}`);

    await notificarTareaPorWhatsapp(
      env, asignado_a_username,
      `To' Revuelto: nuevo tema asignado para el ${fecha_asignada} — "${titulo}". Míralo aquí: ${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/a-${insercionTema.meta.last_row_id}`,
      'tema_articulo', insercionTema.meta.last_row_id
    );

    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/comentarios' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const tipo_objeto = String(body.tipo_objeto || '');
    const objeto_id = parseInt(body.objeto_id, 10);
    const mensaje = String(body.mensaje || '').trim();

    if (!['articulo', 'tarea_difusion'].includes(tipo_objeto)) return errorResponse('Tipo de objeto inválido.');
    if (!objeto_id || !mensaje || mensaje.length > 500) return errorResponse('Comentario inválido.');
    if (tipo_objeto === 'articulo' && !puedeGestionarArticulosRedaccion) return errorResponse('No autorizado.', 403);
    if (tipo_objeto === 'tarea_difusion' && !puedeGestionarDifusion) return errorResponse('No autorizado.', 403);

    await env.DB.prepare(
      `INSERT INTO comentarios (tipo_objeto, objeto_id, autor_username, mensaje) VALUES (?, ?, ?, ?)`
    ).bind(tipo_objeto, objeto_id, usuario.username, mensaje).run();

    if (tipo_objeto === 'articulo') {
      const articuloComentado = await env.DB.prepare(`SELECT titulo, autor_username FROM articulos WHERE id = ?`).bind(objeto_id).first();
      if (articuloComentado && articuloComentado.autor_username && articuloComentado.autor_username !== usuario.username) {
        await notificarUsuarioCompleto(env, articuloComentado.autor_username, `To' Revuelto: ${usuario.nombre_completo} comentó en tu artículo "${articuloComentado.titulo}": "${mensaje.slice(0, 200)}"`, {
          link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${objeto_id}`,
          asunto: "Nuevo comentario en tu artículo — To' Revuelto",
          etiquetaBoton: 'Ver comentario',
          tituloSuperior: 'Nuevo comentario',
          tipoObjeto: 'articulo',
          objetoId: objeto_id,
        });
      }
    } else if (tipo_objeto === 'tarea_difusion') {
      const tareaComentada = await env.DB.prepare(`SELECT titulo, asignado_a_username FROM tareas_difusion WHERE id = ?`).bind(objeto_id).first();
      if (tareaComentada) {
        const destinatariosComentario = new Set();
        if (tareaComentada.asignado_a_username && tareaComentada.asignado_a_username !== usuario.username) {
          destinatariosComentario.add(tareaComentada.asignado_a_username);
        }
        const miembrosTareaComentada = await env.DB.prepare(`SELECT username FROM tareas_difusion_miembros WHERE tarea_id = ?`).bind(objeto_id).all();
        for (const m of (miembrosTareaComentada.results || [])) {
          if (m.username !== usuario.username) destinatariosComentario.add(m.username);
        }
        for (const destinatarioUsername of destinatariosComentario) {
          await notificarUsuarioCompleto(env, destinatarioUsername, `To' Revuelto: ${usuario.nombre_completo} comentó en tu tarea "${tareaComentada.titulo}": "${mensaje.slice(0, 200)}"`, {
            link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${objeto_id}`,
            asunto: "Nuevo comentario en tu tarea — To' Revuelto",
            etiquetaBoton: 'Ver comentario',
            tituloSuperior: 'Nuevo comentario',
            tipoObjeto: 'tarea_difusion',
            objetoId: objeto_id,
          });
        }
      }
    }

    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/ideas-ia' && method === 'POST') {
    if (!ROLES_ALTA_DIRECCION.includes(usuario.rol)) return errorResponse('Solo la dirección puede generar tareas con IA.', 403);
    const body = await request.json().catch(() => ({}));
    const tipo = String(body.tipo || 'post');
    if (!['articulo', 'redaccion', 'meme', 'historia', 'post'].includes(tipo)) return errorResponse('Tipo inválido.');
    try {
      const { idea } = await generarIdeaUnica(env, tipo, usuario.username);
      return jsonResponse({ ok: true, idea });
    } catch (e) {
      return errorResponse('No se pudo generar la idea en este momento.', 502);
    }
  }

  if (path === '/admin/api/tareas-difusion' && method === 'POST') {
    if (!ROLES_ALTA_DIRECCION.includes(usuario.rol)) return errorResponse('Solo la dirección puede crear y asignar tareas.', 403);
    const body = await request.json().catch(() => ({}));
    const tipoCrudo = String(body.tipo || '').trim();
    const titulo = String(body.titulo || '').trim();
    const descripcion = String(body.descripcion || '').trim();
    const asignado_a_username = body.asignado_a_username ? String(body.asignado_a_username) : null;
    const miembros_grupo = Array.isArray(body.miembros_grupo) ? body.miembros_grupo.map(String).filter(Boolean) : [];
    const paraTodos = !!body.todos && !asignado_a_username && !miembros_grupo.length;

    const tiposFijos = ['articulo', 'redaccion', 'meme', 'historia', 'post', 'evento'];
    let tipo = tipoCrudo;
    if (!tiposFijos.includes(tipoCrudo)) {
      if (!tipoCrudo || tipoCrudo.length > 40) return errorResponse('Tipo de tarea inválido.');
      tipo = tipoCrudo;
    }
    if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');
    if (asignado_a_username) {
      const voluntario = await obtenerUsuario(env, asignado_a_username);
      if (!voluntario || (voluntario.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(voluntario.rol))) return errorResponse('Voluntario inválido.');
    }
    if (miembros_grupo.length) {
      for (const m of miembros_grupo) {
        const v = await obtenerUsuario(env, m);
        if (!v || (v.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(v.rol))) return errorResponse(`El usuario ${m} no es un voluntario válido.`);
      }
    }

    let miembrosParaTodos = [];
    if (paraTodos) {
      miembrosParaTodos = await listarUsuariosPorRoles(env, [ROLES.VOLUNTARIO]);
      if (!miembrosParaTodos.length) return errorResponse('No hay voluntarios activos para asignar esta tarea.');
    }

    // Los artículos/redacciones se entregan en una sola versión: si la tarea es grupal,
    // el primer integrante queda como responsable único de redactar en vez de que cada
    // quien redacte su propia versión por separado.
    const esEntregaUnica = (tipo === 'articulo' || tipo === 'redaccion');
    let responsableUnicoGrupo = null;
    let miembrosGrupoFinal = miembros_grupo;
    let asignadoFinal = asignado_a_username;
    if (esEntregaUnica && miembros_grupo.length) {
      responsableUnicoGrupo = miembros_grupo[0];
      asignadoFinal = responsableUnicoGrupo;
      miembrosGrupoFinal = [];
    }

    const insercionTarea = await env.DB.prepare(
      `INSERT INTO tareas_difusion (tipo, titulo, descripcion, asignado_a_username, estado, creado_por) VALUES (?, ?, ?, ?, 'pendiente', ?)`
    ).bind(tipo, titulo, descripcion || null, asignadoFinal, usuario.username).run();

    const idTareaNueva = insercionTarea.meta.last_row_id;
    const enlaceTarea = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${idTareaNueva}`;

    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} creó una nueva tarea de ${tipo} — "${titulo}".`, {
      link: enlaceTarea,
      asunto: "Nueva tarea creada — To' Revuelto",
      tituloSuperior: 'Tarea creada',
    });

    if (paraTodos) {
      for (const m of miembrosParaTodos) {
        await env.DB.prepare(
          `INSERT INTO tareas_difusion_miembros (tarea_id, username) VALUES (?, ?)`
        ).bind(idTareaNueva, m.username).run();
        await notificarTareaPorWhatsapp(
          env, m.username,
          `To' Revuelto: nueva tarea para todo el equipo de ${tipo} — "${titulo}". Cada quien entrega su propia versión. Míralo aquí: ${enlaceTarea}`,
          'tarea_difusion', idTareaNueva
        );
      }
    } else if (responsableUnicoGrupo) {
      await notificarTareaPorWhatsapp(
        env, responsableUnicoGrupo,
        `To' Revuelto: nueva tarea grupal de ${tipo} — "${titulo}". Fuiste asignado/a como responsable de entregarla. Míralo aquí: ${enlaceTarea}`,
        'tarea_difusion', idTareaNueva
      );
      for (const m of miembros_grupo) {
        if (m === responsableUnicoGrupo) continue;
        await notificarTareaPorWhatsapp(
          env, m,
          `To' Revuelto: nueva tarea grupal de ${tipo} — "${titulo}". El grupo la trabajará junto a ${responsableUnicoGrupo}, quien la entregará. Míralo aquí: ${enlaceTarea}`,
          'tarea_difusion', idTareaNueva
        );
      }
    } else if (miembrosGrupoFinal.length) {
      for (const m of miembrosGrupoFinal) {
        await env.DB.prepare(
          `INSERT INTO tareas_difusion_miembros (tarea_id, username) VALUES (?, ?)`
        ).bind(idTareaNueva, m).run();
        await notificarTareaPorWhatsapp(
          env, m,
          `To' Revuelto: nueva tarea grupal de ${tipo} — "${titulo}". Cualquiera del grupo puede entregarla. Míralo aquí: ${enlaceTarea}`,
          'tarea_difusion', idTareaNueva
        );
      }
    } else if (asignadoFinal) {
      await notificarTareaPorWhatsapp(
        env, asignadoFinal,
        `To' Revuelto: nueva tarea de ${tipo} — "${titulo}". Míralo aquí: ${enlaceTarea}`,
        'tarea_difusion', idTareaNueva
      );
    }

    return jsonResponse({ ok: true, id: idTareaNueva });
  }

  if (path === '/admin/api/mis-tareas' && method === 'GET') {
    if (usuario.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(usuario.rol)) return errorResponse('No autorizado.', 403);
    const rowsIndividuales = await env.DB.prepare(
      `SELECT * FROM tareas_difusion WHERE asignado_a_username = ? ORDER BY creado_en DESC LIMIT 50`
    ).bind(usuario.username).all();
    const rowsCompartidas = await env.DB.prepare(
      `SELECT td.* FROM tareas_difusion td INNER JOIN tareas_difusion_miembros tdm ON tdm.tarea_id = td.id WHERE tdm.username = ? ORDER BY td.creado_en DESC LIMIT 50`
    ).bind(usuario.username).all();
    const rowsDisponibles = await env.DB.prepare(
      `SELECT * FROM tareas_difusion WHERE asignado_a_username IS NULL AND estado = 'pendiente' AND id NOT IN (SELECT tarea_id FROM tareas_difusion_miembros) ORDER BY creado_en DESC LIMIT 50`
    ).all();

    const combinadas = [...(rowsIndividuales.results || [])];
    const idsExistentes = new Set(combinadas.map((t) => t.id));
    for (const t of rowsCompartidas.results || []) {
      if (!idsExistentes.has(t.id)) { combinadas.push(t); idsExistentes.add(t.id); }
    }
    for (const t of rowsDisponibles.results || []) {
      if (!idsExistentes.has(t.id)) { combinadas.push({ ...t, disponible_para_tomar: true }); idsExistentes.add(t.id); }
    }
    combinadas.sort((a, b) => (b.creado_en || '').localeCompare(a.creado_en || ''));

    for (const t of combinadas) {
      const miembros = await env.DB.prepare(`SELECT username FROM tareas_difusion_miembros WHERE tarea_id = ?`).bind(t.id).all();
      const listaMiembros = miembros.results || [];
      t.es_grupal = listaMiembros.length > 0;
      t.es_todos = listaMiembros.length > 0 && !t.asignado_a_username;

      if (t.disponible_para_tomar) {
        t.mi_estado = 'disponible';
      } else if (t.es_grupal) {
        const miEntrega = await env.DB.prepare(
          `SELECT estado FROM tareas_difusion_entregas WHERE tarea_id = ? AND username = ?`
        ).bind(t.id, usuario.username).first();
        t.mi_estado = miEntrega ? miEntrega.estado : 'pendiente';
      } else {
        t.mi_estado = t.estado;
      }
    }

    return jsonResponse({ ok: true, tareas: combinadas });
  }

  const matchTareasLista = path === '/admin/api/tareas-difusion';
  if (matchTareasLista && method === 'GET') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const url = new URL(request.url);
    const estado = url.searchParams.get('estado') || 'enviada';
    const rows = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE estado = ? ORDER BY creado_en ASC LIMIT 100`).bind(estado).all();
    const conUrl = [];
    for (const t of rows.results) {
      t.portada_archivo_url = urlPublicaR2(env, t.portada_archivo_key);
      const miembros = await env.DB.prepare(`SELECT username FROM tareas_difusion_miembros WHERE tarea_id = ?`).bind(t.id).all();
      const listaMiembros = miembros.results || [];
      const esCompartida = listaMiembros.length > 0;

      if (esCompartida) {
        const entregas = await env.DB.prepare(
          `SELECT * FROM tareas_difusion_entregas WHERE tarea_id = ? AND estado = ? ORDER BY creado_en ASC`
        ).bind(t.id, estado).all();
        if ((entregas.results || []).length) {
          for (const entrega of entregas.results) {
            const asignado = await obtenerUsuario(env, entrega.username);
            conUrl.push({
              ...t,
              entrega_id: entrega.id,
              asignado_a_username: entrega.username,
              asignado_nombre_completo: asignado ? asignado.nombre_completo : entrega.username,
              archivo_key: entrega.archivo_key,
              archivo_url: urlPublicaR2(env, entrega.archivo_key),
              asignado_foto_url: asignado ? urlPublicaR2(env, asignado.foto_key) : null,
              es_todos: !t.asignado_a_username,
              es_grupal: true,
            });
          }
        } else if (t.estado === estado) {
          conUrl.push({
            ...t,
            archivo_url: urlPublicaR2(env, t.archivo_key),
            asignado_foto_url: null,
            es_todos: !t.asignado_a_username,
            es_grupal: true,
          });
        }
      } else {
        const asignado = t.asignado_a_username ? await obtenerUsuario(env, t.asignado_a_username) : null;
        const portadaAsignado = t.portada_asignado_a_username ? await obtenerUsuario(env, t.portada_asignado_a_username) : null;
        conUrl.push({
          ...t,
          asignado_nombre_completo: asignado ? asignado.nombre_completo : (t.asignado_a_username || null),
          portada_asignado_nombre_completo: portadaAsignado ? portadaAsignado.nombre_completo : (t.portada_asignado_a_username || null),
          archivo_url: urlPublicaR2(env, t.archivo_key),
          asignado_foto_url: asignado ? urlPublicaR2(env, asignado.foto_key) : null,
        });
      }
    }
    return jsonResponse({ ok: true, tareas: conUrl });
  }

  const matchEnviarTarea = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/enviar$/);
  if (matchEnviarTarea && method === 'POST') {
    if (usuario.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(usuario.rol)) return errorResponse('No autorizado.', 403);
    const id = matchEnviarTarea[1];
    const tarea = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE id = ?`).bind(id).first();
    if (!tarea) return errorResponse('Tarea no encontrada.', 404);
    const miembrosGrupoTarea = await env.DB.prepare(`SELECT username FROM tareas_difusion_miembros WHERE tarea_id = ?`).bind(id).all();
    const listaMiembrosTarea = miembrosGrupoTarea.results || [];
    const esCompartida = listaMiembrosTarea.length > 0;
    const esMiembroDelGrupo = listaMiembrosTarea.some((m) => m.username === usuario.username);
    const estaDisponibleParaTomar = !esCompartida && !tarea.asignado_a_username && tarea.estado === 'pendiente';

    if (esCompartida) {
      if (!esMiembroDelGrupo) return errorResponse('Esta tarea no te pertenece.', 403);

      const form = await request.formData();
      const archivo = form.get('archivo');
      if (!archivo || archivo.size === 0) return errorResponse('Debes adjuntar un archivo.');
      if (archivo.size > 15 * 1024 * 1024) return errorResponse('Archivo demasiado grande (máx 15MB).');

      const entregaExistente = await env.DB.prepare(
        `SELECT estado FROM tareas_difusion_entregas WHERE tarea_id = ? AND username = ?`
      ).bind(id, usuario.username).first();
      if (entregaExistente && entregaExistente.estado !== 'rechazada') {
        return errorResponse('Ya entregaste tu versión de esta tarea.');
      }

      const buffer = await archivo.arrayBuffer();
      const esImagen = (archivo.type || '').startsWith('image/');
      let archivo_key;
      if (esImagen) {
        try {
          archivo_key = await subirImagenR2(env, buffer, 'tareas-difusion', `tarea-${id}-${usuario.username}`);
        } catch (e) {
          return errorResponse(e.message || 'La imagen no es válida. Usa JPG, PNG o WEBP.');
        }
      } else {
        archivo_key = `tareas-difusion/tarea-${id}-${usuario.username}-${generarIdAleatorio(8)}`;
        await env.BUCKET.put(archivo_key, buffer, { httpMetadata: { contentType: archivo.type || 'application/octet-stream' } });
      }

      await env.DB.prepare(
        `INSERT INTO tareas_difusion_entregas (tarea_id, username, archivo_key, estado, actualizado_en)
         VALUES (?, ?, ?, 'enviada', datetime('now'))
         ON CONFLICT(tarea_id, username) DO UPDATE SET archivo_key = excluded.archivo_key, estado = 'enviada', actualizado_en = datetime('now')`
      ).bind(id, usuario.username, archivo_key).run();

      if (tarea.estado === 'pendiente') {
        await env.DB.prepare(`UPDATE tareas_difusion SET estado = 'enviada', actualizado_en = datetime('now') WHERE id = ?`).bind(id).run();
      }

      return jsonResponse({ ok: true });
    }

    if (tarea.estado !== 'pendiente') return errorResponse('Tarea no encontrada o ya procesada.', 404);
    if (!estaDisponibleParaTomar && tarea.asignado_a_username && tarea.asignado_a_username !== usuario.username) return errorResponse('Esta tarea no te pertenece.', 403);

    const form = await request.formData();
    const archivo = form.get('archivo');
    if (!archivo || archivo.size === 0) return errorResponse('Debes adjuntar un archivo.');
    if (archivo.size > 15 * 1024 * 1024) return errorResponse('Archivo demasiado grande (máx 15MB).');

    const buffer = await archivo.arrayBuffer();
    const esImagen = (archivo.type || '').startsWith('image/');
    let archivo_key;
    if (esImagen) {
      try {
        archivo_key = await subirImagenR2(env, buffer, 'tareas-difusion', `tarea-${id}`);
      } catch (e) {
        return errorResponse(e.message || 'La imagen no es válida. Usa JPG, PNG o WEBP.');
      }
    } else {
      archivo_key = `tareas-difusion/tarea-${id}-${generarIdAleatorio(8)}`;
      await env.BUCKET.put(archivo_key, buffer, { httpMetadata: { contentType: archivo.type || 'application/octet-stream' } });
    }

    await env.DB.prepare(
      `UPDATE tareas_difusion SET archivo_key = ?, asignado_a_username = ?, estado = 'enviada_redaccion', actualizado_en = datetime('now') WHERE id = ?`
    ).bind(archivo_key, usuario.username, id).run();

    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} entregó la tarea "${tarea.titulo}". Puedes asignar la portada desde el panel.`, {
      link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${id}`,
      asunto: "Entrega lista para portada — To' Revuelto",
      tituloSuperior: 'Entrega recibida',
    });

    return jsonResponse({ ok: true });
  }

  const matchAsignarPortada = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/asignar-portada$/);
  if (matchAsignarPortada && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchAsignarPortada[1];
    const tarea = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE id = ?`).bind(id).first();
    if (!tarea) return errorResponse('Tarea no encontrada.', 404);
    if (tarea.estado !== 'enviada_redaccion') return errorResponse('Esta tarea no está lista para asignar portada.', 400);

    const body = await request.json().catch(() => ({}));
    const portada_asignado_a_username = String(body.portada_asignado_a_username || '');
    if (!validarUsername(portada_asignado_a_username)) return errorResponse('Debes elegir un voluntario válido.');
    const voluntarioPortada = await obtenerUsuario(env, portada_asignado_a_username);
    if (!voluntarioPortada || (voluntarioPortada.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(voluntarioPortada.rol))) {
      return errorResponse('Ese usuario no es un voluntario válido.');
    }

    await env.DB.prepare(
      `UPDATE tareas_difusion SET portada_asignado_a_username = ?, estado = 'portada_asignada', actualizado_en = datetime('now') WHERE id = ?`
    ).bind(portada_asignado_a_username, id).run();

    const enlacePortada = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${id}`;
    await notificarTareaPorWhatsapp(
      env, portada_asignado_a_username,
      `To' Revuelto: se te asignó hacer la portada de "${tarea.titulo}". Míralo aquí: ${enlacePortada}`,
      'tarea_difusion_portada', id, enlacePortada
    );
    await notificarDireccionGeneral(env, `To' Revuelto: se asignó la portada de "${tarea.titulo}" a ${voluntarioPortada.nombre_completo}.`, {
      link: enlacePortada,
      asunto: "Portada asignada — To' Revuelto",
      tituloSuperior: 'Portada asignada',
    });

    return jsonResponse({ ok: true });
  }

  const matchEnviarPortada = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/enviar-portada$/);
  if (matchEnviarPortada && method === 'POST') {
    if (usuario.rol !== ROLES.VOLUNTARIO && !ROLES_ALTA_DIRECCION.includes(usuario.rol)) return errorResponse('No autorizado.', 403);
    const id = matchEnviarPortada[1];
    const tarea = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE id = ?`).bind(id).first();
    if (!tarea) return errorResponse('Tarea no encontrada.', 404);
    if (tarea.portada_asignado_a_username !== usuario.username) return errorResponse('Esta portada no te pertenece.', 403);
    if (tarea.estado !== 'portada_asignada') return errorResponse('Esta tarea no está esperando portada.', 400);

    const form = await request.formData();
    const archivo = form.get('archivo');
    if (!archivo || archivo.size === 0) return errorResponse('Debes adjuntar la portada.');
    if (archivo.size > 15 * 1024 * 1024) return errorResponse('Archivo demasiado grande (máx 15MB).');

    const buffer = await archivo.arrayBuffer();
    let portada_archivo_key;
    try {
      portada_archivo_key = await subirImagenR2(env, buffer, 'tareas-portadas', `tarea-${id}`);
    } catch (e) {
      return errorResponse(e.message || 'La imagen de portada no es válida. Usa JPG, PNG o WEBP.');
    }

    await env.DB.prepare(
      `UPDATE tareas_difusion SET portada_archivo_key = ?, estado = 'portada_enviada', actualizado_en = datetime('now') WHERE id = ?`
    ).bind(portada_archivo_key, id).run();

    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} entregó la portada de "${tarea.titulo}". Ya puedes publicarlo desde el panel.`, {
      link: `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${id}`,
      asunto: "Portada lista para publicar — To' Revuelto",
      tituloSuperior: 'Portada recibida',
    });

    return jsonResponse({ ok: true });
  }

  const matchPublicarTarea = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/publicar$/);
  if (matchPublicarTarea && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchPublicarTarea[1];
    const tarea = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE id = ?`).bind(id).first();
    if (!tarea) return errorResponse('Tarea no encontrada.', 404);
    if (tarea.estado !== 'portada_enviada') return errorResponse('Esta tarea no está lista para publicar.', 400);

    if (tarea.tipo === 'articulo' || tarea.tipo === 'redaccion') {
      if (!tarea.articulo_cuerpo_html) return errorResponse('Esta tarea no tiene cuerpo de artículo redactado.');
      let slug = slugify(tarea.articulo_seccion ? `${tarea.titulo}` : tarea.titulo);
      const existeSlug = await env.DB.prepare(`SELECT id FROM articulos WHERE slug = ?`).bind(slug).first();
      if (existeSlug) slug = `${slug}-${generarIdAleatorio(4)}`;

      await env.DB.prepare(
        `INSERT INTO articulos (titulo, categoria, seccion, autor_username, cuerpo_html, extracto, portada_key, estado, slug, creado_por, publicado_por, fecha_publicacion)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'publicado', ?, ?, ?, datetime('now'))`
      ).bind(
        tarea.titulo, tarea.articulo_categoria || 'General', tarea.articulo_seccion || 'General',
        tarea.asignado_a_username, tarea.articulo_cuerpo_html, tarea.articulo_extracto,
        tarea.portada_archivo_key, slug, tarea.asignado_a_username, usuario.username
      ).run();

      await env.DB.prepare(`UPDATE tareas_difusion SET estado = 'publicada', articulo_slug = ?, publicado_por = ?, actualizado_en = datetime('now') WHERE id = ?`).bind(slug, usuario.username, id).run();

      if (tarea.asignado_a_username) await otorgarPuntoInterno(env, tarea.asignado_a_username, 1, 'Artículo publicado', usuario.username);
      if (tarea.portada_asignado_a_username) await otorgarPuntoInterno(env, tarea.portada_asignado_a_username, 1, 'Portada publicada', usuario.username);

      const enlaceArticuloPublicado = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/articulo/${slug}`;
      if (tarea.asignado_a_username) {
        await notificarUsuarioCompleto(env, tarea.asignado_a_username, `To' Revuelto: ¡tu redacción "${tarea.titulo}" fue publicada!`, {
          link: enlaceArticuloPublicado,
          asunto: "¡Tu artículo ya está en vivo! — To' Revuelto",
          etiquetaBoton: 'Ver artículo publicado',
          tituloSuperior: 'Artículo publicado',
          tipoObjeto: 'articulo',
        });
      }
      if (tarea.portada_asignado_a_username && tarea.portada_asignado_a_username !== tarea.asignado_a_username) {
        await notificarUsuarioCompleto(env, tarea.portada_asignado_a_username, `To' Revuelto: tu portada para "${tarea.titulo}" ya está publicada!`, {
          link: enlaceArticuloPublicado,
          asunto: "Tu portada ya está en vivo! — To' Revuelto",
          etiquetaBoton: 'Ver artículo publicado',
          tituloSuperior: 'Portada publicada',
          tipoObjeto: 'articulo',
        });
      }

      await notificarSuscriptoresNuevaPublicacion(env, tarea.titulo, 'artículo', enlaceArticuloPublicado);
    } else {
      await env.DB.prepare(`UPDATE tareas_difusion SET estado = 'publicada', publicado_por = ?, actualizado_en = datetime('now') WHERE id = ?`).bind(usuario.username, id).run();
      if (tarea.asignado_a_username) await otorgarPuntoInterno(env, tarea.asignado_a_username, 1, 'Tarea aprobada y publicada', usuario.username);
      if (tarea.portada_asignado_a_username) await otorgarPuntoInterno(env, tarea.portada_asignado_a_username, 1, 'Portada aprobada', usuario.username);

      const enlaceTareaPublicada = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/tarea/${id}`;
      if (tarea.asignado_a_username) {
        await notificarUsuarioCompleto(env, tarea.asignado_a_username, `To' Revuelto: tu entrega de "${tarea.titulo}" fue aprobada y publicada.`, {
          link: enlaceTareaPublicada,
          asunto: "Tu tarea ya está publicada — To' Revuelto",
          etiquetaBoton: 'Ver tarea',
          tituloSuperior: 'Tarea publicada',
          tipoObjeto: 'tarea_difusion',
          objetoId: id,
        });
      }
      if (tarea.portada_asignado_a_username && tarea.portada_asignado_a_username !== tarea.asignado_a_username) {
        await notificarUsuarioCompleto(env, tarea.portada_asignado_a_username, `To' Revuelto: tu portada para "${tarea.titulo}" fue aprobada y publicada.`, {
          link: enlaceTareaPublicada,
          asunto: "Tu portada ya está publicada — To' Revuelto",
          etiquetaBoton: 'Ver tarea',
          tituloSuperior: 'Portada publicada',
          tipoObjeto: 'tarea_difusion',
          objetoId: id,
        });
      }
    }

    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} publicó "${tarea.titulo}".`, {
      asunto: "Publicado — To' Revuelto",
      tituloSuperior: 'Publicación confirmada',
    });

    return jsonResponse({ ok: true });
  }

  const matchAprobarTarea = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/aprobar$/);
  if (matchAprobarTarea && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchAprobarTarea[1];
    const tarea = await env.DB.prepare(`SELECT * FROM tareas_difusion WHERE id = ?`).bind(id).first();
    if (!tarea) return errorResponse('Tarea no encontrada.', 404);

    const miembrosTareaAprobar = await env.DB.prepare(`SELECT username FROM tareas_difusion_miembros WHERE tarea_id = ?`).bind(id).all();
    const esCompartidaAprobar = (miembrosTareaAprobar.results || []).length > 0;

    if (esCompartidaAprobar) {
      const body = await request.json().catch(() => ({}));
      const targetUsername = String(body.username || '');
      if (!targetUsername) return errorResponse('Debes indicar qué entrega apruebas (username).');
      const entrega = await env.DB.prepare(
        `SELECT * FROM tareas_difusion_entregas WHERE tarea_id = ? AND username = ? AND estado = 'enviada'`
      ).bind(id, targetUsername).first();
      if (!entrega) return errorResponse('Entrega no encontrada o ya procesada.', 404);

      await env.DB.prepare(
        `UPDATE tareas_difusion_entregas SET estado = 'aprobada', aprobado_por = ?, actualizado_en = datetime('now') WHERE id = ?`
      ).bind(usuario.username, entrega.id).run();
      await otorgarPuntoInterno(env, targetUsername, 1, 'Tarea aprobada', usuario.username);

      return jsonResponse({ ok: true });
    }

    if (tarea.estado !== 'enviada') return errorResponse('Tarea no encontrada o ya procesada.', 404);

    await env.DB.prepare(`UPDATE tareas_difusion SET estado = 'aprobada', aprobado_por = ?, actualizado_en = datetime('now') WHERE id = ?`).bind(usuario.username, id).run();

    if (tarea.asignado_a_username) {
      await otorgarPuntoInterno(env, tarea.asignado_a_username, 1, 'Tarea aprobada', usuario.username);
    }

    await env.DB.prepare(`UPDATE tareas_difusion SET estado = 'publicada' WHERE id = ?`).bind(id).run();

    return jsonResponse({ ok: true });
  }

  const matchRechazarTarea = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/rechazar$/);
  if (matchRechazarTarea && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchRechazarTarea[1];

    const miembrosTareaRechazar = await env.DB.prepare(`SELECT username FROM tareas_difusion_miembros WHERE tarea_id = ?`).bind(id).all();
    const esCompartidaRechazar = (miembrosTareaRechazar.results || []).length > 0;

    if (esCompartidaRechazar) {
      const body = await request.json().catch(() => ({}));
      const targetUsername = String(body.username || '');
      if (!targetUsername) return errorResponse('Debes indicar qué entrega rechazas (username).');
      await env.DB.prepare(
        `UPDATE tareas_difusion_entregas SET estado = 'rechazada', actualizado_en = datetime('now') WHERE tarea_id = ? AND username = ?`
      ).bind(id, targetUsername).run();
      return jsonResponse({ ok: true });
    }

    await env.DB.prepare(`UPDATE tareas_difusion SET estado = 'rechazada', asignado_a_username = NULL, actualizado_en = datetime('now') WHERE id = ?`).bind(id).run();
    return jsonResponse({ ok: true });
  }

  const matchEliminarTarea = path.match(/^\/admin\/api\/tareas-difusion\/(\d+)\/eliminar$/);
  if (matchEliminarTarea && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden eliminar tareas.', 403);
    const id = matchEliminarTarea[1];
    await env.DB.prepare(`DELETE FROM tareas_difusion WHERE id = ?`).bind(id).run();
    await registrarAuditoria(env, usuario.username, 'tarea_difusion_eliminada', `id=${id}`);
    return jsonResponse({ ok: true });
  }

if (path === '/admin/api/postulantes-voluntariado' && method === 'GET') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);

    const url = new URL(request.url);
    const filtroEstado = url.searchParams.get('estado') || 'pendiente';

    if (!['pendiente', 'aceptado', 'rechazado'].includes(filtroEstado)) return errorResponse('Estado inválido.');

    const rows = await env.DB.prepare(
      `SELECT id, nombre_completo, edad, ciudad, correo, instagram, telefono, area, estado, creado_en FROM postulantes_voluntariado WHERE estado = ? ORDER BY creado_en ASC LIMIT 200`
    ).bind(filtroEstado).all();

    return jsonResponse({ ok: true, postulantes: rows.results });
  }

  const matchDetallePostulante = path.match(/^\/admin\/api\/postulantes-voluntariado\/(\d+)$/);
  if (matchDetallePostulante && method === 'GET') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);

    const id = matchDetallePostulante[1];
    const postulante = await env.DB.prepare(`SELECT * FROM postulantes_voluntariado WHERE id = ?`).bind(id).first();
    if (!postulante) return errorResponse('Postulante no encontrado.', 404);

    return jsonResponse({ ok: true, postulante });
  }

  const matchAceptarPostulante = path.match(/^\/admin\/api\/postulantes-voluntariado\/(\d+)\/aceptar$/);
  if (matchAceptarPostulante && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden aceptar postulantes.', 403);

    const id = matchAceptarPostulante[1];
    const postulante = await env.DB.prepare(`SELECT * FROM postulantes_voluntariado WHERE id = ? AND estado = 'pendiente'`).bind(id).first();
    if (!postulante) return errorResponse('Postulante no encontrado o ya procesado.', 404);

    const usuarioExistentePorCorreo = await env.DB.prepare(`SELECT username_creado FROM postulantes_voluntariado WHERE correo = ? AND estado = 'aceptado' AND id != ?`).bind(postulante.correo, id).first();
    if (usuarioExistentePorCorreo) return errorResponse('Ya existe un voluntario aceptado con ese correo.');

    const rolNuevo = ROLES.VOLUNTARIO;
    const username = await generarUsernameDisponible(env, postulante.nombre_completo);
    const passwordTemporal = generarPasswordTemporal();
    const salt = generarSalt();
    const password_hash = await hashPassword(passwordTemporal, salt, env.PASSWORD_PEPPER);

    const nuevoUsuario = {
      nombre_completo: postulante.nombre_completo,
      username,
      rol: rolNuevo,
      correo: postulante.correo,
      telefono: postulante.telefono,
      password_hash,
      salt,
      estado: 'activo',
      foto_key: null,
      creado_en: new Date().toISOString(),
    };
    await guardarUsuario(env, nuevoUsuario);
    await agregarAIndiceUsuarios(env, username);

    await env.DB.prepare(
      `UPDATE postulantes_voluntariado SET estado = 'aceptado', revisado_por = ?, username_creado = ?, credencial_temporal = ?, actualizado_en = datetime('now') WHERE id = ?`
    ).bind(usuario.username, username, passwordTemporal, id).run();

    await registrarAuditoria(env, usuario.username, 'postulante_aceptado', `id=${id} -> ${username}`);

    const areaNombre = NOMBRES_AREA_VISIBLE[postulante.area] || postulante.area;
    await notificarPostulanteAceptado(env, postulante, areaNombre, username, passwordTemporal);

    return jsonResponse({ ok: true, username });
  }

  const matchRechazarPostulante = path.match(/^\/admin\/api\/postulantes-voluntariado\/(\d+)\/rechazar$/);
  if (matchRechazarPostulante && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden rechazar postulantes.', 403);

    const id = matchRechazarPostulante[1];
    const postulante = await env.DB.prepare(`SELECT * FROM postulantes_voluntariado WHERE id = ? AND estado = 'pendiente'`).bind(id).first();
    if (!postulante) return errorResponse('Postulante no encontrado o ya procesado.', 404);

    await env.DB.prepare(`UPDATE postulantes_voluntariado SET estado = 'rechazado', revisado_por = ?, actualizado_en = datetime('now') WHERE id = ?`).bind(usuario.username, id).run();
    await registrarAuditoria(env, usuario.username, 'postulante_rechazado', `id=${id}`);

    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/directiva' && method === 'GET') {
    const rows = await env.DB.prepare(`SELECT * FROM directiva ORDER BY orden ASC`).all();
    const conUrl = rows.results.map((m) => ({ ...m, foto_url: urlPublicaR2(env, m.foto_key) }));
    return jsonResponse({ ok: true, miembros: conUrl });
  }

  if (path === '/admin/api/directiva' && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden gestionar la directiva.', 403);
    const form = await request.formData();
    const nombre_completo = String(form.get('nombre_completo') || '').trim();
    const cargo = String(form.get('cargo') || '').trim();
    const biografia = String(form.get('biografia') || '').trim();
    const orden = parseInt(form.get('orden'), 10) || 0;
    const foto = form.get('foto');

    if (!nombre_completo || nombre_completo.length > 120) return errorResponse('Nombre inválido.');
    if (!cargo || cargo.length > 80) return errorResponse('Cargo inválido.');
    if (!foto || foto.size === 0) return errorResponse('Debes subir una foto.');
    if (foto.size > 8 * 1024 * 1024) return errorResponse('Imagen demasiado grande (máx 8MB).');

    const buffer = await foto.arrayBuffer();
    let foto_key;
    try {
      foto_key = await subirImagenR2(env, buffer, 'directiva', slugify(nombre_completo).slice(0, 40));
    } catch (e) {
      return errorResponse(e.message || 'La foto no es válida. Usa JPG, PNG o WEBP.');
    }

    await env.DB.prepare(
      `INSERT INTO directiva (nombre_completo, cargo, biografia, foto_key, orden, creado_por) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(nombre_completo, cargo, biografia || null, foto_key, orden, usuario.username).run();

    return jsonResponse({ ok: true });
  }

  const matchEliminarDirectiva = path.match(/^\/admin\/api\/directiva\/(\d+)\/eliminar$/);
  if (matchEliminarDirectiva && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    await env.DB.prepare(`DELETE FROM directiva WHERE id = ?`).bind(matchEliminarDirectiva[1]).run();
    return jsonResponse({ ok: true });
  }

  const matchEditarDirectiva = path.match(/^\/admin\/api\/directiva\/(\d+)\/editar$/);
  if (matchEditarDirectiva && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden gestionar la directiva.', 403);
    const id = matchEditarDirectiva[1];
    const miembroExistente = await env.DB.prepare(`SELECT * FROM directiva WHERE id = ?`).bind(id).first();
    if (!miembroExistente) return errorResponse('Miembro de directiva no encontrado.', 404);

    const form = await request.formData();
    const nombre_completo = String(form.get('nombre_completo') || '').trim();
    const cargo = String(form.get('cargo') || '').trim();
    const biografia = String(form.get('biografia') || '').trim();
    const orden = parseInt(form.get('orden'), 10) || 0;
    const foto = form.get('foto');

    if (!nombre_completo || nombre_completo.length > 120) return errorResponse('Nombre inválido.');
    if (!cargo || cargo.length > 80) return errorResponse('Cargo inválido.');

    let foto_key = miembroExistente.foto_key;
    if (foto && foto.size > 0) {
      if (foto.size > 8 * 1024 * 1024) return errorResponse('Imagen demasiado grande (máx 8MB).');
      const buffer = await foto.arrayBuffer();
      try {
        foto_key = await subirImagenR2(env, buffer, 'directiva', slugify(nombre_completo).slice(0, 40));
      } catch (e) {
        return errorResponse(e.message || 'La foto no es válida. Usa JPG, PNG o WEBP.');
      }
    }

    await env.DB.prepare(
      `UPDATE directiva SET nombre_completo = ?, cargo = ?, biografia = ?, foto_key = ?, orden = ? WHERE id = ?`
    ).bind(nombre_completo, cargo, biografia || null, foto_key, orden, id).run();

    await registrarAuditoria(env, usuario.username, 'directiva_editada', `id=${id}`);
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/eventos' && method === 'GET') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const rows = await env.DB.prepare(`SELECT * FROM eventos ORDER BY creado_en DESC LIMIT 100`).all();
    return jsonResponse({ ok: true, eventos: rows.results });
  }

  if (path === '/admin/api/convocatorias' && method === 'GET') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const rows = await env.DB.prepare(`SELECT * FROM convocatorias ORDER BY reportes_count DESC, creado_en DESC LIMIT 200`).all();
    return jsonResponse({ ok: true, convocatorias: rows.results });
  }

  const matchEditarConvocatoria = path.match(/^\/admin\/api\/convocatorias\/(\d+)\/editar$/);
  if (matchEditarConvocatoria && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchEditarConvocatoria[1];
    const body = await request.json().catch(() => ({}));
    const titulo = String(body.titulo || '').trim();
    const descripcion = String(body.descripcion || '').trim();
    const fecha_evento = String(body.fecha_evento || '');
    const fecha_apertura = String(body.fecha_apertura || '');
    const fecha_cierre = String(body.fecha_cierre || '');
    const cupos_tipo = String(body.cupos_tipo || 'ilimitado');
    const cupos_cantidad_crudo = body.cupos_cantidad;
    const form_url = String(body.form_url || '').trim();
    const convocatoria_cerrada = body.convocatoria_cerrada ? 1 : 0;

    const convocatoria = await env.DB.prepare(`SELECT id FROM convocatorias WHERE id = ?`).bind(id).first();
    if (!convocatoria) return errorResponse('Publicación no encontrada.', 404);

    if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');
    if (fecha_evento && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_evento)) return errorResponse('Fecha del evento inválida.');
    if (fecha_apertura && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_apertura)) return errorResponse('Fecha de apertura inválida.');
    if (fecha_cierre && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_cierre)) return errorResponse('Fecha de cierre inválida.');
    if (fecha_apertura && fecha_cierre && fecha_apertura > fecha_cierre) return errorResponse('La fecha de cierre no puede ser antes que la de apertura.');
    if (!['ilimitado', 'personalizado'].includes(cupos_tipo)) return errorResponse('Tipo de cupos inválido.');
    let cupos_cantidad = null;
    if (cupos_tipo === 'personalizado') {
      cupos_cantidad = parseInt(cupos_cantidad_crudo, 10);
      if (!Number.isInteger(cupos_cantidad) || cupos_cantidad < 1) return errorResponse('Debes indicar una cantidad de cupos válida.');
    }
    if (!/^https?:\/\//i.test(form_url)) return errorResponse('El link del formulario debe ser una URL válida.');

    await env.DB.prepare(
      `UPDATE convocatorias SET titulo = ?, descripcion = ?, fecha_evento = ?, fecha_apertura = ?, fecha_cierre = ?, cupos_tipo = ?, cupos_cantidad = ?, form_url = ?, convocatoria_cerrada = ? WHERE id = ?`
    ).bind(titulo, descripcion || null, fecha_evento || null, fecha_apertura || null, fecha_cierre || null, cupos_tipo, cupos_cantidad, form_url, convocatoria_cerrada, id).run();

    await registrarAuditoria(env, usuario.username, 'convocatoria_editada', `id=${id}`);
    return jsonResponse({ ok: true });
  }

  const matchEliminarConvocatoria = path.match(/^\/admin\/api\/convocatorias\/(\d+)\/eliminar$/);
  if (matchEliminarConvocatoria && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    await env.DB.prepare(`DELETE FROM convocatorias WHERE id = ?`).bind(matchEliminarConvocatoria[1]).run();
    await registrarAuditoria(env, usuario.username, 'convocatoria_eliminada', `id=${matchEliminarConvocatoria[1]}`);
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/eventos' && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General puede crear eventos.', 403);
    const form = await request.formData();
    const titulo = String(form.get('titulo') || '').trim();
    const descripcion = String(form.get('descripcion') || '').trim();
    const fecha_evento = String(form.get('fecha_evento') || '');
    const fecha_apertura = String(form.get('fecha_apertura') || '');
    const fecha_cierre = String(form.get('fecha_cierre') || '');
    const cupos_tipo = String(form.get('cupos_tipo') || 'ilimitado');
    const cupos_cantidad_crudo = String(form.get('cupos_cantidad') || '');
    const lugar = String(form.get('lugar') || '').trim();
    const form_url = String(form.get('form_url') || '').trim();
    const imagen = form.get('imagen');

    if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha_evento)) return errorResponse('Fecha inválida.');
    if (fecha_apertura && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_apertura)) return errorResponse('Fecha de apertura inválida.');
    if (fecha_cierre && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_cierre)) return errorResponse('Fecha de cierre inválida.');
    if (fecha_apertura && fecha_cierre && fecha_apertura > fecha_cierre) return errorResponse('La fecha de cierre no puede ser antes que la de apertura.');
    if (!['ilimitado', 'personalizado'].includes(cupos_tipo)) return errorResponse('Tipo de cupos inválido.');
    let cupos_cantidad = null;
    if (cupos_tipo === 'personalizado') {
      cupos_cantidad = parseInt(cupos_cantidad_crudo, 10);
      if (!Number.isInteger(cupos_cantidad) || cupos_cantidad < 1) return errorResponse('Debes indicar una cantidad de cupos válida.');
    }
    if (!/^https?:\/\//i.test(form_url)) return errorResponse('El link del formulario debe ser una URL válida.');

    let imagen_key = null;
    if (imagen && imagen.size > 0) {
      if (imagen.size > 8 * 1024 * 1024) return errorResponse('Imagen demasiado grande (máx 8MB).');
      const buffer = await imagen.arrayBuffer();
      try {
        imagen_key = await subirImagenR2(env, buffer, 'eventos', slugify(titulo).slice(0, 40));
      } catch (e) {
        return errorResponse(e.message || 'La imagen no es válida. Usa JPG, PNG o WEBP.');
      }
    }

    let slug = slugify(titulo);
    const existe = await env.DB.prepare(`SELECT id FROM eventos WHERE slug = ?`).bind(slug).first();
    if (existe) slug = `${slug}-${generarIdAleatorio(4)}`;

    await env.DB.prepare(
      `INSERT INTO eventos (titulo, descripcion, fecha_evento, fecha_apertura, fecha_cierre, cupos_tipo, cupos_cantidad, lugar, imagen_key, form_url, slug, creado_por) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(titulo, descripcion || null, fecha_evento, fecha_apertura || null, fecha_cierre || null, cupos_tipo, cupos_cantidad, lugar || null, imagen_key, form_url, slug, usuario.username).run();

    return jsonResponse({ ok: true });
  }

  const matchAprobarEvento = path.match(/^\/admin\/api\/eventos\/(\d+)\/aprobar$/);
  if (matchAprobarEvento && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const idEventoAprobar = matchAprobarEvento[1];
    await env.DB.prepare(`UPDATE eventos SET estado = 'aprobado' WHERE id = ?`).bind(idEventoAprobar).run();
    const eventoAprobado = await env.DB.prepare(`SELECT titulo, slug FROM eventos WHERE id = ?`).bind(idEventoAprobar).first();
    if (eventoAprobado) {
      await notificarSuscriptoresNuevaPublicacion(env, eventoAprobado.titulo, 'evento', `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/eventos/${eventoAprobado.slug}`);
    }
    return jsonResponse({ ok: true });
  }

  const matchRechazarEvento = path.match(/^\/admin\/api\/eventos\/(\d+)\/rechazar$/);
  if (matchRechazarEvento && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    await env.DB.prepare(`UPDATE eventos SET estado = 'rechazado' WHERE id = ?`).bind(matchRechazarEvento[1]).run();
    return jsonResponse({ ok: true });
  }

  const matchEditarEvento = path.match(/^\/admin\/api\/eventos\/(\d+)\/editar$/);
  if (matchEditarEvento && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchEditarEvento[1];
    const body = await request.json().catch(() => ({}));
    const titulo = String(body.titulo || '').trim();
    const descripcion = String(body.descripcion || '').trim();
    const fecha_evento = String(body.fecha_evento || '');
    const lugar = String(body.lugar || '').trim();
    const fecha_apertura = String(body.fecha_apertura || '');
    const fecha_cierre = String(body.fecha_cierre || '');
    const cupos_tipo = String(body.cupos_tipo || 'ilimitado');
    const cupos_cantidad_crudo = body.cupos_cantidad;
    const form_url = String(body.form_url || '').trim();
    const convocatoria_cerrada = body.convocatoria_cerrada ? 1 : 0;

    const evento = await env.DB.prepare(`SELECT id FROM eventos WHERE id = ?`).bind(id).first();
    if (!evento) return errorResponse('Evento no encontrado.', 404);

    if (!titulo || titulo.length > 150) return errorResponse('Título inválido.');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(fecha_evento)) return errorResponse('Fecha del evento inválida.');
    if (fecha_apertura && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_apertura)) return errorResponse('Fecha de apertura inválida.');
    if (fecha_cierre && !/^\d{4}-\d{2}-\d{2}$/.test(fecha_cierre)) return errorResponse('Fecha de cierre inválida.');
    if (fecha_apertura && fecha_cierre && fecha_apertura > fecha_cierre) return errorResponse('La fecha de cierre no puede ser antes que la de apertura.');
    if (!['ilimitado', 'personalizado'].includes(cupos_tipo)) return errorResponse('Tipo de cupos inválido.');
    let cupos_cantidad = null;
    if (cupos_tipo === 'personalizado') {
      cupos_cantidad = parseInt(cupos_cantidad_crudo, 10);
      if (!Number.isInteger(cupos_cantidad) || cupos_cantidad < 1) return errorResponse('Debes indicar una cantidad de cupos válida.');
    }
    if (!/^https?:\/\//i.test(form_url)) return errorResponse('El link del formulario debe ser una URL válida.');

    await env.DB.prepare(
      `UPDATE eventos SET titulo = ?, descripcion = ?, fecha_evento = ?, lugar = ?, fecha_apertura = ?, fecha_cierre = ?, cupos_tipo = ?, cupos_cantidad = ?, form_url = ?, convocatoria_cerrada = ? WHERE id = ?`
    ).bind(titulo, descripcion || null, fecha_evento, lugar || null, fecha_apertura || null, fecha_cierre || null, cupos_tipo, cupos_cantidad, form_url, convocatoria_cerrada, id).run();

    await registrarAuditoria(env, usuario.username, 'evento_editado', `id=${id}`);
    return jsonResponse({ ok: true });
  }

  const matchAsistentesEvento = path.match(/^\/admin\/api\/eventos\/(\d+)\/asistentes$/);
  if (matchAsistentesEvento && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const body = await request.json().catch(() => ({}));
    const asistentes_texto = sanitizarHtmlArticulo(String(body.asistentes_texto || '').slice(0, 4000));
    await env.DB.prepare(`UPDATE eventos SET asistentes_texto = ? WHERE id = ?`).bind(asistentes_texto, matchAsistentesEvento[1]).run();
    return jsonResponse({ ok: true });
  }

  const matchEliminarEvento = path.match(/^\/admin\/api\/eventos\/(\d+)\/eliminar$/);
  if (matchEliminarEvento && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    await env.DB.prepare(`DELETE FROM eventos WHERE id = ?`).bind(matchEliminarEvento[1]).run();
    await registrarAuditoria(env, usuario.username, 'evento_eliminado', `id=${matchEliminarEvento[1]}`);
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/solicitudes-registro' && method === 'GET') {
    if (!esAccesoTotal) return jsonResponse({ ok: true, solicitudes: [] });
    const rows = await env.DB.prepare(`SELECT id, username, nombre_completo, rol_solicitado, area FROM solicitudes_registro WHERE estado = 'pendiente' ORDER BY creado_en ASC`).all();
    return jsonResponse({ ok: true, solicitudes: rows.results });
  }

  const matchAprobarSolicitud = path.match(/^\/admin\/api\/solicitudes-registro\/(\d+)\/aprobar$/);
  if (matchAprobarSolicitud && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado para aprobar esta solicitud.', 403);
    const id = matchAprobarSolicitud[1];
    const solicitud = await env.DB.prepare(`SELECT * FROM solicitudes_registro WHERE id = ? AND estado = 'pendiente'`).bind(id).first();
    if (!solicitud) return errorResponse('Solicitud no encontrada.', 404);

    const existente = await obtenerUsuario(env, solicitud.username);
    if (existente) return errorResponse('Ya existe un usuario con ese username.');

    const nuevoUsuario = {
      nombre_completo: solicitud.nombre_completo, username: solicitud.username, rol: solicitud.rol_solicitado,
      correo: solicitud.correo, telefono: solicitud.telefono, password_hash: solicitud.password_hash, salt: solicitud.salt,
      estado: 'activo', foto_key: null, creado_en: new Date().toISOString(),
    };
    await guardarUsuario(env, nuevoUsuario);
    await agregarAIndiceUsuarios(env, solicitud.username);
    await env.DB.prepare(`UPDATE solicitudes_registro SET estado = 'aprobado', revisado_por = ? WHERE id = ?`).bind(usuario.username, id).run();

    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} aprobó la solicitud de registro de ${solicitud.nombre_completo} (@${solicitud.username}).`, {
      asunto: "Nuevo usuario aprobado — To' Revuelto",
      tituloSuperior: 'Usuario aprobado',
    });

    return jsonResponse({ ok: true });
  }

  const matchRechazarSolicitud = path.match(/^\/admin\/api\/solicitudes-registro\/(\d+)\/rechazar$/);
  if (matchRechazarSolicitud && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const id = matchRechazarSolicitud[1];
    const solicitud = await env.DB.prepare(`SELECT * FROM solicitudes_registro WHERE id = ?`).bind(id).first();
    if (!solicitud) return errorResponse('Solicitud no encontrada.', 404);
    await env.DB.prepare(`UPDATE solicitudes_registro SET estado = 'rechazado', revisado_por = ? WHERE id = ?`).bind(usuario.username, id).run();
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/usuarios' && method === 'GET') {
    const url = new URL(request.url);
    const filtroRol = url.searchParams.get('rol');
    let usuarios = await listarUsuarios(env);

    if (filtroRol) {
      if (!esAltaDireccion) return errorResponse('No autorizado.', 403);
      usuarios = usuarios.filter((u) => u.rol === filtroRol);
      return jsonResponse({ ok: true, usuarios: usuarios.map((u) => usuarioPublicoConFoto(env, u)) });
    }

    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);

    const puedeGestionar = esAccesoTotal;

    return jsonResponse({ ok: true, usuarios: usuarios.map((u) => usuarioPublicoConFoto(env, u)), puede_gestionar: puedeGestionar });
  }

  const matchSuspenderUsuario = path.match(/^\/admin\/api\/usuarios\/([a-zA-Z0-9_.]+)\/suspender$/);
  if (matchSuspenderUsuario && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const targetUsername = matchSuspenderUsuario[1];
    const target = await obtenerUsuario(env, targetUsername);
    if (!target) return errorResponse('Usuario no encontrado.', 404);
    target.estado = 'suspendido';
    await guardarUsuario(env, target);
    await registrarAuditoria(env, usuario.username, 'usuario_suspendido', targetUsername);
    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} suspendió al usuario ${target.nombre_completo} (@${targetUsername}).`, {
      asunto: "Usuario suspendido — To' Revuelto",
      tituloSuperior: 'Usuario suspendido',
    });
    return jsonResponse({ ok: true });
  }

  const matchReactivarUsuario = path.match(/^\/admin\/api\/usuarios\/([a-zA-Z0-9_.]+)\/reactivar$/);
  if (matchReactivarUsuario && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const targetUsername = matchReactivarUsuario[1];
    const target = await obtenerUsuario(env, targetUsername);
    if (!target) return errorResponse('Usuario no encontrado.', 404);
    target.estado = 'activo';
    delete target.baneado_por_racha;
    await guardarUsuario(env, target);
    await registrarAuditoria(env, usuario.username, 'usuario_reactivado', targetUsername);
    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} reactivó al usuario ${target.nombre_completo} (@${targetUsername}).`, {
      asunto: "Usuario reactivado — To' Revuelto",
      tituloSuperior: 'Usuario reactivado',
    });
    await notificarUsuarioCompleto(env, targetUsername, `To' Revuelto: tu cuenta fue reactivada. Ya puedes entrar al panel de nuevo.`, {
      asunto: "Tu cuenta fue reactivada — To' Revuelto",
      tituloSuperior: 'Cuenta reactivada',
      etiquetaBoton: 'Entrar al panel',
    });
    return jsonResponse({ ok: true });
  }

  const matchEliminarUsuario = path.match(/^\/admin\/api\/usuarios\/([a-zA-Z0-9_.]+)\/eliminar$/);
  if (matchEliminarUsuario && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden eliminar usuarios.', 403);
    const targetUsername = matchEliminarUsuario[1];
    if (targetUsername === usuario.username) return errorResponse('No puedes eliminarte a ti mismo.');
    await env.USERS_KV.delete(`usuario:${targetUsername}`);
    const indice = await obtenerIndiceUsuarios(env);
    const nuevoIndice = indice.filter((u) => u !== targetUsername);
    await env.USERS_KV.put('indice_usuarios', JSON.stringify(nuevoIndice));
    await registrarAuditoria(env, usuario.username, 'usuario_eliminado', targetUsername);
    return jsonResponse({ ok: true });
  }

  const matchMensajeDirectoUsuario = path.match(/^\/admin\/api\/usuarios\/([a-zA-Z0-9_.]+)\/mensaje-whatsapp$/);
  if (matchMensajeDirectoUsuario && method === 'POST') {
    const targetUsername = matchMensajeDirectoUsuario[1];
    const target = await obtenerUsuario(env, targetUsername);
    if (!target) return errorResponse('Usuario no encontrado.', 404);

    if (!esAccesoTotal) return errorResponse('No autorizado para escribirle a este usuario.', 403);

    if (!target.telefono) return errorResponse('Este usuario no tiene teléfono registrado.');

    const body = await request.json().catch(() => ({}));
    const mensaje = String(body.mensaje || '').trim();
    if (!mensaje || mensaje.length > 900) return errorResponse('El mensaje es obligatorio (máx 900 caracteres).');

    const textoFinal = 'To Revuelto, mensaje de ' + usuario.nombre_completo + ': ' + mensaje;
    const resultadoEnvio = await enviarMensajeWhatsapp(
      env, target.telefono, textoFinal,
      { username: targetUsername, tipo_objeto: 'mensaje_directo' }
    );

    if (!resultadoEnvio.ok) return errorResponse(resultadoEnvio.error || 'No se pudo enviar el mensaje.', 502);

    await registrarAuditoria(env, usuario.username, 'mensaje_whatsapp_directo', `a=${targetUsername}`);
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/rachas' && method === 'GET') {
    const resultado = { ok: true };
    resultado.ranking = await obtenerRankingVoluntarios(env, 100);

    if (esAccesoTotal) {
      resultado.puede_otorgar = true;
      const todos = await listarUsuarios(env);
      const misVoluntarios = todos.filter((u) => u.rol === ROLES.VOLUNTARIO);
      resultado.mis_voluntarios = misVoluntarios.map(usuarioPublico);
    }

    return jsonResponse(resultado);
  }

  if (path === '/admin/api/rachas/punto' && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('No autorizado.', 403);
    const body = await request.json().catch(() => ({}));
    const targetUsername = String(body.username || '');
    const puntos = parseInt(body.puntos, 10);
    const motivo = String(body.motivo || '').slice(0, 300);

    if (!validarUsername(targetUsername)) return errorResponse('Usuario inválido.');
    if (puntos !== 1 && puntos !== -1) return errorResponse('Los puntos solo pueden ser +1 o -1.');

    const target = await obtenerUsuario(env, targetUsername);
    if (!target) return errorResponse('Usuario no encontrado.', 404);

    const total = await otorgarPuntoInterno(env, targetUsername, puntos, motivo, usuario.username);
    return jsonResponse({ ok: true, total });
  }

  if (path === '/admin/api/contactos-directiva' && method === 'GET') {
    if (usuario.rol !== ROLES.DIRECTOR_GENERAL) return errorResponse('Solo el Director General puede ver esta sección.', 403);
    const todos = await listarUsuarios(env);
    return jsonResponse({ ok: true, usuarios: todos.map((u) => usuarioPublicoConFoto(env, u)) });
  }

  if (path === '/admin/api/aviso-general' && method === 'POST') {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden enviar avisos generales.', 403);
    const body = await request.json().catch(() => ({}));
    const asunto = String(body.asunto || '').trim();
    const mensaje = String(body.mensaje || '').trim();

    if (!asunto || asunto.length > 150) return errorResponse('Asunto inválido.');
    if (!mensaje || mensaje.length > 2000) return errorResponse('Mensaje inválido.');

    const insercionAviso = await env.DB.prepare(
      `INSERT INTO avisos_generales (asunto, mensaje, creado_por) VALUES (?, ?, ?)`
    ).bind(asunto, mensaje, usuario.username).run();
    const idAvisoNuevo = insercionAviso.meta.last_row_id;
    const enlaceAvisoPublico = `${String(env.PUBLIC_SITE_URL || '').replace(/\/$/, '')}/aviso/${idAvisoNuevo}`;

    const todosUsuarios = await listarUsuarios(env);
    const activos = todosUsuarios.filter((u) => u.estado === 'activo');

    let totalEnviados = 0;
    for (const u of activos) {
      let enviadoAlgunCanal = false;
      if (u.correo) {
        const resultadoCorreo = await enviarCorreoBrevo(
          env, u.correo, u.nombre_completo, asunto, mensaje,
          enlaceAvisoPublico,
          'Ver aviso', 'Aviso general'
        );
        if (resultadoCorreo.ok) enviadoAlgunCanal = true;
      }
      if (u.telefono) {
        const resultadoWhatsapp = await enviarMensajeWhatsapp(
          env, u.telefono, `${asunto}: ${mensaje} ${enlaceAvisoPublico}`,
          { username: u.username, tipo_objeto: 'aviso_general', objeto_id: idAvisoNuevo }
        );
        if (resultadoWhatsapp.ok) enviadoAlgunCanal = true;
      }
      if (enviadoAlgunCanal) totalEnviados++;
    }

    await registrarAuditoria(env, usuario.username, 'aviso_general_enviado', `asunto="${asunto}" id=${idAvisoNuevo} total=${totalEnviados}`);
    await notificarDireccionGeneral(env, `To' Revuelto: ${usuario.nombre_completo} envió un aviso general a ${totalEnviados} usuarios — "${asunto}".`, {
      asunto: "Aviso general enviado — To' Revuelto",
      tituloSuperior: 'Aviso enviado',
    });
    return jsonResponse({ ok: true, total_enviados: totalEnviados, id: idAvisoNuevo });
  }

  if (path === '/admin/api/mis-preferencias' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const prefsActuales = await obtenerPreferenciasUsuario(env, usuario.username);

    if (body.tema !== undefined) {
      if (!TEMAS_DISPONIBLES[body.tema]) return errorResponse('Tema inválido.');
      prefsActuales.tema = body.tema;
    }
    if (body.orden_tabs !== undefined) {
      if (!Array.isArray(body.orden_tabs)) return errorResponse('Orden de pestañas inválido.');
      prefsActuales.orden_tabs = body.orden_tabs.map(String).slice(0, 30);
    }
    if (body.widgets_resumen_colapsados !== undefined) {
      if (!Array.isArray(body.widgets_resumen_colapsados)) return errorResponse('Formato inválido.');
      prefsActuales.widgets_resumen_colapsados = body.widgets_resumen_colapsados.map(String).slice(0, 30);
    }

    await guardarPreferenciasUsuario(env, usuario.username, prefsActuales);
    return jsonResponse({ ok: true });
  }

  if (path === '/admin/api/mi-perfil' && method === 'POST') {
    const form = await request.formData();
    const nuevoNombre = String(form.get('nombre_completo') || '').trim();
    const nuevoUsername = String(form.get('username') || '').trim();
    const nuevaPassword = String(form.get('password') || '');
    const foto = form.get('foto');

    const usuarioActualizado = await obtenerUsuario(env, usuario.username);
    if (!usuarioActualizado) return errorResponse('Usuario no encontrado.', 404);

    let requiereRelogin = false;

    if (nuevoNombre && nuevoNombre.length <= 120) usuarioActualizado.nombre_completo = nuevoNombre;

    if (foto && foto.size > 0) {
      if (foto.size > 8 * 1024 * 1024) return errorResponse('Imagen demasiado grande (máx 8MB).');
      const buffer = await foto.arrayBuffer();
      try {
        usuarioActualizado.foto_key = await subirImagenR2(env, buffer, 'perfiles', usuario.username);
      } catch (e) {
        return errorResponse(e.message || 'La foto no es válida. Usa JPG, PNG o WEBP.');
      }
    }

    if (nuevaPassword) {
      if (!validarPassword(nuevaPassword)) return errorResponse('La nueva contraseña debe tener al menos 6 caracteres.');
      const nuevoSalt = generarSalt();
      usuarioActualizado.password_hash = await hashPassword(nuevaPassword, nuevoSalt, env.PASSWORD_PEPPER);
      usuarioActualizado.salt = nuevoSalt;
      requiereRelogin = true;
    }

    if (nuevoUsername && nuevoUsername !== usuario.username) {
      if (!validarUsername(nuevoUsername)) return errorResponse('El nuevo usuario debe tener 3-32 caracteres alfanuméricos.');
      const existente = await obtenerUsuario(env, nuevoUsername);
      if (existente) return errorResponse('Ese usuario ya está en uso.');

      const usernameAnterior = usuario.username;
      usuarioActualizado.username = nuevoUsername;
      await guardarUsuario(env, usuarioActualizado);
      await agregarAIndiceUsuarios(env, nuevoUsername);
      await env.USERS_KV.delete(`usuario:${usernameAnterior}`);
      const indice = await obtenerIndiceUsuarios(env);
      const nuevoIndice = indice.filter((u) => u !== usernameAnterior);
      await env.USERS_KV.put('indice_usuarios', JSON.stringify(nuevoIndice));
      requiereRelogin = true;
    } else {
      await guardarUsuario(env, usuarioActualizado);
    }

    return jsonResponse({ ok: true, requiere_relogin: requiereRelogin });
  }

  if (path === '/admin/api/users7' && method === 'POST') {
    return errorResponse('Esta migración ya no está disponible.', 410);
  }
  if (false) {
    if (!esAccesoTotal) return errorResponse('Solo el Director General o Sub-Directora General pueden ejecutar esta migración.', 403);

    const todos = await listarUsuarios(env);
    let migrados = 0;
    let yaEstaban = 0;
    let respetados = 0;
    const detalleMigrados = [];

    for (const u of todos) {
      if (u.rol === ROLES.DIRECTOR_GENERAL || u.rol === ROLES.SUBDIRECTORA_GENERAL) {
        respetados++;
        continue;
      }
      if (u.rol === ROLES.VOLUNTARIO) {
        yaEstaban++;
        continue;
      }
      const rolAnterior = u.rol;
      u.rol = ROLES.VOLUNTARIO;
      await guardarUsuario(env, u);
      migrados++;
      detalleMigrados.push({ username: u.username, rol_anterior: rolAnterior });
    }

    await registrarAuditoria(env, usuario.username, 'migracion_masiva_voluntarios', `migrados=${migrados} ya_estaban=${yaEstaban} respetados=${respetados}`);

    return jsonResponse({ ok: true, migrados, ya_estaban_voluntario: yaEstaban, respetados_alta_direccion: respetados, detalle: detalleMigrados });
  }

  return errorResponse('Ruta de API no encontrada.', 404);
}
