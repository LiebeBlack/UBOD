/**
 * Bóveda Académica — Lógica Interactiva y Micro-animaciones Suaves
 * Vanilla JS sin dependencias externas.
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Navegación móvil
  const mobileToggle = document.querySelector('.mobile-toggle');
  const nav = document.querySelector('.nav');
  if (mobileToggle && nav) {
    mobileToggle.addEventListener('click', () => {
      nav.classList.toggle('open');
      const expanded = nav.classList.contains('open');
      mobileToggle.setAttribute('aria-expanded', expanded);
    });
  }

  // 2. Pipeline de Custodia Interactivo
  const pipelineSteps = document.querySelectorAll('.pipeline-step-btn');
  const detailTitle = document.getElementById('pipeline-detail-title');
  const detailDesc = document.getElementById('pipeline-detail-desc');
  const detailTech = document.getElementById('pipeline-detail-tech');
  const detailCode = document.getElementById('pipeline-detail-code');

  const pipelineData = {
    1: {
      title: "1. Admisión Segura & Staging Aislado",
      desc: "Ningún archivo entra directo a la bóveda. Las entregas llegan mediante canal mTLS 1.3 cifrado a un área de recepción temporal ('staging'), donde se evalúa su envelope de metadatos y se calcula el hash para confirmar que no hubo alteración en tránsito.",
      tech: "Canal mTLS 1.3 · PKI P-256 · Envelope JSON",
      code: "POST /v1/upload\nContent-Type: application/octet-stream\nX-Envelope: { \"device_id\": \"term-04\", \"sha256\": \"e3b0c44...\" }\n>> Verificando hash recibido vs calculado... OK [Staging]"
    },
    2: {
      title: "2. Doble Sellado Criptográfico (SHA-256 + BLAKE3)",
      desc: "Se procesa el archivo crudo en memoria calculando dos algoritmos criptográficos independientes y complementarios: SHA-256 para máxima compatibilidad institucional y BLAKE3 para resistencia extrema y rendimiento nativo.",
      tech: "Doble Hash Criptográfico · Algoritmos Independientes",
      code: "let sha256_hash = vault_crypto::sha256(&buffer);\nlet blake3_hash = vault_crypto::blake3(&buffer);\nassert_eq!(envelope.sha256, sha256_hash);\n>> Sellado de contenido validado con éxito."
    },
    3: {
      title: "3. Sello Temporal Cualificado RFC 3161",
      desc: "La TSA (Time Stamping Authority) integrada o externa emite una estampa de tiempo criptográfica firmada (token v1 con ESSCertIDv2). Esto prueba matemáticamente que el documento existía en ese instante exacto.",
      tech: "RFC 3161 TSA · Token ASN.1 Der · Firma P-256",
      code: "tsa::stamp_token(sha256_hash, SystemTime::now())\n>> Token emitido: 2026-09-25T16:08:40.104Z\n>> Firma de la autoridad certificadora verificada."
    },
    4: {
      title: "4. Inmutabilidad Física de Archivo (WORM en Linux)",
      desc: "Al admitirse en la bóveda final, se le aplica el atributo inmutable a nivel de sistema de archivos ('chattr +i'). Ni siquiera el usuario root o un proceso comprometido pueden modificar o truncar el archivo sin un protocolo de desbloqueo explícito.",
      tech: "Inmutabilidad FS (chattr +i) · WORM · Landlock",
      code: "# Bloqueo físico en el sistema de archivos Linux\nchattr +i /opt/boveda/vault/docs/2026/tesis_4192.pdf\n>> Atributo inmutable aplicado: Modificaciones bloqueadas."
    },
    5: {
      title: "5. Auditoría Encadenada Criptográfica (Merkle Chain)",
      desc: "La admisión genera un bloque en la cadena de auditoría, ligando el hash de la operación anterior con la actual. Si alguien intenta alterar un solo registro histórico, toda la cadena posterior queda rota y la bóveda lo señala de inmediato.",
      tech: "Cadena de Bloques Criptográfica · Registro Inalterable",
      code: "Block #4192 {\n  prev_hash: \"7f83b1657ff1fc53b92dc18148a1d65b...\",\n  doc_id: \"doc-2026-884\",\n  action: \"ADMIT_DOCUMENT\",\n  hash: \"a3b98129031ef09c4d9a...\"\n}"
    }
  };

  pipelineSteps.forEach(btn => {
    btn.addEventListener('click', () => {
      pipelineSteps.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const step = btn.getAttribute('data-step');
      if (pipelineData[step] && detailTitle && detailDesc && detailTech && detailCode) {
        detailTitle.textContent = pipelineData[step].title;
        detailDesc.textContent = pipelineData[step].desc;
        detailTech.textContent = pipelineData[step].tech;
        detailCode.textContent = pipelineData[step].code;
      }
    });
  });

  // 3. Simulador de Integridad Criptográfica (Bit-Rot & Alteración)
  const simBtnTamper = document.getElementById('sim-btn-tamper');
  const simBtnRestore = document.getElementById('sim-btn-restore');
  const simStatus = document.getElementById('sim-status');
  const simStatusText = document.getElementById('sim-status-text');
  const simValSha = document.getElementById('sim-val-sha');
  const simValBlake = document.getElementById('sim-val-blake');
  const simValChain = document.getElementById('sim-val-chain');

  const ORIGINAL_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const ORIGINAL_BLAKE = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
  const ORIGINAL_CHAIN = "00004192: 7f83b1657ff1fc53b92dc18148a1d65bfc3... [Cadena íntegra]";

  const TAMPERED_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b899 ⚠️ DIVERGENCIA";
  const TAMPERED_BLAKE = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3299 ⚠️ DIVERGENCIA";
  const TAMPERED_CHAIN = "00004192: ¡ERROR ENLACE CRIPTOGRÁFICO ROTO! Hash previo alterado";

  if (simBtnTamper && simBtnRestore) {
    simBtnTamper.addEventListener('click', () => {
      if (simStatus && simStatusText && simValSha && simValBlake && simValChain) {
        simStatus.classList.add('tampered');
        simStatusText.innerHTML = "<strong>ALERTA DE DIVERGENCIA CRIPTOGRÁFICA</strong> — Se detectó una alteración de bytes. El barrido de integridad aísla el archivo y preserva la evidencia.";
        simValSha.textContent = TAMPERED_SHA;
        simValSha.classList.add('invalid');
        simValBlake.textContent = TAMPERED_BLAKE;
        simValBlake.classList.add('invalid');
        simValChain.textContent = TAMPERED_CHAIN;
        simValChain.classList.add('invalid');
      }
    });

    simBtnRestore.addEventListener('click', () => {
      if (simStatus && simStatusText && simValSha && simValBlake && simValChain) {
        simStatus.classList.remove('tampered');
        simStatusText.innerHTML = "<strong>INTEGRIDAD 100% VERIFICADA</strong> — Doble hash coincidente con el registro de custodia. Auditoría encadenada intacta.";
        simValSha.textContent = ORIGINAL_SHA;
        simValSha.classList.remove('invalid');
        simValBlake.textContent = ORIGINAL_BLAKE;
        simValBlake.classList.remove('invalid');
        simValChain.textContent = ORIGINAL_CHAIN;
        simValChain.classList.remove('invalid');
      }
    });
  }

  // 4. Selector Interactivo de Roles y Permisos Institucionales
  const roleTabBtns = document.querySelectorAll('.role-tab-btn');
  const roleTitle = document.getElementById('role-title');
  const roleBadge = document.getElementById('role-badge');
  const roleDesc = document.getElementById('role-desc');
  const rolePermList = document.getElementById('role-perm-list');
  const roleAuditTrail = document.getElementById('role-audit-trail');

  const roleData = {
    docente: {
      badge: "Rol Docente · Consulta Segura",
      title: "Acceso y Búsqueda Documental",
      desc: "Permite a los docentes investigar y consultar el acervo institucional mediante búsqueda indexada y filtros de metadatos, con estricto régimen de solo lectura.",
      perms: [
        "Búsqueda por texto completo y metadatos (título, autor, cátedra)",
        "Visualización y descarga autorizada de documentos custodiados",
        "Sin permisos de modificación, movimiento o eliminación",
        "Rastro: Solo lectura (consultas registradas en registro de acceso)"
      ],
      audit: "ACCESS_READ { role: \"Docente\", doc_id: \"tesis-2026-04\", ip: \"127.0.0.1\" }"
    },
    administracion: {
      badge: "Rol Administración · Gestión Documental",
      title: "Organización y Clasificación del Fondo",
      desc: "Habilitado para clasificar, mover entre departamentos y enviar a papelera restaurable. Nunca tiene potestad de borrado físico directo.",
      perms: [
        "Mover documentos entre categorías institucionales",
        "Renombrar y organizar expedientes académicos",
        "Envío exclusivo a Papelera Restaurable (nunca borrado definitivo)",
        "Rastro: Auditoría encadenada con firma criptográfica en cada movimiento"
      ],
      audit: "MOVE_DOCUMENT { role: \"Admin\", doc_id: \"acta-2026-11\", from: \"/Facultad/A\", to: \"/Facultad/B\", chain_hash: \"3d89...\" }"
    },
    coordinacion: {
      badge: "Rol Coordinación · Versionado Seguro",
      title: "Control Editorial y Metadatos",
      desc: "Permite enriquecer y rectificar metadatos institucionales. El sistema genera de forma obligatoria e instantánea un snapshot inmutable previo antes de admitir cualquier cambio.",
      perms: [
        "Edición de metadatos catalográficos y descriptivos",
        "Creación automática de versión inmutable previa (historial completo)",
        "Consulta de auditoría encadenada del departamento",
        "Rastro: Registro de versión inmutable y hash enlazado"
      ],
      audit: "VERSION_METADATA { role: \"Coordinacion\", prev_version_hash: \"9f2a...\", new_version: 2, chain_hash: \"18ba...\" }"
    },
    direccion: {
      badge: "Rol Dirección · Supervisión & Acreditación",
      title: "Visión Global y Evidencia de Custodia",
      desc: "Otorga visión integral de todo el acervo institucional, consulta completa de la cadena de bloques de auditoría y emisión de reportes para procesos de acreditación.",
      perms: [
        "Supervisión global de todos los departamentos y facultades",
        "Auditoría integral: verificación matemática de toda la cadena de custodia",
        "Participación en protocolo de destrucción supervisada con doble PIN",
        "Rastro: Toda acción de supervisión queda firmada en la cadena"
      ],
      audit: "SUPERVISION_VERIFY { role: \"Direccion\", scan: \"FULL_SWEEP\", verified_items: 4192, bit_rot_errors: 0, status: \"INTEGRITY_OK\" }"
    }
  };

  roleTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      roleTabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const roleKey = btn.getAttribute('data-role');
      if (roleData[roleKey] && roleTitle && roleBadge && roleDesc && rolePermList && roleAuditTrail) {
        const r = roleData[roleKey];
        roleTitle.textContent = r.title;
        roleBadge.textContent = r.badge;
        roleDesc.textContent = r.desc;
        roleAuditTrail.textContent = r.audit;
        rolePermList.innerHTML = r.perms.map(p => `
          <li class="perm-item">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
            <span>${p}</span>
          </li>
        `).join('');
      }
    });
  });

  // 5. Simulador de Búsqueda Rápida
  const searchInput = document.getElementById('search-demo-input');
  const searchPills = document.querySelectorAll('.search-pill-btn');
  const searchResults = document.getElementById('search-results');

  const sampleDocs = [
    { title: "Tesis Doctoral: Redes Neuronales y Criptografía Poscuántica", cat: "Tesis", dep: "Informática", year: "2026", hash: "a492...e10b" },
    { title: "Acta de Sesión Ordinaria de Consejo Directivo #104", cat: "Acta", dep: "Gobierno", year: "2026", hash: "c812...77bb" },
    { title: "Investigación Clínica: Eficacia de Nuevos Antivirales", cat: "Investigación", dep: "Medicina", year: "2025", hash: "e341...aa90" },
    { title: "Plan de Estudios y Acreditación de Ingeniería de Software", cat: "Curricular", dep: "Ingeniería", year: "2026", hash: "7b01...41dd" },
    { title: "Tesis de Maestría: Análisis Genómico con Algoritmos BLAKE3", cat: "Tesis", dep: "Biotecnología", year: "2026", hash: "99fa...62cd" }
  ];

  function renderSearchResults(filterText = '') {
    if (!searchResults) return;
    const q = filterText.toLowerCase().trim();
    const filtered = sampleDocs.filter(doc => {
      if (!q) return true;
      const fullText = `${doc.title} ${doc.cat} ${doc.dep} ${doc.year}`.toLowerCase();
      if (q.includes(':')) {
        const [field, val] = q.split(':');
        if (field === 'categoria' || field === 'cat') return doc.cat.toLowerCase().includes(val);
        if (field === 'departamento' || field === 'dep') return doc.dep.toLowerCase().includes(val);
        if (field === 'año' || field === 'year') return doc.year.includes(val);
        if (field === 'texto') return doc.title.toLowerCase().includes(val);
      }
      return fullText.includes(q);
    });

    if (filtered.length === 0) {
      searchResults.innerHTML = `<div class="mut" style="padding:16px;text-align:center;">No se encontraron documentos custodiados con ese criterio.</div>`;
      return;
    }

    searchResults.innerHTML = filtered.map(d => `
      <div class="search-result-item">
        <div>
          <strong style="color:#fff;display:block;font-size:0.92rem;">${d.title}</strong>
          <span class="mut" style="font-size:0.78rem;">${d.cat} · Dpto. ${d.dep} · Año ${d.year}</span>
        </div>
        <div style="text-align:right;">
          <span class="badge-verified" style="font-size:0.7rem;">Sellado</span>
          <span class="mut" style="display:block;font-family:ui-monospace,monospace;font-size:0.7rem;margin-top:2px;">${d.hash}</span>
        </div>
      </div>
    `).join('');
  }

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      renderSearchResults(e.target.value);
    });
  }

  searchPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const q = pill.getAttribute('data-query');
      if (searchInput) {
        searchInput.value = q;
      }
      renderSearchResults(q);
    });
  });

  // Render inicial de búsqueda
  renderSearchResults();

  // 6. Botones de Copiar al Portapapeles
  const copyButtons = document.querySelectorAll('.copy-btn');
  copyButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const textToCopy = btn.getAttribute('data-copy') || btn.parentElement.querySelector('code')?.textContent || '';
      if (textToCopy) {
        try {
          await navigator.clipboard.writeText(textToCopy);
          const originalHTML = btn.innerHTML;
          btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg> Copiado`;
          btn.style.borderColor = 'rgba(52, 211, 153, 0.5)';
          btn.style.color = '#34d399';
          setTimeout(() => {
            btn.innerHTML = originalHTML;
            btn.style.borderColor = '';
            btn.style.color = '';
          }, 2000);
        } catch (err) {
          console.error("Error al copiar:", err);
        }
      }
    });
  });

  // 7. Animaciones suaves de scroll (IntersectionObserver)
  const reveals = document.querySelectorAll('.reveal-on-scroll');
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, {
      threshold: 0.08,
      rootMargin: "0px 0px -40px 0px"
    });

    reveals.forEach(el => observer.observe(el));
  } else {
    reveals.forEach(el => el.classList.add('is-visible'));
  }
});
