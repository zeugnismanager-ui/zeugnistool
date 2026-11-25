// Browser-Seite von IKO.Zeugnis.
// Enthält nur rohe Kryptografie und Dateihilfen; das Dateiformat liegt in C# (Zeugnis.Exchange.EnvelopeCodec).
window.zeugnis = (() => {
  const encoder = new TextEncoder();

  async function deriveKey(password, salt, iterations) {
    const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // Ergebnis = Ciphertext || 16-Byte-Tag (identisch zur .NET-Implementierung).
  async function encrypt(plain, password, salt, nonce, iterations, aad) {
    const key = await deriveKey(password, salt, iterations);
    return new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, plain));
  }

  async function decrypt(cipherAndTag, password, salt, nonce, iterations, aad) {
    const key = await deriveKey(password, salt, iterations);
    try {
      return new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, cipherAndTag));
    } catch {
      throw new Error("ZEUGNIS_DECRYPT_FAILED");
    }
  }

  function download(bytes, fileName, mime) {
    const blob = new Blob([bytes], { type: mime || "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  const isSecure = () => !!(window.isSecureContext && crypto && crypto.subtle);

  // Warnung beim Schließen/Neuladen des Tabs, solange ungespeicherte Änderungen bestehen.
  let guard = false;
  window.addEventListener("beforeunload", e => { if (guard) { e.preventDefault(); e.returnValue = ""; } });
  const setUnloadGuard = active => { guard = !!active; };

  const scrollToMain = () => {
    const el = document.querySelector(".grading-main");
    if (el && el.getBoundingClientRect().top < 0) el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const scrollToField = id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.remove("field-jump-highlight");
    void el.offsetWidth;
    el.classList.add("field-jump-highlight");
    setTimeout(() => el.classList.remove("field-jump-highlight"), 1800);
    setTimeout(() => el.querySelector("button, input, textarea, select")?.focus({ preventScroll: true }), 450);
  };

  // Katalogelemente: Pointer-basierte Sortierung funktioniert mit Maus, Stift und Touch.
  // Der sichtbare Klon folgt dem Zeiger; die eigentliche Liste wird erst nach dem Loslassen in C# geändert.
  const catalogSort = (() => {
    let ref = null;
    let drag = null;

    const clearTarget = () => {
      document.querySelectorAll(".catalog-drop-zone.active").forEach(x => x.classList.remove("active"));
    };

    const cleanup = () => {
      if (!drag) return;
      drag.handle.removeEventListener("pointermove", move);
      drag.handle.removeEventListener("pointerup", end);
      drag.handle.removeEventListener("pointercancel", cancel);
      drag.card.classList.remove("is-dragging");
      drag.container.classList.remove("is-sorting");
      drag.ghost.remove();
      clearTarget();
      drag = null;
    };

    const targetAt = (x, y) => {
      const hit = document.elementFromPoint(x, y);
      const direct = hit?.closest?.(".catalog-drop-zone");
      if (direct) return direct;
      const card = hit?.closest?.(".section-card[data-catalog-key]");
      if (!card || !drag?.container.contains(card)) return null;
      const cards = [...drag.container.querySelectorAll(".section-card[data-catalog-key]")];
      const index = cards.indexOf(card);
      const before = y < card.getBoundingClientRect().top + card.getBoundingClientRect().height / 2;
      return drag.container.querySelector(`[data-drop-index="${index + (before ? 0 : 1)}"]`);
    };

    function move(e) {
      if (!drag || e.pointerId !== drag.pointerId) return;
      e.preventDefault();
      drag.ghost.style.left = `${e.clientX - drag.offsetX}px`;
      drag.ghost.style.top = `${e.clientY - drag.offsetY}px`;
      clearTarget();
      drag.target = targetAt(e.clientX, e.clientY);
      drag.target?.classList.add("active");
      const edge = 90;
      const speed = 18;
      if (e.clientY < edge) window.scrollBy(0, -speed);
      else if (e.clientY > window.innerHeight - edge) window.scrollBy(0, speed);
    }

    function finish(e, apply) {
      if (!drag || e.pointerId !== drag.pointerId) return;
      e.preventDefault();
      const current = drag;
      const index = current.target ? Number(current.target.dataset.dropIndex) : NaN;
      cleanup();
      if (apply && Number.isInteger(index) && ref)
        ref.invokeMethodAsync("OnCatalogDrop", current.kind, current.key, index);
    }

    function end(e) { finish(e, true); }
    function cancel(e) { finish(e, false); }

    function down(e) {
      const handle = e.target.closest?.(".drag-handle");
      if (!handle || (e.button !== undefined && e.button !== 0)) return;
      const card = handle.closest(".section-card[data-catalog-key]");
      const container = handle.closest("[data-catalog-sort]");
      if (!card || !container) return;
      e.preventDefault();
      const rect = card.getBoundingClientRect();
      const ghost = card.cloneNode(true);
      ghost.classList.add("catalog-drag-ghost");
      ghost.removeAttribute("data-catalog-key");
      ghost.style.width = `${rect.width}px`;
      ghost.style.left = `${rect.left}px`;
      ghost.style.top = `${rect.top}px`;
      ghost.style.height = `${rect.height}px`;
      document.body.appendChild(ghost);
      drag = {
        pointerId: e.pointerId, handle, card, container, ghost,
        key: card.dataset.catalogKey, kind: card.dataset.catalogKind,
        offsetX: e.clientX - rect.left, offsetY: e.clientY - rect.top, target: null,
      };
      card.classList.add("is-dragging");
      container.classList.add("is-sorting");
      handle.setPointerCapture(e.pointerId);
      handle.addEventListener("pointermove", move, { passive: false });
      handle.addEventListener("pointerup", end, { passive: false });
      handle.addEventListener("pointercancel", cancel, { passive: false });
    }

    const start = dotNetRef => {
      stop();
      ref = dotNetRef;
      document.addEventListener("pointerdown", down, { passive: false });
    };
    const stop = () => {
      cleanup();
      document.removeEventListener("pointerdown", down);
      ref = null;
    };
    return { start, stop };
  })();

  // Verschlüsselte Entwürfe im Gerätespeicher (Inhalt ist bereits mit dem Auftragskennwort verschlüsselt).
  const draftPrefix = "zeugnis.draft.";
  const draft = {
    get: id => { try { return localStorage.getItem(draftPrefix + id); } catch { return null; } },
    set: (id, base64) => {
      try { localStorage.setItem(draftPrefix + id, base64); return true; } catch { return false; }
    },
    remove: id => { try { localStorage.removeItem(draftPrefix + id); } catch { } },
  };

  // Inaktivität: misst die Zeit seit der letzten Eingabe. Zeitstempel statt Timer,
  // weil iPad/Safari Timer im Hintergrund anhält; beim Zurückkehren wird sofort geprüft.
  const idle = (() => {
    const state = { last: Date.now(), ref: null, warnMs: 0, closeMs: 0, warned: false, timer: 0 };
    const touch = () => {
      state.last = Date.now();
      if (state.warned && state.ref) { state.warned = false; state.ref.invokeMethodAsync("OnIdleReset"); }
    };
    ["pointerdown", "keydown", "wheel", "touchstart"].forEach(t =>
      window.addEventListener(t, touch, { passive: true, capture: true }));
    const check = () => {
      if (!state.ref) return;
      const elapsed = Date.now() - state.last;
      if (elapsed >= state.closeMs) {
        const ref = state.ref;
        stop();
        ref.invokeMethodAsync("OnIdleTimeout");
      } else if (elapsed >= state.warnMs) {
        state.warned = true;
        state.ref.invokeMethodAsync("OnIdleWarning", Math.ceil((state.closeMs - elapsed) / 1000));
      }
    };
    document.addEventListener("visibilitychange", () => { if (!document.hidden) check(); });
    function start(ref, warnMs, closeMs) {
      stop();
      Object.assign(state, { ref, warnMs, closeMs, warned: false, last: Date.now() });
      state.timer = setInterval(check, 5000);
    }
    function stop() { clearInterval(state.timer); state.ref = null; state.warned = false; }
    return { start, stop, touch, check, state };
  })();

  // Updates der installierten App: ein neuer Service Worker wartet, bis die Nutzerin/der Nutzer bestätigt.
  const sw = (() => {
    const state = { registration: null, ready: false, ref: null };
    const markReady = () => {
      state.ready = true;
      if (state.ref) state.ref.invokeMethodAsync("OnUpdateReady");
    };
    async function register() {
      if (!("serviceWorker" in navigator)) return;
      try {
        const reg = await navigator.serviceWorker.register("service-worker.js");
        state.registration = reg;
        if (reg.waiting && navigator.serviceWorker.controller) markReady();
        reg.addEventListener("updatefound", () => {
          const worker = reg.installing;
          worker?.addEventListener("statechange", () => {
            if (worker.state === "installed" && navigator.serviceWorker.controller) markReady();
          });
        });
        // Regelmäßig und beim Zurückkehren in die App nach einer neuen Version fragen.
        setInterval(() => reg.update().catch(() => { }), 30 * 60_000);
        document.addEventListener("visibilitychange", () => { if (!document.hidden) reg.update().catch(() => { }); });
      } catch (e) {
        console.warn("Service worker:", e);
      }
    }
    function watch(ref) {
      state.ref = ref;
      if (state.ready) ref.invokeMethodAsync("OnUpdateReady");
    }
    function apply() {
      const waiting = state.registration?.waiting;
      if (!waiting) { location.reload(); return; }
      navigator.serviceWorker.addEventListener("controllerchange", () => location.reload(), { once: true });
      waiting.postMessage("SKIP_WAITING");
    }
    return { register, watch, apply, markReady, state };
  })();

  return { encrypt, decrypt, download, isSecure, setUnloadGuard, scrollToMain, scrollToField, catalogSort, draft, idle, sw };
})();
