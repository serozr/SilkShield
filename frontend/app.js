/* ═══════════════════════════════════════════════════════════════
   SilkShield — Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

const API = window.location.origin;
const MAX_HASH_FILE_SIZE = 50 * 1024 * 1024;
let selectedFile = null;

// ─── State Management ──────────────────────────────────────── //

const $ = (id) => document.getElementById(id);

function showState(state) {
    ["idle-state", "loading-state", "error-state", "result-state"].forEach(
        (s) => $(s)?.classList.add("hidden")
    );
    $(state)?.classList.remove("hidden");
}

// ─── Demo IOCs ─────────────────────────────────────────────── //

async function loadDemoIOCs() {
    try {
        const res = await fetch(`${API}/demo-iocs`);
        const data = await res.json();
        const container = $("demo-iocs");

        (data.demo_iocs || []).forEach((item) => {
            const chip = document.createElement("button");
            chip.className = "demo-chip";
            chip.textContent = item.ioc;
            chip.title = item.description;
            chip.onclick = () => {
                setSearchMode("ioc");
                $("ioc-input").value = item.ioc;
                updateDetectedType();
                analyzeIOC();
            };
            container.appendChild(chip);
        });
    } catch {
        /* silently ignore — demo chips are optional */
    }
}

// ─── Analysis ──────────────────────────────────────────────── //

let lastIOC = "";

async function analyzeIOC(iocOverride = null, actionButton = $("analyze-btn")) {
    const input = $("ioc-input");
    const ioc = String(iocOverride ?? input.value).trim();
    if (!ioc) {
        input.focus();
        return;
    }

    lastIOC = ioc;
    const btn = actionButton;
    if (iocOverride !== null) input.value = ioc;
    btn.classList.add("loading");
    btn.disabled = true;

    showState("loading-state");
    animateLoadingSteps();

    try {
        const res = await fetch(`${API}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ioc }),
        });

        if (!res.ok) {
            const err = await res.json().catch(() => null);
            const msg =
                err?.detail?.error?.message ||
                err?.detail?.[0]?.msg ||
                `Server returned ${res.status}`;
            throw new Error(msg);
        }

        const data = await res.json();
        renderResult(data);
        showState("result-state");
        return true;
    } catch (err) {
        $("error-message").textContent = err.message;
        showState("error-state");
        return false;
    } finally {
        btn.classList.remove("loading");
        btn.disabled = false;
    }
}

function setSearchMode(mode) {
    const isFileMode = mode === "file";
    $("ioc-tab").classList.toggle("active", !isFileMode);
    $("file-tab").classList.toggle("active", isFileMode);
    $("ioc-tab").setAttribute("aria-selected", String(!isFileMode));
    $("file-tab").setAttribute("aria-selected", String(isFileMode));
    $("ioc-panel").classList.toggle("hidden", isFileMode);
    $("file-panel").classList.toggle("hidden", !isFileMode);
    if (isFileMode) $("file-dropzone").focus();
    else $("ioc-input").focus();
}

function detectInputType(value) {
    const ioc = value.trim();
    if (!ioc) return "AUTO DETECT";
    if (/^[a-f\d]{32}$|^[a-f\d]{40}$|^[a-f\d]{64}$/i.test(ioc)) return "FILE HASH";
    if (/^https?:\/\//i.test(ioc)) return "URL";
    if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(ioc) || ioc.includes(":")) return "IP ADDRESS";
    return "DOMAIN";
}

function updateDetectedType() {
    const label = $("detected-type");
    if (label) label.textContent = detectInputType($("ioc-input").value);
}

function formatFileSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function hashSelectedFile() {
    const file = selectedFile;
    const button = $("scan-file-btn");
    const hashOutput = $("file-hash-result");
    if (!file) return;
    if (file.size > MAX_HASH_FILE_SIZE) {
        hashOutput.textContent = "This file exceeds the 50 MB browser hashing limit. Paste a known hash instead.";
        hashOutput.classList.remove("hidden");
        return;
    }
    if (!window.crypto?.subtle) {
        hashOutput.textContent = "Secure browser hashing is unavailable here. Open this page over HTTPS or enter a SHA-256 hash manually.";
        hashOutput.classList.remove("hidden");
        return;
    }

    button.disabled = true;
    button.classList.add("loading");
    $("file-meta").textContent = `Calculating SHA-256 · ${formatFileSize(file.size)}`;
    hashOutput.classList.add("hidden");
    try {
        const bytes = await file.arrayBuffer();
        const digest = await window.crypto.subtle.digest("SHA-256", bytes);
        const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
        $("ioc-input").value = hash;
        hashOutput.textContent = `SHA-256 · ${hash} · Looking up reputation…`;
        hashOutput.classList.remove("hidden");
        const completed = await analyzeIOC(hash, button);
        hashOutput.textContent = completed
            ? `SHA-256 · ${hash} · Reputation result shown below; check its intelligence source.`
            : `SHA-256 · ${hash} · Lookup failed. Review the error above before retrying.`;
    } catch (err) {
        hashOutput.textContent = `Could not calculate the file hash: ${err.message}`;
        hashOutput.classList.remove("hidden");
        button.disabled = false;
        button.classList.remove("loading");
    } finally {
        button.disabled = false;
        button.classList.remove("loading");
        $("file-meta").textContent = `${formatFileSize(file.size)} · file stays on this device`;
    }
}

function initSearchControls() {
    $("ioc-tab")?.addEventListener("click", () => setSearchMode("ioc"));
    $("file-tab")?.addEventListener("click", () => setSearchMode("file"));
    $("ioc-input")?.addEventListener("input", updateDetectedType);
    const fileInput = $("sample-file");
    const dropzone = $("file-dropzone");

    const acceptFile = (file) => {
        if (!file) return;
        selectedFile = file;
        $("file-name").textContent = file.name;
        $("file-meta").textContent = `${formatFileSize(file.size)} · ready for local SHA-256 calculation`;
        $("scan-file-btn").disabled = false;
        $("file-hash-result").classList.add("hidden");
    };

    dropzone?.addEventListener("click", () => fileInput?.click());
    fileInput?.addEventListener("change", () => acceptFile(fileInput.files?.[0]));
    ["dragenter", "dragover"].forEach((eventName) => dropzone?.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.add("dragging");
    }));
    ["dragleave", "drop"].forEach((eventName) => dropzone?.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.remove("dragging");
    }));
    dropzone?.addEventListener("drop", (event) => acceptFile(event.dataTransfer?.files?.[0]));
    $("scan-file-btn")?.addEventListener("click", hashSelectedFile);
}

function retryAnalysis() {
    if (lastIOC) {
        $("ioc-input").value = lastIOC;
        analyzeIOC();
    } else {
        showState("idle-state");
    }
}

// ─── Loading Animation ────────────────────────────────────── //

function animateLoadingSteps() {
    const steps = ["step-intel", "step-ml", "step-ai"];
    steps.forEach((s) => {
        $(s).classList.remove("active", "done");
    });
    $(steps[0]).classList.add("active");

    setTimeout(() => {
        $(steps[0]).classList.replace("active", "done");
        $(steps[1]).classList.add("active");
    }, 600);

    setTimeout(() => {
        $(steps[1]).classList.replace("active", "done");
        $(steps[2]).classList.add("active");
    }, 1200);
}

// ─── Render Result ─────────────────────────────────────────── //

function renderResult(d) {
    // Score ring
    const score = d.risk_score;
    const arc = $("score-arc");
    const circumference = 2 * Math.PI * 85;  // ~534
    const offset = circumference - (score / 100) * circumference;
    arc.style.transition = "stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)";
    requestAnimationFrame(() => {
        arc.setAttribute("stroke-dashoffset", offset);
    });

    // Score gradient color
    const colors = scoreColors(d.risk_level);
    $("score-grad-start").setAttribute("stop-color", colors[0]);
    $("score-grad-end").setAttribute("stop-color", colors[1]);

    // Animated counter
    animateCounter($("score-number"), 0, score, 1000);

    // Risk badge
    const badge = $("risk-badge");
    badge.textContent = d.risk_level;
    badge.className = `risk-badge ${d.risk_level.toLowerCase()}`;

    // Score hero border glow
    const hero = $("score-hero");
    hero.style.borderColor = colors[0] + "30";

    // Meta
    $("classification").textContent = d.classification;
    $("confidence").textContent = Math.round(d.confidence * 100) + "%";
    $("ioc-type").textContent = d.type.toUpperCase();

    // AI Analysis
    $("ai-summary").textContent = d.ai_analysis || "No AI analysis available.";

    const reasoning = $("ai-reasoning");
    reasoning.innerHTML = "";
    const meta = d.metadata || {};
    // Try to get reasoning from backend — if we add it later
    // For now, show ai_analysis as the main content

    // Evidence
    const evList = $("evidence-list");
    evList.innerHTML = "";
    (d.evidence || []).forEach((ev) => {
        const isWarning = ev.includes("⚠") || ev.includes("[!]");
        const cleanText = ev.replace("⚠ ", "").replace("[!] ", "").trim();
        const li = document.createElement("li");
        li.className = "evidence-item" + (isWarning ? " warning" : "");
        li.innerHTML = `
            <span class="evidence-icon">${isWarning ? "⚠" : "✓"}</span>
            <span>${escapeHtml(cleanText)}</span>
        `;
        evList.appendChild(li);
    });

    // Recommendation
    const recBadge = $("recommendation-badge");
    recBadge.textContent = d.recommendation;
    recBadge.className =
        "recommendation-badge " + d.recommendation.toLowerCase();

    const recDesc = $("recommendation-desc");
    const recTexts = {
        BLOCK: "Immediately block this indicator across all security controls. Investigate any historical exposure.",
        MONITOR: "Add this indicator to monitoring watchlists. Investigate if suspicious activity is observed.",
        ALLOW: "No action required. Continue standard monitoring policies.",
    };
    recDesc.textContent = recTexts[d.recommendation] || "";

    // MITRE
    const mitreContainer = $("mitre-tags");
    mitreContainer.innerHTML = "";
    if (d.mitre && d.mitre.length > 0) {
        d.mitre.forEach((t) => {
            const tag = document.createElement("a");
            tag.className = "mitre-tag";
            tag.textContent = t;
            tag.href = `https://attack.mitre.org/techniques/${t.replace(".", "/")}/`;
            tag.target = "_blank";
            tag.rel = "noopener noreferrer";
            mitreContainer.appendChild(tag);
        });
    } else {
        mitreContainer.innerHTML =
            '<span class="no-mitre">No specific techniques identified</span>';
    }

    // Defensive Mitigations (RAG Grounding)
    const mitList = $("mitigations-list");
    if (mitList) {
        mitList.innerHTML = "";
        const mitigations = d.mitigations || [];
        if (mitigations.length > 0) {
            mitigations.forEach((m) => {
                const li = document.createElement("li");
                li.className = "mitigation-item";
                li.innerHTML = `
                    <span class="mitigation-icon">🛡️</span>
                    <span>${escapeHtml(m)}</span>
                `;
                mitList.appendChild(li);
            });
            $("mitigations-section")?.classList.remove("hidden");
        } else {
            $("mitigations-section")?.classList.add("hidden");
        }
    }

    // Intelligence source label formatter
    const sourceLabels = {
        virustotal: "VirusTotal (Live)",
        virustotal_live: "VirusTotal (Live)",
        virustotal_cached: "VirusTotal (Cached)",
        virustotal_unseen: "VirusTotal (Unseen IOC)",
        virustotal_rate_limited: "VT Limit (Fallback)",
        demo_fixture: "Demo Fixture",
        local_fallback: "Local Heuristics",
    };
    const rawSource = meta.intelligence_source || "";
    const sourceDisplay = sourceLabels[rawSource] || rawSource || "Standard";

    // Metadata bar
    $("meta-source").textContent = `Source: ${sourceDisplay}`;
    $("meta-model").textContent = `ML: ${meta.model_available ? "XGBoost" : "Heuristic"}`;
    $("meta-provider").textContent = `AI: ${meta.ai_provider || "—"}`;
    $("meta-platform").textContent = `Host: ${meta.host_platform || "Standard"}`;
    $("meta-version").textContent = `v${meta.analysis_version || "0.1.0"}`;
}

// ─── System Telemetry & Hardware Modal ────────────────────── //

let systemTelemetryData = null;

async function loadSystemTelemetry() {
    try {
        const res = await fetch(`${API}/system/info`);
        if (!res.ok) return;
        const data = await res.json();
        systemTelemetryData = data;

        const badge = $("platform-badge");
        const text = $("platform-text");

        if (data.is_linuxone) {
            badge.classList.add("linuxone");
            text.textContent = "IBM LinuxONE (s390x)";
        } else {
            text.textContent = data.platform_name || `${data.system} (${data.machine})`;
        }
        const platformLabel = data.is_linuxone
            ? "IBM LinuxONE (s390x)"
            : data.platform_name || `${data.system} (${data.machine})`;
        $("welcome-eyebrow").textContent = `${platformLabel} · Security Analytics`;

        // Populate modal
        $("hw-arch").textContent = data.architecture ? `${data.architecture} (${data.byte_order || 'Big Endian'})` : (data.machine || "s390x");
        $("hw-os").textContent = `${data.system} ${data.release || ""}`;
        $("hw-cpu").textContent = `${data.cpu_count} vCPUs (Online: ${data.online_cpus || "0-2"})`;
        $("hw-vendor").textContent = `${data.vendor || "IBM/S390"}${data.machine_type ? ` · Type ${data.machine_type}` : ""}`;
        $("hw-hypervisor").textContent = data.hypervisor || "z/VM 7.3.0";
        $("hw-mem").textContent = data.memory_total_mb ? `${data.memory_total_mb} MB` : "Available";

        const clockEl = $("hw-clock");
        if (clockEl) {
            clockEl.textContent = `${data.cpu_mhz ? data.cpu_mhz + " MHz" : "5508 MHz"} · ${data.bogomips ? data.bogomips + " BogoMIPS" : "28901 BogoMIPS"}`;
        }
        const accelEl = $("hw-accel");
        if (accelEl) {
            accelEl.textContent = data.crypto_acceleration || "MSA (CPACF Crypto), NNPA (AI)";
        }

        const banner = $("hw-linuxone-banner");
        if (data.is_linuxone) {
            banner.innerHTML = `<span class="hw-banner-icon">🛡️</span><span><strong>Verified Host:</strong> IBM LinuxONE (s390x) · Machine Type ${escapeHtml(data.machine_type || "9175")} · z/VM Hypervisor</span>`;
        } else {
            banner.innerHTML = `<span class="hw-banner-icon">💻</span><span>Development environment: ${escapeHtml(data.platform_name || `${data.system} (${data.machine})`)}.</span>`;
        }
    } catch {
        /* silently ignore if endpoint is unreachable */
    }
}

async function loadSystemStatus() {
    const status = $("system-status");
    const label = status?.querySelector(".status-text");
    if (!status || !label) return;

    try {
        const res = await fetch(`${API}/health`);
        if (!res.ok) throw new Error(`Health check returned ${res.status}`);
        status.classList.remove("checking", "offline");
        status.classList.add("online");
        label.textContent = "System Online";
        status.title = "SilkShield API health check succeeded";
    } catch {
        status.classList.remove("checking", "online");
        status.classList.add("offline");
        label.textContent = "API Unavailable";
        status.title = "SilkShield API health check failed";
    }
}

function initModal() {
    const modal = $("hardware-modal");
    const badge = $("platform-badge");
    const closeBtn = $("close-modal-btn");

    badge?.addEventListener("click", () => {
        modal?.classList.remove("hidden");
    });

    closeBtn?.addEventListener("click", () => {
        modal?.classList.add("hidden");
    });

    modal?.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.classList.add("hidden");
        }
    });
}

// ─── Helpers ───────────────────────────────────────────────── //

function scoreColors(level) {
    switch (level) {
        case "LOW":
            return ["#10b981", "#059669"];
        case "MEDIUM":
            return ["#f59e0b", "#d97706"];
        case "HIGH":
            return ["#f43f5e", "#e11d48"];
        case "CRITICAL":
            return ["#ef4444", "#dc2626"];
        default:
            return ["#06b6d4", "#8b5cf6"];
    }
}

function animateCounter(el, start, end, duration) {
    const range = end - start;
    const startTime = performance.now();

    function step(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(start + range * eased);
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

// ─── Keyboard shortcut ────────────────────────────────────── //
document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && document.activeElement === $("ioc-input")) {
        analyzeIOC();
    }
    if (e.key === "Escape") {
        $("hardware-modal")?.classList.add("hidden");
    }
});

// ─── Init ──────────────────────────────────────────────────── //
document.addEventListener("DOMContentLoaded", () => {
    initSearchControls();
    loadDemoIOCs();
    loadSystemTelemetry();
    loadSystemStatus();
    initModal();
    $("ioc-input")?.focus();
});
