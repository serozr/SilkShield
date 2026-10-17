/* ═══════════════════════════════════════════════════════════════
   SilkShield — Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

const API = window.location.origin;

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
                $("ioc-input").value = item.ioc;
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

async function analyzeIOC() {
    const input = $("ioc-input");
    const ioc = input.value.trim();
    if (!ioc) {
        input.focus();
        return;
    }

    lastIOC = ioc;
    const btn = $("analyze-btn");
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
    } catch (err) {
        $("error-message").textContent = err.message;
        showState("error-state");
    } finally {
        btn.classList.remove("loading");
        btn.disabled = false;
    }
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
        const li = document.createElement("li");
        li.className = "evidence-item" + (ev.includes("⚠") ? " warning" : "");
        li.innerHTML = `
            <span class="evidence-icon">${ev.includes("⚠") ? "⚠" : "✓"}</span>
            <span>${escapeHtml(ev.replace("⚠ ", ""))}</span>
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

    // Metadata bar
    $("meta-source").textContent = `Source: ${meta.intelligence_source || "—"}`;
    $("meta-model").textContent = `ML: ${meta.model_available ? "XGBoost" : "Heuristic"}`;
    $("meta-provider").textContent = `AI: ${meta.ai_provider || "—"}`;
    $("meta-version").textContent = `v${meta.analysis_version || "0.1.0"}`;
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
});

// ─── Init ──────────────────────────────────────────────────── //
document.addEventListener("DOMContentLoaded", () => {
    loadDemoIOCs();
    $("ioc-input")?.focus();
});
