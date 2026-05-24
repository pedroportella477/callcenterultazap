const state = {
  user: null,
  customers: [],
  queues: [],
  operators: [],
  selectedCustomer: null,
  sla: null,
  intelligence: null,
  tmaTme: null,
  tmaTmeTargets: null,
  quickReplies: [],
  teamMessages: [],
  campaigns: [],
  realtimeSource: null,
  realtimeRefreshTimer: null,
  realtimeRefreshInFlight: false,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    credentials: "same-origin",
    ...options,
  });
  if (response.status === 204) return null;
  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }
  if (!response.ok) {
    if (response.status === 429) {
      const retryAfter = response.headers.get("Retry-After");
      const suffix = retryAfter ? ` Tente novamente em ${retryAfter}s.` : "";
      throw new Error((payload && payload.error) || `Muitas requisicoes.${suffix}`);
    }
    throw new Error((payload && payload.error) || "Erro inesperado");
  }
  return payload;
}

function toast(message) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.remove("hidden");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => el.classList.add("hidden"), 3600);
}

function formatDate(ts) {
  if (!ts) return "";
  return new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short" }).format(new Date(ts * 1000));
}

function formatPercent(value) {
  const numeric = Number(value || 0);
  return `${numeric.toFixed(2).replace(/\.00$/, "")}%`;
}

function statusLabel(status) {
  return { open: "Aberto", pending: "Pendente", closed: "Fechado" }[status] || status;
}

function channelLabel(channel) {
  return (
    {
      whatsapp: "WhatsApp",
      telegram: "Telegram",
      instagram: "Instagram",
      facebook_messenger: "Facebook Messenger",
      email: "E-mail",
      webchat: "Chat do site",
    }[channel] || channel || "Canal"
  );
}

async function bootstrap() {
  const me = await api("/api/me");
  if (!me.user) {
    showLogin();
    return;
  }
  state.user = me.user;
  showApp();
  const ready = await ensurePasswordChanged();
  if (!ready) {
    await api("/api/logout", { method: "POST" });
    state.user = null;
    showLogin();
    return;
  }
  await Promise.all([
    loadQueues(),
    loadOperators(),
    loadQuickReplies(),
    loadDashboard(),
    loadSLA(),
    loadTmaTme(),
    loadTmaTmeTargets(),
    loadIntelligence(),
    loadCustomers(),
    loadEvolutionStatus(),
  ]);
  renderCampaignCustomerOptions();
  await Promise.all([loadTeamMessages(), loadCampaigns()]);
  startRealtime();
}

function showLogin() {
  stopRealtime();
  $("#login-screen").classList.remove("hidden");
  $("#app-screen").classList.add("hidden");
}

function showApp() {
  $("#login-screen").classList.add("hidden");
  $("#app-screen").classList.remove("hidden");
  $("#user-name").textContent = state.user.name;
  $("#user-role").textContent = state.user.role === "admin" ? "Administrador" : "Operador";
  $("#scope-label").textContent = state.user.role === "admin" ? "Todas as filas" : "Minha fila";
  $$(".admin-only").forEach((el) => el.classList.toggle("hidden", state.user.role !== "admin"));
}

function parsePermissions(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      return [];
    }
  }
  return [];
}

async function ensurePasswordChanged() {
  if (!state.user?.must_change_password) return true;
  toast("Troca de senha obrigatoria para continuar.");
  const oldPassword = window.prompt("Informe a senha atual:");
  if (!oldPassword) return false;
  const newPassword = window.prompt("Defina uma nova senha (minimo 8 caracteres):");
  if (!newPassword) return false;
  try {
    await api("/api/change-password", {
      method: "POST",
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
    state.user.must_change_password = 0;
    toast("Senha alterada com sucesso.");
    return true;
  } catch (error) {
    toast(error.message);
    return false;
  }
}

async function loadDashboard() {
  const { dashboard } = await api("/api/dashboard");
  $("#metric-total").textContent = dashboard.total || 0;
  $("#metric-open").textContent = dashboard.open_total || 0;
  $("#metric-pending").textContent = dashboard.pending_total || 0;
  $("#metric-closed").textContent = dashboard.closed_total || 0;
}

function renderSLATable(byQueue) {
  const body = $("#sla-table");
  if (!byQueue || !byQueue.length) {
    body.innerHTML = `<tr><td colspan="6" class="muted">Sem dados de SLA para o filtro atual.</td></tr>`;
    return;
  }
  body.innerHTML = byQueue
    .map(
      (row) => `
      <tr>
        <td>${escapeHtml(row.queue_name)}</td>
        <td>${row.total || 0}</td>
        <td>${row.waiting_first_response || 0}</td>
        <td>${row.breached_first_response || 0}</td>
        <td>${row.avg_first_response_seconds || 0}</td>
        <td>${row.avg_resolution_seconds || 0}</td>
      </tr>`
    )
    .join("");
}

async function loadSLA() {
  const payload = await api("/api/sla");
  state.sla = payload;
  $("#metric-sla-waiting").textContent = payload.sla.waiting_first_response || 0;
  $("#metric-sla-breached").textContent = payload.sla.breached_first_response || 0;
  renderSLATable(payload.by_queue || []);
}

function renderQuickReplyCatalog() {
  const select = $("#quick-reply-select");
  const sendButton = $("#quick-reply-send-button");
  if (!select) return;
  const options = state.quickReplies || [];
  if (!options.length) {
    select.innerHTML = `<option value="">Sem frases rapidas</option>`;
    if (sendButton) sendButton.disabled = true;
    return;
  }
  select.innerHTML = [
    `<option value="">Selecione frase rapida</option>`,
    ...options.map((item) => `<option value="${escapeHtml(item.shortcut)}">${escapeHtml(item.shortcut)}</option>`),
  ].join("");
  if (sendButton) {
    const blocked = !state.selectedCustomer || !!state.selectedCustomer.finalized;
    sendButton.disabled = blocked;
  }
}

function renderQuickReplyTable() {
  const body = $("#quick-replies-table");
  if (!body) return;
  const options = state.quickReplies || [];
  if (!options.length) {
    body.innerHTML = `<tr><td colspan="3" class="muted">Nenhuma frase cadastrada.</td></tr>`;
    return;
  }
  body.innerHTML = options
    .map(
      (item) => `
      <tr>
        <td>${escapeHtml(item.shortcut)}</td>
        <td>${escapeHtml(item.body)}</td>
        <td>${formatDate(item.updated_at)}</td>
      </tr>`
    )
    .join("");
}

async function loadQuickReplies() {
  const { quick_replies } = await api("/api/quick-replies");
  state.quickReplies = quick_replies || [];
  renderQuickReplyCatalog();
  renderQuickReplyTable();
}

function renderPrivateNotes(notes) {
  const box = $("#private-notes-list");
  if (!box) return;
  if (!notes || !notes.length) {
    box.innerHTML = `<div class="muted">Sem notas privadas.</div>`;
    return;
  }
  box.innerHTML = notes
    .map(
      (note) => `
      <article class="private-note-item">
        <small>${escapeHtml(note.user_name || "Usuario")} - ${formatDate(note.created_at)}</small>
        <div>${escapeHtml(note.body)}</div>
      </article>`
    )
    .join("");
}

async function loadPrivateNotes(customerId) {
  const payload = await api(`/api/customers/${customerId}/notes`);
  renderPrivateNotes(payload.notes || []);
}

function renderScheduledMessages(items) {
  const body = $("#scheduled-messages-table");
  if (!body) return;
  if (!items || !items.length) {
    body.innerHTML = `<tr><td colspan="3" class="muted">Sem mensagens agendadas.</td></tr>`;
    return;
  }
  body.innerHTML = items
    .map((item) => {
      const canCancel = item.status === "pending";
      return `
      <tr>
        <td>${formatDate(item.send_at)}</td>
        <td>${escapeHtml(item.status)}</td>
        <td>${canCancel ? `<button type="button" class="cancel-scheduled-button" data-id="${item.id}">Cancelar</button>` : "-"}</td>
      </tr>`;
    })
    .join("");
  $$(".cancel-scheduled-button").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        await api(`/api/scheduled-messages/${button.dataset.id}/cancel`, { method: "POST", body: "{}" });
        if (state.selectedCustomer) {
          await loadScheduledMessages(state.selectedCustomer.id);
        }
        toast("Agendamento cancelado");
      } catch (error) {
        toast(error.message);
      }
    });
  });
}

async function loadScheduledMessages(customerId) {
  const payload = await api(`/api/customers/${customerId}/scheduled-messages`);
  renderScheduledMessages(payload.scheduled_messages || []);
}

function renderMediaTable(items) {
  const body = $("#media-table");
  if (!body) return;
  if (!items || !items.length) {
    body.innerHTML = `<tr><td colspan="3" class="muted">Sem midias para esta conversa.</td></tr>`;
    return;
  }
  body.innerHTML = items
    .map(
      (item) => `
      <tr>
        <td>${escapeHtml(item.media_type)}</td>
        <td><a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">abrir</a></td>
        <td>${formatDate(item.created_at)}</td>
      </tr>`
    )
    .join("");
}

async function loadMedia(customerId) {
  const payload = await api(`/api/customers/${customerId}/media`);
  renderMediaTable(payload.media || []);
}

function renderTeamMessages() {
  const box = $("#team-messages-list");
  if (!box) return;
  const items = state.teamMessages || [];
  if (!items.length) {
    box.innerHTML = `<div class="muted">Sem mensagens internas.</div>`;
    return;
  }
  box.innerHTML = items
    .map(
      (item) => `
      <article class="private-note-item">
        <small>${escapeHtml(item.user_name || "Usuario")} - ${formatDate(item.created_at)}</small>
        <div>${escapeHtml(item.body)}</div>
      </article>`
    )
    .join("");
}

async function loadTeamMessages() {
  const payload = await api("/api/team-messages?limit=100");
  state.teamMessages = payload.messages || [];
  renderTeamMessages();
}

function renderCampaignCustomerOptions() {
  const select = $("#campaign-customers");
  if (!select) return;
  const customers = state.customers || [];
  if (!customers.length) {
    select.innerHTML = "";
    return;
  }
  select.innerHTML = customers
    .map(
      (customer) =>
        `<option value="${customer.id}">${escapeHtml(customer.name)} (${escapeHtml(channelLabel(customer.channel))}: ${escapeHtml(customer.contact || customer.phone)})</option>`
    )
    .join("");
}

function renderCampaignsTable() {
  const body = $("#campaigns-table");
  if (!body) return;
  const campaigns = state.campaigns || [];
  if (!campaigns.length) {
    body.innerHTML = `<tr><td colspan="8" class="muted">Sem campanhas registradas.</td></tr>`;
    return;
  }
  body.innerHTML = campaigns
    .map(
      (item) => `
      <tr>
        <td>${escapeHtml(item.name)}</td>
        <td>${escapeHtml(item.status)}</td>
        <td>${item.total_targets || 0}</td>
        <td>${item.queued_total || 0}</td>
        <td>${item.sent_total || 0}</td>
        <td>${item.failed_total || 0}</td>
        <td>${item.scheduled_at ? formatDate(item.scheduled_at) : "imediata"}</td>
        <td><a href="/api/campaigns/${item.id}/export" target="_blank" rel="noopener noreferrer">CSV</a></td>
      </tr>`
    )
    .join("");
}

async function loadCampaigns() {
  if (state.user?.role !== "admin") {
    state.campaigns = [];
    renderCampaignsTable();
    return;
  }
  const payload = await api("/api/campaigns?limit=50");
  state.campaigns = payload.campaigns || [];
  renderCampaignsTable();
}

function renderTmaTmeTargets(targetsPayload) {
  if (!targetsPayload) return;
  const globalTarget = targetsPayload.global || {};
  const queues = targetsPayload.queues || [];
  const globalTmeInput = $("#target-global-tme");
  const globalTmaInput = $("#target-global-tma");
  const queueBody = $("#tma-tme-targets-queues");

  if (!queueBody || !globalTmeInput || !globalTmaInput) return;

  globalTmeInput.value = globalTarget.tme_target_seconds || 300;
  globalTmaInput.value = globalTarget.tma_target_seconds || 1200;

  queueBody.innerHTML = queues
    .map((item) => {
      const useGlobal = !item.has_custom_target;
      return `
        <tr data-queue-id="${item.queue_id}">
          <td>${escapeHtml(item.queue_name)}</td>
          <td class="target-cell">
            <input class="target-tme-input" type="number" min="30" max="86400" value="${item.tme_target_seconds || 300}" ${useGlobal ? "disabled" : ""}>
          </td>
          <td class="target-cell">
            <input class="target-tma-input" type="number" min="60" max="172800" value="${item.tma_target_seconds || 1200}" ${useGlobal ? "disabled" : ""}>
          </td>
          <td class="target-cell">
            <input class="target-inherit-input" type="checkbox" ${useGlobal ? "checked" : ""}>
          </td>
        </tr>
      `;
    })
    .join("");

  $$(".target-inherit-input").forEach((checkbox) => {
    checkbox.addEventListener("change", (event) => {
      const row = event.currentTarget.closest("tr");
      if (!row) return;
      const disabled = event.currentTarget.checked;
      const tmeInput = row.querySelector(".target-tme-input");
      const tmaInput = row.querySelector(".target-tma-input");
      if (tmeInput) tmeInput.disabled = disabled;
      if (tmaInput) tmaInput.disabled = disabled;
    });
  });
}

function renderTmaTme(payload) {
  const summary = payload.summary || {};
  $("#metric-tme-average").textContent = `${summary.avg_tme_seconds || 0}s`;
  $("#metric-tma-average").textContent = `${summary.avg_tma_seconds || 0}s`;
  $("#metric-tme-compliance").textContent = formatPercent(summary.tme_compliance_percent);
  $("#metric-tma-compliance").textContent = formatPercent(summary.tma_compliance_percent);

  const queueRows = payload.by_queue || [];
  const queueBody = $("#tma-tme-queues");
  if (queueBody) {
    queueBody.innerHTML = queueRows.length
      ? queueRows
          .map(
            (row) => `
          <tr>
            <td>${escapeHtml(row.queue_name)}</td>
            <td>${row.total || 0}</td>
            <td>${row.avg_tme_seconds || 0}</td>
            <td>${row.tme_target_seconds || 0}</td>
            <td>${formatPercent(row.tme_compliance_percent)}</td>
            <td>${row.avg_tma_seconds || 0}</td>
            <td>${row.tma_target_seconds || 0}</td>
            <td>${formatPercent(row.tma_compliance_percent)}</td>
          </tr>`
          )
          .join("")
      : `<tr><td colspan="8" class="muted">Sem dados de TMA/TME para o filtro atual.</td></tr>`;
  }

  const operatorRows = payload.by_operator || [];
  const operatorBody = $("#tma-tme-operators");
  if (operatorBody) {
    operatorBody.innerHTML = operatorRows.length
      ? operatorRows
          .map(
            (row) => `
          <tr>
            <td>${escapeHtml(row.operator_name)}</td>
            <td>${row.total || 0}</td>
            <td>${row.answered_tickets || 0}</td>
            <td>${row.handled_tickets || 0}</td>
            <td>${row.avg_tme_seconds || 0}</td>
            <td>${row.avg_tma_seconds || 0}</td>
          </tr>`
          )
          .join("")
      : `<tr><td colspan="6" class="muted">Sem dados por operador para o filtro atual.</td></tr>`;
  }
}

async function loadTmaTme() {
  const windowSelect = $("#tma-tme-window");
  const days = Number(windowSelect?.value || 30);
  const payload = await api(`/api/tma-tme?days=${days}`);
  state.tmaTme = payload;
  renderTmaTme(payload);
}

async function loadTmaTmeTargets() {
  const payload = await api("/api/tma-tme/targets");
  state.tmaTmeTargets = payload.targets;
  renderTmaTmeTargets(payload.targets);
}

function renderIntelligence(payload) {
  $("#intel-score").textContent = payload.score || 0;
  $("#intel-active").textContent = payload.active_tickets || 0;
  $("#intel-unassigned").textContent = payload.unassigned_active || 0;
  $("#intel-overdue").textContent = payload.overdue_first_response || 0;
  $("#intel-age").textContent = `${payload.avg_active_age_seconds || 0}s`;

  const alerts = payload.alerts || [];
  $("#intel-alerts").innerHTML = alerts
    .map(
      (alert) => `
      <li>
        <span class="alert-${escapeHtml(alert.level || "info")}">${escapeHtml(alert.title || "Alerta")}</span>:
        ${escapeHtml(alert.detail || "")}
      </li>`
    )
    .join("");

  const recommendations = payload.recommendations || [];
  $("#intel-recommendations").innerHTML = recommendations
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");

  const operators = payload.operators || [];
  $("#intel-operators").innerHTML = operators.length
    ? operators
        .map(
          (row) => `
          <tr>
            <td>${escapeHtml(row.operator_name)}</td>
            <td>${row.active_tickets || 0}</td>
            <td>${row.closed_tickets || 0}</td>
            <td>${row.avg_first_response_seconds || 0}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="4" class="muted">Sem dados para o escopo atual.</td></tr>`;

  const queues = payload.queue_health || [];
  $("#intel-queues").innerHTML = queues.length
    ? queues
        .map(
          (row) => `
          <tr>
            <td>${escapeHtml(row.queue_name)}</td>
            <td>${row.active_tickets || 0}</td>
            <td>${row.waiting_first_response || 0}</td>
            <td>${row.overdue_first_response || 0}</td>
            <td>${row.pressure_score || 0}</td>
          </tr>`
        )
        .join("")
    : `<tr><td colspan="5" class="muted">Sem dados para o escopo atual.</td></tr>`;
}

async function loadIntelligence() {
  const payload = await api("/api/dashboard/intelligence");
  state.intelligence = payload;
  renderIntelligence(payload);
}

async function loadQueues() {
  const { queues } = await api("/api/queues");
  state.queues = queues;
  const select = $("#customer-form select[name='queue_id']");
  select.innerHTML = queues.map((q) => `<option value="${q.id}">${q.name}</option>`).join("");
}

async function loadOperators() {
  const { operators } = await api("/api/operators");
  state.operators = operators;
  const options = operators.map((o) => `<option value="${o.id}">${o.name}</option>`).join("");
  $("#assign-select").innerHTML = options;
  $("#customer-form select[name='assigned_operator_id']").innerHTML = options;
}

async function loadCustomers() {
  const params = new URLSearchParams();
  const q = $("#search-input").value.trim();
  const status = $("#status-filter").value;
  const channel = $("#channel-filter")?.value || "";
  if (q) params.set("q", q);
  if (status) params.set("status", status);
  if (channel) params.set("channel", channel);
  const { customers } = await api(`/api/customers?${params.toString()}`);
  state.customers = customers;
  renderCampaignCustomerOptions();
  renderCustomerList();
  renderCustomerTable();
  if (state.selectedCustomer) {
    const next = customers.find((c) => c.id === state.selectedCustomer.id);
    if (next) await selectCustomer(next.id);
  }
}

function stopRealtime() {
  if (state.realtimeRefreshTimer) {
    window.clearTimeout(state.realtimeRefreshTimer);
    state.realtimeRefreshTimer = null;
  }
  if (state.realtimeSource) {
    state.realtimeSource.close();
    state.realtimeSource = null;
  }
}

function scheduleRealtimeRefresh() {
  if (state.realtimeRefreshTimer) return;
  state.realtimeRefreshTimer = window.setTimeout(async () => {
    state.realtimeRefreshTimer = null;
    if (state.realtimeRefreshInFlight) return;
    state.realtimeRefreshInFlight = true;
    try {
      await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
      if (state.selectedCustomer) {
        await selectCustomer(state.selectedCustomer.id);
      }
    } catch (error) {
      // keep background refresh silent unless we lose auth
      if (String(error.message || "").toLowerCase().includes("não autenticado")) {
        stopRealtime();
      }
    } finally {
      state.realtimeRefreshInFlight = false;
    }
  }, 250);
}

function startRealtime() {
  stopRealtime();
  if (!state.user) return;
  try {
    const source = new EventSource("/api/events");
    source.addEventListener("ticket.updated", () => scheduleRealtimeRefresh());
    source.addEventListener("ready", () => {});
    source.onerror = () => {
      // EventSource reconnects automatically; keep interface calm.
    };
    state.realtimeSource = source;
  } catch (error) {
    // Browser without SSE support: continue sem tempo real.
  }
}

function renderCustomerList() {
  const list = $("#customer-list");
  if (!state.customers.length) {
    list.innerHTML = `<div class="empty-state">Nenhum cliente nesta visao.</div>`;
    return;
  }
  list.innerHTML = state.customers
    .map(
      (customer) => `
      <article class="customer-item ${state.selectedCustomer?.id === customer.id ? "active" : ""}"
        style="border-left-color:${customer.queue_color}" data-id="${customer.id}">
        <div class="customer-line">
          <strong>${escapeHtml(customer.name)}</strong>
          <span class="status-pill">${statusLabel(customer.status)}${customer.finalized ? " (finalizado)" : ""}</span>
        </div>
        <small class="muted">${escapeHtml(channelLabel(customer.channel))} - ${escapeHtml(customer.contact || customer.phone)} - ${escapeHtml(customer.queue_name)}</small>
        <small class="muted">${escapeHtml(customer.operator_name || "Sem operador")} - ${formatDate(customer.last_message_at)}</small>
      </article>`
    )
    .join("");
  $$(".customer-item").forEach((item) => item.addEventListener("click", () => selectCustomer(Number(item.dataset.id))));
}

function renderCustomerTable() {
  $("#customers-table").innerHTML = state.customers
    .map(
      (c) => `
      <tr>
        <td><strong>${escapeHtml(c.name)}</strong></td>
        <td>${escapeHtml(c.contact || c.phone)}</td>
        <td>${escapeHtml(channelLabel(c.channel))}</td>
        <td>${escapeHtml(c.queue_name)}</td>
        <td>${escapeHtml(c.operator_name || "Sem operador")}</td>
        <td>${statusLabel(c.status)}${c.finalized ? " / finalizado" : ""}</td>
      </tr>`
    )
    .join("");
}

async function selectCustomer(id) {
  const customer = state.customers.find((c) => c.id === id);
  if (!customer) return;
  state.selectedCustomer = customer;
  renderCustomerList();
  $("#chat-empty").classList.add("hidden");
  $("#chat-content").classList.remove("hidden");
  $("#chat-name").textContent = customer.name;
  $("#chat-meta").textContent = `${channelLabel(customer.channel)} - ${customer.contact || customer.phone} - ${customer.queue_name} - ${customer.operator_name || "Sem operador"}`;
  $("#customer-status").value = customer.status;
  $("#message-form button[type='submit']").disabled = !!customer.finalized;
  $("#message-form textarea[name='body']").disabled = !!customer.finalized;
  $("#finalize-button").disabled = !!customer.finalized;
  $("#transfer-button").disabled = !!customer.finalized;
  $("#quick-reply-send-button").disabled = !!customer.finalized || !(state.quickReplies || []).length;
  $("#private-note-form button[type='submit']").disabled = !!customer.finalized;
  $("#private-note-form textarea[name='body']").disabled = !!customer.finalized;
  $("#schedule-message-form button[type='submit']").disabled = !!customer.finalized;
  $("#schedule-message-form textarea[name='body']").disabled = !!customer.finalized;
  $("#schedule-message-form input[name='send_at']").disabled = !!customer.finalized;
  $("#media-form button[type='submit']").disabled = !!customer.finalized;
  $("#media-form input[name='url']").disabled = !!customer.finalized;
  $("#media-form input[name='file']").disabled = !!customer.finalized;
  $("#media-form input[name='caption']").disabled = !!customer.finalized;
  $("#media-form select[name='media_type']").disabled = !!customer.finalized;
  const perms = parsePermissions(state.user?.permissions);
  const canAiSuggest = state.user?.role === "admin" || perms.includes("ai:suggest");
  $("#ai-suggest-button").disabled = !!customer.finalized || !canAiSuggest;
  $("#ai-suggest-output").value = "";
  const optOutCheckbox = $("#campaign-opt-out-checkbox");
  if (optOutCheckbox) {
    optOutCheckbox.checked = !!customer.campaign_opt_out;
    optOutCheckbox.disabled = state.user?.role !== "admin";
  }
  const scheduleInput = $("#schedule-message-form input[name='send_at']");
  if (scheduleInput && !scheduleInput.value) {
    const future = new Date(Date.now() + 15 * 60 * 1000);
    scheduleInput.value = new Date(future.getTime() - future.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  }
  if (customer.assigned_operator_id) {
    $("#assign-select").value = customer.assigned_operator_id;
  }
  const { messages } = await api(`/api/customers/${id}/messages`);
  renderMessages(messages);
  await Promise.all([
    loadERP(customer.id),
    loadPrivateNotes(customer.id),
    loadScheduledMessages(customer.id),
    loadMedia(customer.id),
  ]);
}

function renderMessages(messages) {
  const list = $("#message-list");
  list.innerHTML = messages
    .map(
      (m) => `
      <div class="message ${m.direction}">
        ${escapeHtml(m.body)}
        <small>${formatDate(m.created_at)} ${m.status && m.status !== "sent" ? `- ${escapeHtml(m.status)}` : ""}</small>
      </div>`
    )
    .join("");
  list.scrollTop = list.scrollHeight;
}

async function loadEvolutionStatus() {
  const { configured, baseUrl, instance } = await api("/api/evolution/status");
  $("#evolution-base").textContent = baseUrl || "Nao configurada";
  $("#evolution-instance").textContent = instance;
  $("#evolution-configured").textContent = configured ? "Configurada" : "Pendente";
}

async function loadERP(customerId) {
  const payload = await api(`/api/customers/${customerId}/erp`);
  $("#erp-summary").textContent = payload.erp_active
    ? `ERP ativo (${payload.provider || "sem nome"}). Pendencia financeira: ${payload.financial_pending ? "sim" : "nao"}.`
    : "Integracao ERP inativa para este cliente.";
  $("#erp-connection").textContent = JSON.stringify(payload.connection_data || {}, null, 2);
  $("#send-boleto-button").disabled = !payload.financial_pending;
  const perms = parsePermissions(state.user.permissions);
  $("#unlock-billing-button").disabled = !perms.includes("billing:unlock");
  if (state.selectedCustomer?.finalized) {
    $("#send-boleto-button").disabled = true;
    $("#unlock-billing-button").disabled = true;
  }
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.onerror = () => reject(new Error("Falha ao ler o arquivo."));
    reader.readAsDataURL(file);
  });
}

function switchView(viewName) {
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === viewName));
  $$(".view").forEach((view) => view.classList.add("hidden"));
  $(`#view-${viewName}`).classList.remove("hidden");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]
  ));
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const { user } = await api("/api/login", {
      method: "POST",
      body: JSON.stringify(Object.fromEntries(form)),
    });
    state.user = user;
    showApp();
    const ready = await ensurePasswordChanged();
    if (!ready) {
      await api("/api/logout", { method: "POST" });
      state.user = null;
      showLogin();
      return;
    }
    await Promise.all([
      loadQueues(),
      loadOperators(),
      loadQuickReplies(),
      loadDashboard(),
      loadSLA(),
      loadTmaTme(),
      loadTmaTmeTargets(),
      loadIntelligence(),
      loadCustomers(),
      loadEvolutionStatus(),
    ]);
    renderCampaignCustomerOptions();
    await Promise.all([loadTeamMessages(), loadCampaigns()]);
    startRealtime();
  } catch (error) {
    toast(error.message);
  }
});

$("#logout-button").addEventListener("click", async () => {
  stopRealtime();
  await api("/api/logout", { method: "POST" });
  state.user = null;
  showLogin();
});

$$(".nav-item").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
$("#search-input").addEventListener("input", () => {
  window.clearTimeout(loadCustomers.timer);
  loadCustomers.timer = window.setTimeout(loadCustomers, 250);
});
$("#status-filter").addEventListener("change", loadCustomers);
$("#channel-filter").addEventListener("change", loadCustomers);
$("#tma-tme-window").addEventListener("change", () => {
  loadTmaTme().catch((error) => toast(error.message));
});

$("#new-customer-button").addEventListener("click", () => $("#customer-dialog").showModal());
$("#cancel-customer-button").addEventListener("click", () => $("#customer-dialog").close());

const customerChannelSelect = $("#customer-form select[name='channel']");
const customerContactInput = $("#customer-form input[name='contact']");
if (customerChannelSelect && customerContactInput) {
  const placeholders = {
    whatsapp: "5511999999999",
    telegram: "@usuario_telegram",
    instagram: "@perfil_instagram",
    facebook_messenger: "id_ou_usuario",
    email: "cliente@dominio.com",
    webchat: "sessao-chat-12345",
  };
  customerChannelSelect.addEventListener("change", () => {
    customerContactInput.placeholder = placeholders[customerChannelSelect.value] || "Contato";
  });
}

$("#customer-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await api("/api/customers", { method: "POST", body: JSON.stringify(Object.fromEntries(form)) });
    $("#customer-dialog").close();
    event.currentTarget.reset();
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
    toast("Cliente criado");
  } catch (error) {
    toast(error.message);
  }
});

$("#message-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedCustomer) return;
  const textarea = event.currentTarget.elements.body;
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/messages`, {
      method: "POST",
      body: JSON.stringify({ body: textarea.value }),
    });
    textarea.value = "";
    await selectCustomer(state.selectedCustomer.id);
    await Promise.all([loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
  } catch (error) {
    toast(error.message);
  }
});

$("#quick-reply-send-button").addEventListener("click", async () => {
  if (!state.selectedCustomer) return;
  const shortcut = $("#quick-reply-select").value;
  if (!shortcut) {
    toast("Selecione uma frase rapida");
    return;
  }
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/quick-reply`, {
      method: "POST",
      body: JSON.stringify({ shortcut }),
    });
    await selectCustomer(state.selectedCustomer.id);
    await Promise.all([loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
  } catch (error) {
    toast(error.message);
  }
});

$("#private-note-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedCustomer) return;
  const form = new FormData(event.currentTarget);
  const body = String(form.get("body") || "").trim();
  if (!body) {
    toast("Informe a nota");
    return;
  }
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    });
    event.currentTarget.reset();
    await loadPrivateNotes(state.selectedCustomer.id);
    toast("Nota registrada");
  } catch (error) {
    toast(error.message);
  }
});

$("#schedule-message-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedCustomer) return;
  const form = new FormData(event.currentTarget);
  const body = String(form.get("body") || "").trim();
  const sendAtRaw = String(form.get("send_at") || "").trim();
  if (!body || !sendAtRaw) {
    toast("Preencha data/hora e mensagem.");
    return;
  }
  const sendAtEpoch = Math.floor(new Date(sendAtRaw).getTime() / 1000);
  if (!Number.isFinite(sendAtEpoch) || sendAtEpoch <= 0) {
    toast("Data/hora invalida.");
    return;
  }
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/schedule-message`, {
      method: "POST",
      body: JSON.stringify({ body, send_at: sendAtEpoch }),
    });
    event.currentTarget.reset();
    await loadScheduledMessages(state.selectedCustomer.id);
    toast("Mensagem agendada");
  } catch (error) {
    toast(error.message);
  }
});

$("#media-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedCustomer) return;
  const form = new FormData(event.currentTarget);
  const mediaType = String(form.get("media_type") || "").trim();
  const url = String(form.get("url") || "").trim();
  const file = form.get("file");
  const caption = String(form.get("caption") || "").trim();
  if (!mediaType) {
    toast("Informe o tipo de midia.");
    return;
  }
  const hasFile = file instanceof File && file.size > 0;
  if (!url && !hasFile) {
    toast("Informe uma URL ou selecione um arquivo.");
    return;
  }
  try {
    if (hasFile) {
      const contentBase64 = await fileToBase64(file);
      await api(`/api/customers/${state.selectedCustomer.id}/media-upload`, {
        method: "POST",
        body: JSON.stringify({
          media_type: mediaType,
          filename: file.name || "upload.bin",
          content_base64: contentBase64,
          caption,
        }),
      });
    } else {
      await api(`/api/customers/${state.selectedCustomer.id}/media`, {
        method: "POST",
        body: JSON.stringify({ media_type: mediaType, url, caption }),
      });
    }
    event.currentTarget.reset();
    await selectCustomer(state.selectedCustomer.id);
    toast("Midia enviada");
  } catch (error) {
    toast(error.message);
  }
});

$("#ai-suggest-button").addEventListener("click", async () => {
  if (!state.selectedCustomer) return;
  try {
    const payload = await api(`/api/customers/${state.selectedCustomer.id}/ai-suggest`, {
      method: "POST",
      body: "{}",
    });
    $("#ai-suggest-output").value = payload.suggestion || "";
    toast("Sugestao gerada");
  } catch (error) {
    toast(error.message);
  }
});

$("#campaign-opt-out-checkbox").addEventListener("change", async (event) => {
  if (!state.selectedCustomer || state.user?.role !== "admin") return;
  const checked = !!event.target.checked;
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/campaign-opt-out`, {
      method: "POST",
      body: JSON.stringify({ opt_out: checked }),
    });
    const current = state.customers.find((item) => item.id === state.selectedCustomer.id);
    if (current) current.campaign_opt_out = checked ? 1 : 0;
    toast("Preferencia de campanha atualizada");
  } catch (error) {
    event.target.checked = !checked;
    toast(error.message);
  }
});

$("#customer-status").addEventListener("change", async (event) => {
  if (!state.selectedCustomer) return;
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/status`, {
      method: "POST",
      body: JSON.stringify({ status: event.target.value }),
    });
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
  } catch (error) {
    toast(error.message);
  }
});

$("#assign-select").addEventListener("change", async (event) => {
  if (!state.selectedCustomer) return;
  if (state.user.role !== "admin") return;
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/assign`, {
      method: "POST",
      body: JSON.stringify({ operator_id: event.target.value }),
    });
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
    toast("Cliente redistribuido");
  } catch (error) {
    toast(error.message);
  }
});

$("#transfer-button").addEventListener("click", async () => {
  if (!state.selectedCustomer) return;
  const operatorId = $("#assign-select").value;
  if (!operatorId) {
    toast("Selecione um operador para transferir");
    return;
  }
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/transfer`, {
      method: "POST",
      body: JSON.stringify({ operator_id: operatorId }),
    });
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
    toast("Atendimento transferido");
  } catch (error) {
    toast(error.message);
  }
});

$("#finalize-button").addEventListener("click", async () => {
  if (!state.selectedCustomer) return;
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/finalize`, {
      method: "POST",
      body: "{}",
    });
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
    toast("Atendimento finalizado e bloqueado para novas acoes");
  } catch (error) {
    toast(error.message);
  }
});

$("#send-boleto-button").addEventListener("click", async () => {
  if (!state.selectedCustomer) return;
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/send-boleto`, { method: "POST", body: "{}" });
    await selectCustomer(state.selectedCustomer.id);
    toast("Boleto enviado no chat");
  } catch (error) {
    toast(error.message);
  }
});

$("#unlock-billing-button").addEventListener("click", async () => {
  if (!state.selectedCustomer) return;
  try {
    await api(`/api/customers/${state.selectedCustomer.id}/unlock-billing`, { method: "POST", body: "{}" });
    await selectCustomer(state.selectedCustomer.id);
    toast("Desbloqueio em cobranca registrado");
  } catch (error) {
    toast(error.message);
  }
});

$("#create-instance-button").addEventListener("click", async () => {
  try {
    await api("/api/evolution/create-instance", { method: "POST", body: "{}" });
    toast("Instancia solicitada na Evolution API");
  } catch (error) {
    toast(error.message);
  }
});

$("#webhook-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/evolution/set-webhook", {
      method: "POST",
      body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))),
    });
    toast("Webhook configurado");
  } catch (error) {
    toast(error.message);
  }
});

$("#quick-reply-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.user?.role !== "admin") {
    toast("Somente admin pode salvar frases.");
    return;
  }
  const form = new FormData(event.currentTarget);
  const shortcut = String(form.get("shortcut") || "").trim();
  const body = String(form.get("body") || "").trim();
  if (!shortcut || !body) {
    toast("Atalho e texto sao obrigatorios.");
    return;
  }
  try {
    await api("/api/quick-replies", {
      method: "POST",
      body: JSON.stringify({ shortcut, body }),
    });
    event.currentTarget.reset();
    await loadQuickReplies();
    toast("Frase rapida salva");
  } catch (error) {
    toast(error.message);
  }
});

$("#team-message-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const body = String(form.get("body") || "").trim();
  if (!body) {
    toast("Informe a mensagem interna.");
    return;
  }
  try {
    await api("/api/team-messages", {
      method: "POST",
      body: JSON.stringify({ body }),
    });
    event.currentTarget.reset();
    await loadTeamMessages();
    toast("Mensagem enviada no chat interno");
  } catch (error) {
    toast(error.message);
  }
});

$("#campaign-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.user?.role !== "admin") {
    toast("Somente admin pode disparar campanhas.");
    return;
  }
  const form = new FormData(event.currentTarget);
  const name = String(form.get("name") || "").trim();
  const body = String(form.get("body") || "").trim();
  const scheduledAtRaw = String(form.get("scheduled_at") || "").trim();
  const ratePerMinute = Number(form.get("rate_per_minute") || 120);
  const selected = Array.from($("#campaign-customers").selectedOptions || []);
  const customerIds = selected.map((option) => Number(option.value)).filter((id) => Number.isInteger(id) && id > 0);
  if (!name || !body || !customerIds.length) {
    toast("Preencha nome, mensagem e selecione clientes.");
    return;
  }
  if (!Number.isFinite(ratePerMinute) || ratePerMinute < 1 || ratePerMinute > 600) {
    toast("Taxa por minuto invalida.");
    return;
  }
  let scheduledAt = null;
  if (scheduledAtRaw) {
    const value = Math.floor(new Date(scheduledAtRaw).getTime() / 1000);
    if (!Number.isFinite(value) || value <= 0) {
      toast("Data/hora de campanha invalida.");
      return;
    }
    scheduledAt = value;
  }
  try {
    await api("/api/campaigns", {
      method: "POST",
      body: JSON.stringify({
        name,
        body,
        customer_ids: customerIds,
        rate_per_minute: Math.trunc(ratePerMinute),
        scheduled_at: scheduledAt,
      }),
    });
    event.currentTarget.reset();
    const rateField = $("#campaign-form input[name='rate_per_minute']");
    if (rateField) rateField.value = "120";
    await Promise.all([loadCampaigns(), loadCustomers(), loadDashboard(), loadSLA(), loadTmaTme(), loadIntelligence()]);
    toast("Campanha registrada");
  } catch (error) {
    toast(error.message);
  }
});

$("#tma-tme-targets-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.user?.role !== "admin") {
    toast("Somente admin pode alterar metas.");
    return;
  }
  const globalTme = Number($("#target-global-tme").value || 0);
  const globalTma = Number($("#target-global-tma").value || 0);
  const queueRows = $$("#tma-tme-targets-queues tr[data-queue-id]");
  const queuePayload = queueRows.map((row) => {
    const queueId = Number(row.dataset.queueId || 0);
    const inherit = !!row.querySelector(".target-inherit-input")?.checked;
    if (inherit) return { queue_id: queueId, inherit: true };
    return {
      queue_id: queueId,
      tme_target_seconds: Number(row.querySelector(".target-tme-input")?.value || 0),
      tma_target_seconds: Number(row.querySelector(".target-tma-input")?.value || 0),
    };
  });
  try {
    await api("/api/tma-tme/targets", {
      method: "POST",
      body: JSON.stringify({
        global: { tme_target_seconds: globalTme, tma_target_seconds: globalTma },
        queues: queuePayload,
      }),
    });
    await Promise.all([loadTmaTmeTargets(), loadTmaTme()]);
    toast("Metas TMA/TME atualizadas");
  } catch (error) {
    toast(error.message);
  }
});

bootstrap().catch((error) => toast(error.message));
