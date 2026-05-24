const state = {
  user: null,
  customers: [],
  queues: [],
  operators: [],
  selectedCustomer: null,
  sla: null,
  intelligence: null,
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

function statusLabel(status) {
  return { open: "Aberto", pending: "Pendente", closed: "Fechado" }[status] || status;
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
    loadDashboard(),
    loadSLA(),
    loadIntelligence(),
    loadCustomers(),
    loadEvolutionStatus(),
  ]);
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
  if (q) params.set("q", q);
  if (status) params.set("status", status);
  const { customers } = await api(`/api/customers?${params.toString()}`);
  state.customers = customers;
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
      await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadIntelligence()]);
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
        <small class="muted">${escapeHtml(customer.phone)} - ${escapeHtml(customer.queue_name)}</small>
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
        <td>${escapeHtml(c.phone)}</td>
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
  $("#chat-meta").textContent = `${customer.phone} - ${customer.queue_name} - ${customer.operator_name || "Sem operador"}`;
  $("#customer-status").value = customer.status;
  $("#message-form button[type='submit']").disabled = !!customer.finalized;
  $("#message-form textarea[name='body']").disabled = !!customer.finalized;
  $("#finalize-button").disabled = !!customer.finalized;
  $("#transfer-button").disabled = !!customer.finalized;
  if (customer.assigned_operator_id) {
    $("#assign-select").value = customer.assigned_operator_id;
  }
  const { messages } = await api(`/api/customers/${id}/messages`);
  renderMessages(messages);
  await loadERP(customer.id);
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
      loadDashboard(),
      loadSLA(),
      loadIntelligence(),
      loadCustomers(),
      loadEvolutionStatus(),
    ]);
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

$("#new-customer-button").addEventListener("click", () => $("#customer-dialog").showModal());
$("#cancel-customer-button").addEventListener("click", () => $("#customer-dialog").close());

$("#customer-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await api("/api/customers", { method: "POST", body: JSON.stringify(Object.fromEntries(form)) });
    $("#customer-dialog").close();
    event.currentTarget.reset();
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadIntelligence()]);
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
    await Promise.all([loadDashboard(), loadSLA(), loadIntelligence()]);
  } catch (error) {
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
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadIntelligence()]);
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
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadIntelligence()]);
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
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadIntelligence()]);
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
    await Promise.all([loadCustomers(), loadDashboard(), loadSLA(), loadIntelligence()]);
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

bootstrap().catch((error) => toast(error.message));
