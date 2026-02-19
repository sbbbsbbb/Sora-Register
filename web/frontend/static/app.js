const API_BASE = "";
let token = localStorage.getItem("admin_token");
let currentPage = 1;
let accountsTotal = 0;

function api(url, options = {}) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (token) headers["Authorization"] = "Bearer " + token;
  return fetch(API_BASE + url, { ...options, headers }).then(async (r) => {
    if (r.status === 401) {
      if (!url.includes("/auth/login")) {
        localStorage.removeItem("admin_token");
        window.location.reload();
      }
      const text = await r.text();
      let msg = "Unauthorized";
      try {
        const j = JSON.parse(text);
        if (j.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
      } catch (_) {}
      throw new Error(msg);
    }
    if (!r.ok) throw new Error(await r.text());
    const ct = r.headers.get("content-type");
    if (ct && ct.includes("application/json")) return r.json();
    return r.text();
  });
}

function showPage(name) {
  document.querySelectorAll(".panel").forEach((el) => el.classList.add("hidden"));
  document.querySelectorAll(".nav a").forEach((a) => a.classList.remove("active"));
  const panel = document.getElementById("panel-" + name);
  const link = document.querySelector('.nav a[data-tab="' + name + '"]');
  if (panel) panel.classList.remove("hidden");
  if (link) link.classList.add("active");
  if (name === "accounts") loadAccounts();
  if (name === "emails") {
    loadEmails();
    api("/api/settings").then((d) => {
      const sel = document.getElementById("email-api-mail-type");
      if (sel && d.email_api_default_type) {
        if ([].some.call(sel.options, (o) => o.value === d.email_api_default_type)) sel.value = d.email_api_default_type;
      }
    }).catch(() => {});
  }
  if (name === "bank-cards") loadBankCards();
  if (name === "phones") loadPhones();
  if (name === "logs") {
    loadDashboard();
    loadLogs();
    updateRegisterStatusOnce();
    startRegisterStatusPoll();
  } else {
    stopRegisterStatusPoll();
  }
  if (name === "settings") loadSettings();
}

var registerStatusPollTimer = null;
var REGISTER_POLL_INTERVAL_MS = 1500;

/** 状态来源：GET /api/register/status 的 running 字段（后端 _registration_running，重启后必为 false） */
function updateRegisterButtonFromStatus(s) {
  var btnStart = document.getElementById("btn-start-register");
  var btnStop = document.getElementById("btn-stop-register");
  var heartbeatEl = document.getElementById("register-status-heartbeat");
  if (!btnStart) return;
  var running = !!(s && s.running === true);
  if (running) {
    btnStart.textContent = "正在注册";
    btnStart.disabled = true;
    btnStart.classList.add("btn-dash-disabled");
    if (btnStop) { btnStop.style.display = ""; }
    if (heartbeatEl) {
      heartbeatEl.style.display = "";
      heartbeatEl.textContent = s.last_heartbeat ? "最后心跳时间 " + (s.last_heartbeat.replace("T", " ").replace("Z", "").slice(0, 19)) : "";
    }
  } else {
    btnStart.textContent = "开启注册";
    btnStart.disabled = false;
    btnStart.classList.remove("btn-dash-disabled");
    if (btnStop) { btnStop.style.display = "none"; }
    if (heartbeatEl) {
      heartbeatEl.style.display = "none";
      heartbeatEl.textContent = "";
    }
  }
}

function updateRegisterStatusOnce() {
  api("/api/register/status").then(function(s) {
    updateRegisterButtonFromStatus(s);
  }).catch(function() {
    updateRegisterButtonFromStatus({ running: false });
  });
}

function startRegisterStatusPoll() {
  stopRegisterStatusPoll();
  registerStatusPollTimer = setInterval(function() {
    api("/api/register/status").then(function(s) {
      updateRegisterButtonFromStatus(s);
      loadDashboard();
      loadLogs();
    }).catch(function() {
      updateRegisterButtonFromStatus({ running: false });
    });
  }, REGISTER_POLL_INTERVAL_MS);
}

document.addEventListener("visibilitychange", function() {
  if (document.visibilityState === "visible") {
    var panelLogs = document.getElementById("panel-logs");
    if (panelLogs && !panelLogs.classList.contains("hidden")) {
      updateRegisterStatusOnce();
    }
  }
});

function stopRegisterStatusPoll() {
  if (registerStatusPollTimer) {
    clearInterval(registerStatusPollTimer);
    registerStatusPollTimer = null;
  }
}

function showModal(html) {
  document.getElementById("modal-body").innerHTML = html;
  document.getElementById("modal").classList.remove("hidden");
}
function hideModal() {
  document.getElementById("modal").classList.add("hidden");
  var mc = document.querySelector(".modal-content");
  if (mc) mc.classList.remove("modal-content-wide");
}
document.querySelector(".modal-close").addEventListener("click", hideModal);
document.getElementById("modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") hideModal();
});

function toast(msg, type) {
  type = type || "success";
  var container = document.getElementById("toast-container");
  var el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(function() {
    el.style.opacity = "0";
    el.style.transform = "translateX(100%)";
    setTimeout(function() { el.remove(); }, 250);
  }, 2500);
}
function confirmBox(msg, onConfirm) {
  showModal(
    '<div class="confirm-dialog">' +
      '<p class="confirm-msg">' + escapeHtml(msg) + '</p>' +
      '<div class="confirm-btns">' +
        '<button type="button" class="btn-default btn-cancel">取消</button>' +
        '<button type="button" class="btn-primary btn-ok">确定</button>' +
      '</div>' +
    '</div>'
  );
  document.querySelector(".btn-cancel").addEventListener("click", function() { hideModal(); });
  document.querySelector(".btn-ok").addEventListener("click", function() {
    hideModal();
    if (onConfirm) onConfirm();
  });
}

// Login
if (!token) {
  document.getElementById("login-page").classList.remove("hidden");
  document.getElementById("admin-page").classList.add("hidden");
} else {
  document.getElementById("login-page").classList.add("hidden");
  document.getElementById("admin-page").classList.remove("hidden");
  api("/api/auth/me").then((d) => {
    var u = document.getElementById("current-user"); if (u) { var t = u.querySelector(".user-name-text"); if (t) t.textContent = d.username; else u.textContent = d.username; }
  }).catch(() => {
    localStorage.removeItem("admin_token");
    window.location.reload();
  });
}

document.getElementById("login-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const errEl = document.getElementById("login-error");
  errEl.textContent = "";
  api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  })
    .then((d) => {
      if (!d || !d.token) {
        errEl.textContent = "登录返回异常，请重试";
        return;
      }
      token = d.token;
      localStorage.setItem("admin_token", token);
      document.getElementById("login-page").classList.add("hidden");
      document.getElementById("admin-page").classList.remove("hidden");
      var cu = document.getElementById("current-user"); if (cu) { var ct = cu.querySelector(".user-name-text"); if (ct) ct.textContent = d.username || username; else cu.textContent = d.username || username; }
      errEl.textContent = "";
      showPage("accounts");
    })
    .catch((err) => {
      errEl.textContent = err.message || "登录失败";
    });
});

document.getElementById("btn-logout").addEventListener("click", () => {
  localStorage.removeItem("admin_token");
  window.location.reload();
});

// 侧栏默认收起，可展开；状态存 localStorage；收起时用底部按钮，展开时用头部按钮
(function() {
  var sidebar = document.getElementById("sidebar");
  var key = "sidebarCollapsed";
  function toggleSidebar() {
    sidebar.classList.toggle("collapsed");
    localStorage.setItem(key, sidebar.classList.contains("collapsed") ? "1" : "0");
  }
  if (sidebar) {
    var saved = localStorage.getItem(key);
    if (saved === "0" || saved === "false") sidebar.classList.remove("collapsed");
    else sidebar.classList.add("collapsed");
    var btnHeader = document.getElementById("sidebar-toggle");
    var btnFooter = document.getElementById("sidebar-toggle-footer");
    if (btnHeader) btnHeader.addEventListener("click", toggleSidebar);
    if (btnFooter) btnFooter.addEventListener("click", toggleSidebar);
  }
})();

// Nav tabs
document.querySelectorAll('.nav a[data-tab]').forEach((a) => {
  a.addEventListener("click", (e) => {
    e.preventDefault();
    showPage(a.getAttribute("data-tab"));
  });
});

// Accounts
function loadAccounts() {
  const status = document.getElementById("filter-status").value;
  const sora = document.getElementById("filter-sora").value;
  const plus = document.getElementById("filter-plus").value;
  const params = new URLSearchParams({ page: currentPage, page_size: 20 });
  if (status) params.set("status", status);
  if (sora) params.set("has_sora", sora);
  if (plus) params.set("has_plus", plus);
  api("/api/debug/db-info").then(function (info) {
    const el = document.getElementById("accounts-db-hint");
    if (el) el.textContent = "共 " + (info.accounts_count != null ? info.accounts_count : "?") + " 条。若用脚本注册，请用相同 DATA_DIR 启动本后端，否则新账号不会出现在本列表。";
  }).catch(function () {});
  api("/api/accounts?" + params).then((d) => {
    accountsTotal = d.total;
    const tbody = document.getElementById("accounts-tbody");
    tbody.innerHTML = d.items
      .map(
        (r) =>
          `<tr>
        <td>${r.id}</td>
        <td>${escapeHtml(r.email)}</td>
        <td>${escapeHtml(r.password || "")}</td>
        <td>${escapeHtml(r.status || "")}</td>
        <td>${r.has_sora ? "是" : "否"}</td>
        <td>${r.has_plus ? "是" : "否"}</td>
        <td>${r.phone_bound ? "是" : "否"}</td>
        <td title="${escapeHtml(r.refresh_token || "")}">${escapeHtml((r.refresh_token || "").slice(0, 24))}${(r.refresh_token || "").length > 24 ? "…" : ""}</td>
        <td>${escapeHtml(r.registered_at || r.created_at || "")}</td>
      </tr>`
      )
      .join("");
    const pag = document.getElementById("accounts-pagination");
    const totalPages = Math.ceil(d.total / d.page_size) || 1;
    pag.innerHTML = `共 ${d.total} 条 ` + (totalPages > 1 ? `<button type="button" data-page="prev">上一页</button> <span>${currentPage}/${totalPages}</span> <button type="button" data-page="next">下一页</button>` : "");
    pag.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (btn.dataset.page === "prev" && currentPage > 1) currentPage--;
        if (btn.dataset.page === "next" && currentPage < totalPages) currentPage++;
        loadAccounts();
      });
    });
  });
}
document.getElementById("filter-status").addEventListener("change", () => { currentPage = 1; loadAccounts(); });
document.getElementById("filter-sora").addEventListener("change", () => { currentPage = 1; loadAccounts(); });
document.getElementById("filter-plus").addEventListener("change", () => { currentPage = 1; loadAccounts(); });

document.getElementById("btn-export-accounts").addEventListener("click", () => {
  const status = document.getElementById("filter-status").value;
  const sora = document.getElementById("filter-sora").value;
  const plus = document.getElementById("filter-plus").value;
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (sora) params.set("has_sora", sora);
  if (plus) params.set("has_plus", plus);
  fetch(API_BASE + "/api/accounts/export?" + params, { headers: { Authorization: "Bearer " + token } })
    .then((r) => { if (!r.ok) throw new Error(r.statusText); return r.blob(); })
    .then((blob) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "accounts.csv";
      a.click();
      URL.revokeObjectURL(a.href);
    })
    .catch((err) => toast("导出失败: " + err.message, "error"));
});

// Emails
function loadEmails() {
  document.getElementById("email-api-balance").textContent = "--";
  document.getElementById("email-api-msg").textContent = "";
  api("/api/email-api/balance").then((d) => {
    document.getElementById("email-api-balance").textContent = String(d.balance);
  }).catch(() => {
    document.getElementById("email-api-balance").textContent = "未配置或请求失败";
  });
  api("/api/emails").then((d) => {
    document.getElementById("emails-tbody").innerHTML = (d.items || [])
      .map(
        (r) =>
          `<tr>
        <td>${r.id}</td>
        <td>${escapeHtml(r.email)}</td>
        <td>${escapeHtml(r.password ? "***" : "")}</td>
        <td>${escapeHtml((r.uuid || "").slice(0, 12))}</td>
        <td>${r.registered ? '<span class="status-registered">已注册</span>' : '<span class="status-unregistered">未注册</span>'}</td>
        <td>
          <button type="button" class="btn-op btn-op-view" data-id="${r.id}">查看邮件</button>
          <button type="button" class="btn-op danger" data-id="${r.id}">删除邮箱</button>
        </td>
      </tr>`
      )
      .join("");
    document.getElementById("emails-tbody").querySelectorAll(".btn-op-view").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.id;
        showModal('<div class="email-view-card"><p>正在获取邮件列表…</p></div>');
        var modalContent = document.querySelector(".modal-content");
        if (modalContent) modalContent.classList.add("modal-content-wide");
        api("/api/email-api/mail-list?email_id=" + encodeURIComponent(id))
          .then((d) => {
            var list = d.list || [];
            function renderMailDetail(mail) {
              var isObj = mail && typeof mail === "object" && !Array.isArray(mail);
              var subject = isObj && (mail.subject != null || mail.title != null) ? (mail.subject ?? mail.title) : "";
              var body = isObj && (mail.body != null || mail.content != null || mail.text != null || mail.Text != null) ? (mail.body ?? mail.content ?? mail.text ?? mail.Text) : "";
              var from = isObj && mail.from != null ? mail.from : "";
              var date = isObj && mail.date != null ? mail.date : "";
              var html = isObj && (mail.html != null || mail.Html != null) ? (mail.html ?? mail.Html) : "";
              var previewHtml = "";
              if (html) previewHtml = "<div class=\"email-body-html\">" + html + "</div>";
              else if (body) previewHtml = "<pre class=\"email-body\">" + escapeHtml(String(body)) + "</pre>";
              else if (isObj) previewHtml = "<pre class=\"email-body\">" + escapeHtml(JSON.stringify(mail, null, 2)) + "</pre>";
              else previewHtml = "<pre class=\"email-body\">" + escapeHtml(String(mail)) + "</pre>";
              var rawHtml = "<pre class=\"email-body\">" + escapeHtml(JSON.stringify(mail, null, 2)) + "</pre>";
              return '<p><strong>发件人</strong> ' + escapeHtml(String(from)) + '</p><p><strong>主题</strong> ' + escapeHtml(String(subject)) + (date ? '</p><p><strong>时间</strong> ' + escapeHtml(String(date)) : '') + '</p><div class="email-view-tabs"><button type="button" class="email-tab active" data-tab="preview">正常显示</button><button type="button" class="email-tab" data-tab="raw">源文件</button></div><div class="email-tab-panel" id="email-panel-preview">' + previewHtml + '</div><div class="email-tab-panel hidden" id="email-panel-raw">' + rawHtml + "</div>";
            }
            function bindTabSwitch() {
              document.querySelectorAll(".email-view-detail .email-tab").forEach(function(tab) {
                tab.onclick = function() {
                  document.querySelectorAll(".email-view-detail .email-tab").forEach(function(t) { t.classList.remove("active"); });
                  document.querySelectorAll(".email-view-detail .email-tab-panel").forEach(function(p) { p.classList.add("hidden"); });
                  this.classList.add("active");
                  var pid = "email-panel-" + this.getAttribute("data-tab");
                  var panel = document.getElementById(pid);
                  if (panel) panel.classList.remove("hidden");
                };
              });
            }
            var listHtml = '<div class="email-view-list"><div class="email-view-list-title">邮件列表</div><div class="email-view-list-inner">';
            if (list.length === 0) {
              listHtml += '<p class="email-view-empty">收件箱暂无邮件或 API 未返回</p>';
            } else {
              list.forEach(function(m, i) {
                var subj = (m.subject != null || m.title != null) ? (m.subject ?? m.title) : "(无主题)";
                var fr = m.from != null ? m.from : "";
                var dt = m.date != null ? m.date : "";
                listHtml += '<div class="email-view-list-item' + (i === 0 ? ' active' : '') + '" data-index="' + i + '"><div class="email-view-list-item-subject">' + escapeHtml(String(subj).slice(0, 28)) + (String(subj).length > 28 ? "…" : "") + '</div><div class="email-view-list-item-meta">' + escapeHtml(String(fr).slice(0, 20)) + (String(fr).length > 20 ? "…" : "") + (dt ? " · " + escapeHtml(String(dt).slice(0, 12)) : "") + '</div></div>';
              });
            }
            listHtml += "</div></div>";
            var detailHtml = '<div class="email-view-detail"><div class="email-view-detail-inner">';
            if (list.length === 0) {
              detailHtml += '<p class="email-view-empty">收件箱暂无邮件，或该邮箱尚未收到新邮件；当前仅能拉取最新 1 封，更多请登录 Outlook 查看。</p>';
            } else {
              detailHtml += renderMailDetail(list[0]);
            }
            detailHtml += '<p class="email-view-fallback"><a href="https://outlook.live.com" target="_blank" rel="noopener">在 Outlook 登录</a> 可查看全部邮件</p></div></div>';
            document.getElementById("modal-body").innerHTML = '<div class="email-view-card email-view-layout">' + listHtml + detailHtml + "</div>";
            bindTabSwitch();
            document.querySelectorAll(".email-view-list-item").forEach(function(item) {
              item.addEventListener("click", function() {
                var idx = parseInt(this.getAttribute("data-index"), 10);
                var mail = list[idx];
                if (!mail) return;
                document.querySelectorAll(".email-view-list-item").forEach(function(el) { el.classList.remove("active"); });
                this.classList.add("active");
                var inner = document.querySelector(".email-view-detail-inner");
                if (inner) {
                  inner.innerHTML = renderMailDetail(mail) + '<p class="email-view-fallback"><a href="https://outlook.live.com" target="_blank" rel="noopener">在 Outlook 登录</a> 可查看全部邮件</p>';
                  bindTabSwitch();
                }
              });
            });
          })
          .catch((err) => {
            if (modalContent) modalContent.classList.remove("modal-content-wide");
            document.getElementById("modal-body").innerHTML =
              '<div class="email-view-card"><p class="error">' + escapeHtml(err.message || "获取失败") + '</p><p><a href="https://outlook.live.com" target="_blank" rel="noopener">在 Outlook 登录</a> 查看邮件</p></div>';
          });
      });
    });
    document.getElementById("emails-tbody").querySelectorAll(".btn-op.danger").forEach((btn) => {
      btn.addEventListener("click", () => {
        confirmBox("确定删除该邮箱？", function() {
            api("/api/emails/" + btn.dataset.id, { method: "DELETE" }).then(() => { toast("已删除"); loadEmails(); });
          });
      });
    });
  });
}
document.getElementById("btn-add-email").addEventListener("click", () => {
  showModal(`
    <form id="email-form">
      <label>邮箱 <input type="text" name="email" required /></label>
      <label>密码 <input type="password" name="password" /></label>
      <label>UUID <input type="text" name="uuid" /></label>
      <label>Token <input type="text" name="token" /></label>
      <label>备注 <input type="text" name="remark" /></label>
      <button type="submit">添加</button>
    </form>
  `);
  document.getElementById("email-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    api("/api/emails", {
      method: "POST",
      body: JSON.stringify({
        email: fd.get("email"),
        password: fd.get("password"),
        uuid: fd.get("uuid"),
        token: fd.get("token"),
        remark: fd.get("remark"),
      }),
    }).then(() => { hideModal(); loadEmails(); });
  });
});
document.getElementById("btn-batch-import-email").addEventListener("click", () => {
  showModal(`
    <p>每行一条：邮箱----密码----UUID----Token</p>
    <textarea id="email-import-lines" rows="12" style="width:100%;background:#2c3036;border:1px solid #3d4248;color:#e4e6e8;padding:0.5rem;font-family:monospace;"></textarea>
    <button type="button" id="email-import-submit">导入</button>
  `);
  document.getElementById("email-import-submit").addEventListener("click", () => {
    const lines = document.getElementById("email-import-lines").value;
    api("/api/emails/batch-import", { method: "POST", body: JSON.stringify({ lines }) }).then((d) => {
      hideModal();
      toast("已导入 " + d.added + " 条");
      loadEmails();
    });
  });
});
document.getElementById("btn-batch-export-email").addEventListener("click", () => {
  api("/api/emails/export").then((d) => {
    const items = d.items || [];
    const lines = items.map((r) => [r.email, r.password || "", r.uuid || "", r.token || ""].join("----"));
    const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "emails-" + new Date().toISOString().slice(0, 10) + ".txt";
    a.click();
    URL.revokeObjectURL(a.href);
    toast("已导出 " + items.length + " 条");
  }).catch((err) => toast("导出失败: " + (err.message || "请求错误"), "error"));
});
document.getElementById("link-to-settings").addEventListener("click", function(e) {
  e.preventDefault();
  showPage("settings");
});
document.getElementById("btn-email-api-stock").addEventListener("click", function() {
  const mailType = document.getElementById("email-api-mail-type").value;
  const msg = document.getElementById("email-api-msg");
  msg.textContent = "查询中...";
  api("/api/email-api/stock?mailType=" + encodeURIComponent(mailType)).then((d) => {
    msg.textContent = "库存：" + d.stock + "（" + (d.mail_type || "全部") + "）";
  }).catch((err) => {
    msg.textContent = "失败：" + (err.message || "请求错误");
  });
});
document.getElementById("btn-email-api-fetch").addEventListener("click", function() {
  const mailType = document.getElementById("email-api-mail-type").value;
  const quantity = parseInt(document.getElementById("email-api-quantity").value, 10) || 1;
  const msg = document.getElementById("email-api-msg");
  msg.textContent = "拉取中...";
  api("/api/email-api/fetch-mail", {
    method: "POST",
    body: JSON.stringify({ mail_type: mailType, quantity, import_to_emails: true }),
  }).then((d) => {
    msg.textContent = "拉取 " + d.count + " 条，已导入 " + d.imported + " 条";
    if (d.imported) loadEmails();
  }).catch((err) => {
    msg.textContent = "失败：" + (err.message || "请求错误");
  });
});

// Bank cards
function loadBankCards() {
  api("/api/bank-cards").then((d) => {
    document.getElementById("cards-tbody").innerHTML = (d.items || [])
      .map(
        (r) =>
          `<tr>
        <td><input type="checkbox" class="card-id" value="${r.id}" /></td>
        <td>${r.id}</td>
        <td>${escapeHtml(r.card_number_masked || "")}</td>
        <td>${r.used_count}/${r.max_use_count}</td>
        <td>${escapeHtml(r.remark || "")}</td>
        <td><button type="button" class="btn-link danger" data-id="${r.id}">删除</button></td>
      </tr>`
      )
      .join("");
    document.getElementById("cards-tbody").querySelectorAll(".btn-link.danger").forEach((btn) => {
      btn.addEventListener("click", () => {
        confirmBox("确定删除该银行卡？", function() {
            api("/api/bank-cards/" + btn.dataset.id, { method: "DELETE" }).then(() => { toast("已删除"); loadBankCards(); });
          });
      });
    });
  });
}
document.getElementById("btn-add-card").addEventListener("click", () => {
  showModal(`
    <form id="card-form">
      <label>卡号(掩码) <input type="text" name="card_number_masked" placeholder="****1234" /></label>
      <label>使用次数上限 <input type="number" name="max_use_count" value="1" min="1" /></label>
      <label>备注 <input type="text" name="remark" /></label>
      <button type="submit">添加</button>
    </form>
  `);
  document.getElementById("card-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    api("/api/bank-cards", {
      method: "POST",
      body: JSON.stringify({
        card_number_masked: fd.get("card_number_masked"),
        card_data: fd.get("card_number_masked"),
        max_use_count: parseInt(fd.get("max_use_count") || 1, 10),
        remark: fd.get("remark"),
      }),
    }).then(() => { hideModal(); loadBankCards(); });
  });
});
document.getElementById("btn-batch-import-card").addEventListener("click", () => {
  showModal(`
    <p>每行一条卡信息（掩码或后四位），使用次数从系统设置读取</p>
    <textarea id="card-import-lines" rows="12" style="width:100%;background:#2c3036;border:1px solid #3d4248;color:#e4e6e8;padding:0.5rem;font-family:monospace;"></textarea>
    <button type="button" id="card-import-submit">导入</button>
  `);
  document.getElementById("card-import-submit").addEventListener("click", () => {
    const lines = document.getElementById("card-import-lines").value;
    api("/api/bank-cards/batch-import", { method: "POST", body: JSON.stringify({ lines }) }).then((d) => {
      hideModal();
      toast("已导入 " + d.added + " 条");
      loadBankCards();
    });
  });
});
document.getElementById("btn-batch-delete-card").addEventListener("click", () => {
  const ids = Array.from(document.querySelectorAll(".card-id:checked")).map((c) => parseInt(c.value, 10));
  if (!ids.length) { toast("请先勾选要删除的卡", "info"); return; }
  confirmBox("确定删除已选 " + ids.length + " 条银行卡？", function() {
    api("/api/bank-cards/batch-delete", { method: "POST", body: JSON.stringify({ ids }) }).then(() => {
      toast("已删除");
      loadBankCards();
    });
  });
});

// Phones
document.getElementById("link-to-settings-phones").addEventListener("click", function(e) {
  e.preventDefault();
  showPage("settings");
});
function refreshSmsApiSummary() {
  var balanceEl = document.getElementById("sms-api-balance");
  var countEl = document.getElementById("sms-api-openai-count");
  var msgEl = document.getElementById("sms-api-msg");
  balanceEl.textContent = "--";
  countEl.textContent = "--";
  msgEl.textContent = "";
  api("/api/sms-api/openai-availability").then(function(d) {
    balanceEl.textContent = String(d.balance != null ? d.balance : 0);
    countEl.textContent = String(d.total_count != null ? d.total_count : 0);
    if (d.service_hint && d.service_hint.length) {
      msgEl.textContent = "当前服务代号不被支持。可用代号: " + d.service_hint.join(", ") + "，请到系统设置修改「OpenAI 服务 ID」";
    }
  }).catch(function() {
    balanceEl.textContent = "未配置或失败";
    countEl.textContent = "--";
  });
}
function formatExpiredAtLocal(utcStr) {
  if (!utcStr) return "—";
  var s = String(utcStr).trim();
  if (s.indexOf("Z") === -1 && s.indexOf("+") === -1 && s.indexOf("-") >= 0) s = s.replace(" ", "T") + "Z";
  var d = new Date(s);
  if (isNaN(d.getTime())) return utcStr;
  return d.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}
function loadPhones() {
  refreshSmsApiSummary();
  var tbody = document.getElementById("phones-tbody");
  api("/api/phones?_=" + Date.now()).then((d) => {
    var items = d.items || [];
    tbody.innerHTML = items
      .map(
        (r) =>
          "<tr>" +
          "<td><input type=\"checkbox\" class=\"phone-id\" value=\"" + r.id + "\" /></td>" +
          "<td>" + r.id + "</td>" +
          "<td>" + escapeHtml(r.phone || "") + "</td>" +
          "<td>" + (r.used_count != null ? r.used_count : 0) + "/" + (r.max_use_count != null ? r.max_use_count : 1) + "</td>" +
          "<td>" + escapeHtml(formatExpiredAtLocal(r.expired_at)) + "</td>" +
          "<td>" + escapeHtml(r.remark || "") + "</td>" +
          "<td>" +
          "<button type=\"button\" class=\"btn-op sms-code\" data-id=\"" + r.id + "\">收码</button> " +
          "<button type=\"button\" class=\"btn-op release-phone\" data-id=\"" + r.id + "\">销毁</button> " +
          "<button type=\"button\" class=\"btn-op danger\" data-id=\"" + r.id + "\">删除</button>" +
          "</td>" +
          "</tr>"
      )
      .join("");
    tbody.querySelectorAll(".btn-op.sms-code").forEach(function(btn) {
      btn.addEventListener("click", function() {
        var id = btn.dataset.id;
        btn.disabled = true;
        btn.textContent = "查询中...";
        api("/api/phones/" + id + "/sms-code").then(function(d) {
          btn.disabled = false;
          btn.textContent = "收码";
          if (d.code) showModal("<p><strong>短信验证码</strong></p><p style=\"font-size:1.5rem;letter-spacing:0.2em;font-weight:600;\">" + escapeHtml(d.code) + "</p><p style=\"color:var(--text-muted);font-size:12px;\">" + (d.message || "") + "</p>");
          else toast(d.message || "等待短信中", "info");
        }).catch(function(e) {
          btn.disabled = false;
          btn.textContent = "收码";
          toast(e.message || "失败", "info");
        });
      });
    });
    tbody.querySelectorAll(".btn-op.release-phone").forEach(function(btn) {
      btn.addEventListener("click", function() {
        confirmBox("确定销毁该号码？将通知接码平台取消并从列表移除。", function() {
          api("/api/phones/" + btn.dataset.id + "/release", { method: "POST" }).then(function() {
            toast("已销毁");
            loadPhones();
          }).catch(function(e) { toast(e.message || "失败", "info"); });
        });
      });
    });
    tbody.querySelectorAll(".btn-op.danger").forEach(function(btn) {
      btn.addEventListener("click", function() {
        confirmBox("确定删除该手机号？", function() {
          api("/api/phones/" + btn.dataset.id, { method: "DELETE" }).then(function() {
            toast("已删除");
            loadPhones();
          });
        });
      });
    });
  }).catch(function(err) {
    tbody.innerHTML = "<tr><td colspan=\"7\">加载失败：" + escapeHtml(err.message || "请求错误") + "</td></tr>";
  });
}
document.getElementById("btn-add-phone").addEventListener("click", function() {
  showModal(
    "<form id=\"phone-form\">" +
      "<label>手机号 <input type=\"text\" name=\"phone\" required placeholder=\"+86 或 国家码+号码\" /></label>" +
      "<label>可绑定次数 <input type=\"number\" name=\"max_use_count\" value=\"1\" min=\"1\" /></label>" +
      "<label>备注 <input type=\"text\" name=\"remark\" /></label>" +
      "<button type=\"submit\">添加</button>" +
    "</form>"
  );
  document.getElementById("phone-form").addEventListener("submit", function(e) {
    e.preventDefault();
    var fd = new FormData(e.target);
    api("/api/phones", {
      method: "POST",
      body: JSON.stringify({
        phone: fd.get("phone"),
        max_use_count: parseInt(fd.get("max_use_count") || 1, 10),
        remark: fd.get("remark"),
      }),
    }).then(function() { hideModal(); toast("已添加"); loadPhones(); });
  });
});
document.getElementById("btn-batch-import-phone").addEventListener("click", function() {
  showModal(
    "<p>每行一个手机号，可绑定次数使用系统设置中的「手机号绑定数」。</p>" +
    "<textarea id=\"phone-import-lines\" rows=\"12\" style=\"width:100%;padding:0.5rem;font-family:monospace;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;\"></textarea>" +
    "<button type=\"button\" id=\"phone-import-submit\">导入</button>"
  );
  document.getElementById("phone-import-submit").addEventListener("click", function() {
    var lines = document.getElementById("phone-import-lines").value;
    api("/api/phones/batch-import", { method: "POST", body: JSON.stringify({ lines }) }).then(function(d) {
      hideModal();
      toast("已导入 " + d.added + " 条");
      loadPhones();
    });
  });
});
document.getElementById("btn-batch-delete-phone").addEventListener("click", function() {
  var ids = Array.from(document.querySelectorAll(".phone-id:checked")).map(function(c) { return parseInt(c.value, 10); });
  if (!ids.length) { toast("请先勾选要删除的手机号", "info"); return; }
  confirmBox("确定删除已选 " + ids.length + " 个手机号？", function() {
    api("/api/phones/batch-delete", { method: "POST", body: JSON.stringify({ ids }) }).then(function() {
      toast("已删除");
      loadPhones();
    });
  });
});
document.getElementById("btn-sms-api-test").addEventListener("click", function() {
  var msgEl = document.getElementById("sms-api-msg");
  msgEl.textContent = "测试中...";
  api("/api/sms-api/balance").then(function(d) {
    msgEl.textContent = "接口正常，余额：" + d.balance;
  }).catch(function(err) {
    msgEl.textContent = "失败：" + (err.message || "请求错误");
  });
});
document.getElementById("btn-sms-api-refresh-openai").addEventListener("click", function() {
  refreshSmsApiSummary();
});
document.getElementById("btn-sms-api-debug-prices").addEventListener("click", function() {
  var msgEl = document.getElementById("sms-api-msg");
  msgEl.textContent = "加载中...";
  api("/api/sms-api/openai-availability?debug=1").then(function(d) {
    msgEl.textContent = "";
    var raw = d.prices_raw;
    var text = raw === undefined ? "(无 prices_raw)" : JSON.stringify(raw, null, 2);
    var desc = "<p class=\"modal-desc\">接码平台 <strong>getPrices</strong> 接口的原始返回（当前「OpenAI 服务 ID」下的价格/库存）。若「OpenAI 可用数量」一直为 0，可据此核对返回结构或到系统设置中修改服务代号。</p>";
    showModal(desc + "<pre style=\"max-height:70vh;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px;\">" + escapeHtml(text) + "</pre>");
  }).catch(function(err) {
    msgEl.textContent = "失败：" + (err.message || "请求错误");
  });
});
document.getElementById("btn-sms-api-services").addEventListener("click", function() {
  var msgEl = document.getElementById("sms-api-msg");
  var country = parseInt(document.getElementById("sms-api-country").value, 10) || 0;
  msgEl.textContent = "加载中...";
  api("/api/sms-api/services?country=" + country).then(function(d) {
    msgEl.textContent = "";
    var list = d.services || [];
    var text = list.length ? JSON.stringify(list, null, 2) : "(空)，请检查 API 与 country";
    showModal("<p>接码平台服务列表（country=" + country + "），请找到 OpenAI 对应的 id 或 shortName 填到系统设置「OpenAI 服务 ID」：</p><pre style=\"max-height:70vh;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px;\">" + escapeHtml(text) + "</pre>");
  }).catch(function(err) {
    msgEl.textContent = "失败：" + (err.message || "请求错误");
  });
});
document.getElementById("btn-sms-api-get-numbers").addEventListener("click", function() {
  var msgEl = document.getElementById("sms-api-msg");
  var quantity = parseInt(document.getElementById("sms-api-get-quantity").value, 10) || 1;
  var country = parseInt(document.getElementById("sms-api-country").value, 10) || 0;
  msgEl.textContent = "获取中...";
  api("/api/sms-api/get-numbers", {
    method: "POST",
    body: JSON.stringify({ country: country, quantity: quantity }),
  }).then(function(d) {
    if (d.got) {
      msgEl.textContent = "已获取 " + d.got + " 个号码并加入列表";
    } else {
      var errMsg = (d.errors && d.errors[0]) ? ("获取失败：" + d.errors[0]) : "已获取 0 个号码并加入列表";
      if (d.errors && d.errors[0] === "BAD_SERVICE") errMsg += "（请到系统设置将「OpenAI 服务 ID」改为 dr 并保存）";
      msgEl.textContent = errMsg;
    }
    loadPhones();
  }).catch(function(err) {
    msgEl.textContent = "失败：" + (err.message || "请求错误");
  });
});

// 批量注册 - 仪表盘与日志
function loadDashboard() {
  api("/api/dashboard").then(function(d) {
    document.getElementById("dash-today").textContent = d.today_registered != null ? d.today_registered : 0;
    document.getElementById("dash-total").textContent = d.total_registered != null ? d.total_registered : 0;
    document.getElementById("dash-phone").textContent = d.phone_bound_count != null ? d.phone_bound_count : 0;
    document.getElementById("dash-plus").textContent = d.plus_count != null ? d.plus_count : 0;
    document.getElementById("dash-success").textContent = d.success_count != null ? d.success_count : 0;
    document.getElementById("dash-fail").textContent = d.fail_count != null ? d.fail_count : 0;
    document.getElementById("dash-email-api").textContent = d.email_api_set ? "已设置" : "未设置";
    document.getElementById("dash-sms-api").textContent = d.sms_api_set ? "已设置" : "未设置";
    document.getElementById("dash-bank-api").textContent = d.bank_api_set ? "已设置" : "未设置";
    document.getElementById("dash-captcha-api").textContent = d.captcha_api_set ? "已设置" : "未设置";
    document.getElementById("dash-threads").textContent = d.thread_count != null ? d.thread_count : "1";
  }).catch(function() {
    document.getElementById("dash-today").textContent = "—";
    document.getElementById("dash-total").textContent = "—";
    document.getElementById("dash-phone").textContent = "—";
    document.getElementById("dash-plus").textContent = "—";
    document.getElementById("dash-success").textContent = "—";
    document.getElementById("dash-fail").textContent = "—";
    document.getElementById("dash-email-api").textContent = "—";
    document.getElementById("dash-sms-api").textContent = "—";
    document.getElementById("dash-bank-api").textContent = "—";
    document.getElementById("dash-captcha-api").textContent = "—";
    document.getElementById("dash-threads").textContent = "—";
  });
}
var currentLogLimit = 20;
function loadLogs(limit) {
  if (limit != null && limit !== undefined) currentLogLimit = Math.min(Math.max(Number(limit) || 20, 1), 100);
  limit = currentLogLimit;
  api("/api/logs?page=1&page_size=" + limit).then(function(d) {
    var list = document.getElementById("log-list");
    var items = d.items || [];
    var total = d.total || 0;
    var titleEl = document.getElementById("log-panel-title");
    var expandEl = document.getElementById("log-expand-area");
    if (titleEl) titleEl.textContent = "最近 " + limit + " 条日志";
    list.classList.toggle("log-list-expanded", limit > 20);
    list.innerHTML = items.length ? items.map(function(r) {
      var levelClass = (r.level === "error") ? " log-line--error" : " log-line--info";
      return "<div class=\"log-line" + levelClass + "\"><span class=\"ts\">" + escapeHtml(r.created_at) + "</span> " + escapeHtml(r.message) + "</div>";
    }).join("") : "<div class=\"log-line log-line--info\">暂无日志</div>";
    if (expandEl) {
      if (limit < 100 && total > 20) {
        expandEl.innerHTML = "<button type=\"button\" id=\"btn-expand-logs\" class=\"log-panel-expand-btn\"><span class=\"log-panel-expand-icon\" aria-hidden=\"true\">▼</span> 展开更多（最多 100 条）</button>";
        expandEl.style.display = "";
        expandEl.className = "log-panel-expand";
        document.getElementById("btn-expand-logs").addEventListener("click", function() { loadLogs(100); });
      } else if (limit === 100 && total > 20) {
        expandEl.innerHTML = "<span class=\"log-panel-expand-done\">已显示最多 100 条</span> <button type=\"button\" id=\"btn-collapse-logs\" class=\"log-panel-collapse-btn\">收起</button>";
        expandEl.style.display = "";
        expandEl.className = "log-panel-expand log-panel-expand--done";
        document.getElementById("btn-collapse-logs").addEventListener("click", function() { loadLogs(20); });
      } else {
        expandEl.innerHTML = "";
        expandEl.style.display = "none";
        expandEl.className = "log-panel-expand";
      }
    }
  }).catch(function() {
    document.getElementById("log-list").innerHTML = "<div class=\"log-line log-line--error\">加载失败</div>";
    var expandEl = document.getElementById("log-expand-area");
    if (expandEl) { expandEl.innerHTML = ""; expandEl.style.display = "none"; }
  });
}
document.getElementById("btn-start-register").addEventListener("click", function() {
  if (this.disabled) return;
  api("/api/register/start", { method: "POST" }).then(function(d) {
    if (d && d.ok) {
      toast(d.message || "已启动注册任务", "success");
      updateRegisterStatusOnce();
      loadDashboard();
      loadLogs();
    } else {
      toast(d.message || "启动失败", "error");
    }
  }).catch(function(err) {
    toast(err.message || "请求失败", "error");
  });
});
document.getElementById("btn-stop-register").addEventListener("click", function() {
  api("/api/register/stop", { method: "POST" }).then(function(d) {
    if (d && d.ok) {
      toast(d.message || "已请求停止", "info");
      updateRegisterStatusOnce();
    } else {
      toast(d.message || "操作失败", "error");
    }
  }).catch(function(err) {
    toast(err.message || "请求失败", "error");
  });
});
document.getElementById("btn-start-bind-phone").addEventListener("click", function() {
  toast("开始绑定手机功能开发中", "info");
});
document.getElementById("btn-start-plus").addEventListener("click", function() {
  toast("开始开通 Plus 功能开发中", "info");
});
document.getElementById("btn-refresh-dashboard").addEventListener("click", function() {
  loadDashboard();
  loadLogs();
});
document.getElementById("btn-clear-logs").addEventListener("click", function() {
  confirmBox("确定清空所有日志？", function() {
    api("/api/logs", { method: "DELETE" }).then(function(d) {
      toast(d.message || "已清空日志", "success");
      loadDashboard();
      loadLogs();
    }).catch(function(err) {
      toast(err.message || "清空失败", "error");
    });
  });
});

// Settings
var SETTINGS_KEYS = [
  "sms_api_url", "sms_api_key", "sms_openai_service", "sms_max_price", "thread_count", "proxy_url", "proxy_api_url",
  "bank_card_api_url", "bank_card_api_key", "bank_card_api_platform", "email_api_url", "email_api_key", "email_api_default_type",
  "captcha_api_url", "captcha_api_key", "oauth_client_id", "oauth_redirect_uri",
  "retry_count", "card_use_limit", "phone_bind_limit"
];
function loadSettings() {
  api("/api/settings").then((d) => {
    const form = document.getElementById("settings-form");
    SETTINGS_KEYS.forEach((k) => {
      const el = form.querySelector(`[name="${k}"]`);
      if (el) el.value = d[k] != null ? d[k] : "";
    });
  });
}
document.getElementById("settings-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {};
  SETTINGS_KEYS.forEach((k) => { body[k] = fd.get(k) || ""; });
  api("/api/settings", { method: "PUT", body: JSON.stringify(body) })
    .then(() => {
      toast("已保存");
      loadSettings();
    })
    .catch((err) => {
      toast(err && err.message ? err.message : "保存失败");
    });
});

function escapeHtml(s) {
  if (s == null) return "";
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// 点击用户名弹出修改账号密码
document.getElementById("current-user").addEventListener("click", function() {
  showModal(`
    <div class="login-update-modal">
      <h3 class="login-update-title">修改登录账号</h3>
      <p class="login-update-desc">保存后需重新登录。</p>
      <form id="login-update-form">
        <label>新账号 <input type="text" name="admin_username" placeholder="请输入新登录账号" required autocomplete="username" /></label>
        <label>新密码 <input type="password" name="admin_password" placeholder="请输入新密码" required autocomplete="new-password" /></label>
        <div class="login-update-actions">
          <button type="submit" class="login-update-btn">保存</button>
        </div>
      </form>
    </div>
  `);
  document.getElementById("login-update-form").addEventListener("submit", function(e) {
    e.preventDefault();
    var fd = new FormData(this);
    var username = (fd.get("admin_username") || "").toString().trim();
    var password = (fd.get("admin_password") || "").toString();
    if (!username || !password) {
      toast("账号与密码均不能为空", "error");
      return;
    }
    api("/api/settings/login", { method: "PUT", body: JSON.stringify({ admin_username: username, admin_password: password }) })
      .then(function() {
        hideModal();
        toast("已修改，请重新登录");
        localStorage.removeItem("admin_token");
        window.location.reload();
      })
      .catch(function(err) {
        toast(err.message || "保存失败", "error");
      });
  });
});

// Default tab（登录后默认打开批量注册）
if (token) showPage("logs");
