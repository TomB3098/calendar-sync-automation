(function () {
  "use strict";

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function statusPill(label, extraClass) {
    return '<span class="status-pill log-pill' + (extraClass ? " " + extraClass : "") + '">' + escapeHtml(label) + "</span>";
  }

  function renderChanges(entry) {
    if (!entry.change_summary) {
      return "";
    }
    var rows = (entry.changes || [])
      .map(function (change) {
        return (
          '<div class="change-row">' +
          '<span class="change-label">' + escapeHtml(change.label) + "</span>" +
          '<span class="change-value">' + escapeHtml(change.before) + "</span>" +
          '<span class="change-value">' + escapeHtml(change.after) + "</span>" +
          "</div>"
        );
      })
      .join("");
    return (
      '<p class="change-summary">Geändert: ' + escapeHtml(entry.change_summary) + "</p>" +
      '<div class="change-table">' +
      '<div class="change-row change-head"><span>Feld</span><span>Vorher</span><span>Nachher</span></div>' +
      rows +
      "</div>"
    );
  }

  function renderPayload(entry) {
    if (entry.error_text) {
      return '<pre class="log-payload">' + escapeHtml(entry.error_text) + "</pre>";
    }
    if (entry.payload_preview) {
      return '<pre class="log-payload">' + escapeHtml(entry.payload_preview) + "</pre>";
    }
    return "";
  }

  function renderLogEntry(entry) {
    var tags = [
      statusPill(entry.level, "log-pill-" + escapeHtml(entry.level_slug || "info")),
      statusPill(entry.provider_label || "system"),
      statusPill(entry.action_label || "event"),
    ];
    if (entry.has_sync_id) {
      tags.push(statusPill(entry.sync_id));
    }
    var meta = escapeHtml(entry.created_at || "");
    if (entry.triggered_by) {
      meta += " · " + escapeHtml(entry.triggered_by);
    }
    var detail = "";
    if (entry.detail_line && entry.detail_line !== entry.message) {
      detail = '<p class="meta-line">' + escapeHtml(entry.detail_line) + "</p>";
    }
    return (
      '<article class="log-line">' +
      '<div class="log-head">' +
      "<div>" +
      '<div class="log-meta">' + meta + "</div>" +
      "<strong>" + escapeHtml(entry.message || "") + "</strong>" +
      "</div>" +
      '<div class="log-tags">' + tags.join("") + "</div>" +
      "</div>" +
      detail +
      renderChanges(entry) +
      renderPayload(entry) +
      "</article>"
    );
  }

  function renderJobRow(job, columnCount, selectedJobId) {
    var endCell = "";
    if (columnCount >= 5) {
      endCell = "<td>" + escapeHtml(job.finished_at || "-") + "</td>";
    }
    return (
      '<tr' + (selectedJobId && Number(selectedJobId) === Number(job.id) ? ' class="table-row-active"' : "") + ">" +
      "<td><span class=\"status-pill\">" + escapeHtml(job.status || "") + "</span></td>" +
      "<td>" + escapeHtml(job.triggered_by || "") + "</td>" +
      "<td>" + escapeHtml(job.started_at || "") + "</td>" +
      endCell +
      "<td>" +
      "<div>" + escapeHtml(job.message || "") + "</div>" +
      (job.id ? '<a class="table-link" href="/app/logs?job_id=' + encodeURIComponent(job.id) + '">Nur diesen Job</a>' : "") +
      "</td>" +
      "</tr>"
    );
  }

  function updateRunningState(payload, root) {
    var runningJobLine = document.querySelector("[data-live-running-job]");
    var startButton = document.querySelector("[data-live-sync-start-button]");
    var cancelForm = document.querySelector("[data-live-sync-cancel-form]");
    var runningJob = payload.running_job;

    if (runningJobLine) {
      if (runningJob) {
        runningJobLine.hidden = false;
        runningJobLine.textContent = "Aktiver Sync: Job " + runningJob.id + " läuft seit " + (runningJob.started_at || "");
        if (root.dataset.liveMode === "logs") {
          runningJobLine.textContent = "Aktiver Lauf: Job " + runningJob.id + " seit " + (runningJob.started_at || "");
        }
      } else {
        runningJobLine.hidden = true;
        runningJobLine.textContent = "";
      }
    }

    if (startButton) {
      startButton.disabled = Boolean(runningJob);
      startButton.textContent = runningJob ? startButton.dataset.runningLabel : startButton.dataset.idleLabel;
    }
    if (cancelForm) {
      cancelForm.hidden = !runningJob;
    }
  }

  function updateJobs(payload) {
    var jobsBody = document.querySelector("[data-live-jobs-body]");
    if (!jobsBody) {
      return;
    }
    var rows = payload.jobs || [];
    var table = jobsBody.closest("table");
    var columnCount = table ? table.querySelectorAll("thead th").length : 5;
    if (!rows.length) {
      jobsBody.innerHTML = '<tr><td colspan="' + (columnCount || 5) + '">Noch keine Jobs vorhanden.</td></tr>';
      return;
    }
    jobsBody.innerHTML = rows
      .map(function (job) { return renderJobRow(job, columnCount, payload.selected_job_id); })
      .join("");
  }

  function updateLogEntries(payload, root) {
    var stream = root.querySelector("[data-live-log-stream]");
    var summary = root.querySelector("[data-live-log-summary]");
    var status = root.querySelector("[data-live-status]");
    if (!stream) {
      return;
    }
    var entries = payload.log_entries || [];
    if (!entries.length) {
      stream.innerHTML = '<p class="meta-line">' + escapeHtml(stream.dataset.emptyText || "Keine Logeinträge vorhanden.") + "</p>";
    } else {
      stream.innerHTML = entries.map(renderLogEntry).join("");
    }

    if (summary) {
      if (root.dataset.liveMode === "dashboard") {
        summary.textContent = entries.length
          ? entries.length + " aktuelle Logeinträge, werden ohne Seiten-Reload nachgeladen."
          : "Sobald der nächste Sync läuft, erscheinen die Logeinträge hier automatisch.";
      } else {
        summary.textContent = payload.log_result_summary || "";
      }
    }
    if (status) {
      status.textContent = payload.running_job ? "Live · aktiv" : "Live · bereit";
    }
  }

  function startLiveFeed(root) {
    var endpoint = root.dataset.liveEndpoint;
    if (!endpoint) {
      return;
    }
    var failureCount = 0;
    var stopped = false;

    function schedule(nextMs) {
      window.setTimeout(function () {
        if (!stopped) {
          refresh();
        }
      }, nextMs);
    }

    function refresh() {
      fetch(endpoint, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        cache: "no-store",
      })
        .then(function (response) {
          if (!response.ok) {
            throw new Error("HTTP " + response.status);
          }
          return response.json();
        })
        .then(function (payload) {
          failureCount = 0;
          updateRunningState(payload, root);
          updateJobs(payload);
          updateLogEntries(payload, root);
          schedule(payload.running_job ? 1500 : 5000);
        })
        .catch(function () {
          failureCount += 1;
          var status = root.querySelector("[data-live-status]");
          if (status) {
            status.textContent = "Live · getrennt";
          }
          schedule(Math.min(12000, 2000 * failureCount));
        });
    }

    refresh();
    window.addEventListener("beforeunload", function () {
      stopped = true;
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-live-log-root]").forEach(startLiveFeed);
  });
})();
