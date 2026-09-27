(function (root) {
  "use strict";

  function node(doc, tag, text, className) {
    var out = doc.createElement(tag);
    if (text !== undefined && text !== null) out.textContent = String(text);
    if (className) out.className = className;
    return out;
  }

  function append(parent, child) {
    parent.appendChild(child);
    return child;
  }

  function heading(doc, parent, level, text) {
    return append(parent, node(doc, "h" + level, text));
  }

  function render(rootNode, payload, doc) {
    doc = doc || root.document;
    var snapshot = payload && payload.snapshot ? payload.snapshot : {};
    var knowledge = payload && payload.knowledge ? payload.knowledge : {};
    rootNode.replaceChildren();

    var header = append(rootNode, node(doc, "header", undefined, "head"));
    heading(doc, header, 1, "d2k");
    var build = append(header, node(doc, "dl"));
    [
      ["версия", snapshot.version || "неизвестна"],
      ["коммит", snapshot.commit ? String(snapshot.commit).slice(0, 12) : "неизвестен"],
      ["собрано", snapshot.built || "неизвестно"]
    ].forEach(function (pair) {
      append(build, node(doc, "dt", pair[0]));
      append(build, node(doc, "dd", pair[1]));
    });
    if (snapshot.dirty) append(build, node(doc, "dd", "сборка с незакоммиченными правками", "dirty"));

    var verdict = append(rootNode, node(doc, "section", undefined, "verdict"));
    if (knowledge.linked) {
      append(verdict, node(doc, "p", "d2k наблюдает трафик."));
    } else {
      append(verdict, node(doc, "p", "d2k не смотрит на трафик и ничего не обходит."));
      append(verdict, node(doc, "p", knowledge.link_note || "Контроллер не подключён к датапату.", "why"));
    }

    var stages = Array.isArray(snapshot.stages) ? snapshot.stages : [];
    var chain = append(rootNode, node(doc, "ul", undefined, "chain"));
    stages.forEach(function (stage) {
      var item = append(chain, node(doc, "li", undefined, "stage " + (stage.built ? "built" : "unbuilt")));
      heading(doc, item, 3, stage.title || "Звено обработки");
      append(item, node(doc, "span", stage.built ? "есть" : "не написано", "mark"));
      append(item, node(doc, "p", stage.detail || ""));
    });
    var builtCount = stages.filter(function (stage) { return !!stage.built; }).length;
    append(rootNode, node(doc, "p", "построено " + builtCount + " из " + stages.length + " звеньев обработки", "chain-note"));

    var bands = append(rootNode, node(doc, "div", undefined, "bands"));
    var settings = append(bands, node(doc, "section", undefined, "band"));
    heading(doc, settings, 2, "Что настроено");
    var facts = append(settings, node(doc, "dl", undefined, "facts"));
    [
      ["режим", snapshot.mode || "неизвестен"],
      ["конфигурация", snapshot.config_path || "неизвестна"],
      ["каталог состояния", snapshot.state_dir || "не задан"],
      ["состояние каталога", snapshot.state_dir_note || "неизвестно"],
      ["очередь", snapshot.queue_num === undefined ? "неизвестна" : snapshot.queue_num],
      ["панель", snapshot.panel_listen || "выключена"]
    ].forEach(function (pair) {
      append(facts, node(doc, "dt", pair[0]));
      append(facts, node(doc, "dd", pair[1]));
    });
    if (snapshot.config_exists === false) append(settings, node(doc, "p", "Файла конфигурации нет, действуют умолчания.", "quiet"));
    if (Array.isArray(snapshot.unknown_keys) && snapshot.unknown_keys.length) {
      var unknown = append(settings, node(doc, "p", undefined, "warn"));
      append(unknown, doc.createTextNode("В конфигурации есть ключи, которых эта сборка не знает: "));
      snapshot.unknown_keys.forEach(function (key, index) {
        if (index) append(unknown, doc.createTextNode(", "));
        append(unknown, node(doc, "code", key));
      });
      append(unknown, doc.createTextNode(". Они сохранены: откат на предыдущую версию не должен терять настройки следующей."));
    }

    var absent = append(bands, node(doc, "section", undefined, "band"));
    heading(doc, absent, 2, "Чего панель не показывает и почему");
    var absentList = append(absent, node(doc, "ul", undefined, "absent"));
    (Array.isArray(snapshot.absent) ? snapshot.absent : []).forEach(function (entry) {
      var li = append(absentList, node(doc, "li"));
      append(li, node(doc, "b", entry.title || "Показания отсутствуют"));
      append(li, node(doc, "span", entry.detail || "Причина не указана."));
    });

    var live = append(rootNode, node(doc, "section", undefined, "learned"));
    heading(doc, live, 2, "Сейчас в работе");
    if (!knowledge.linked) {
      append(live, node(doc, "p", "Контроллер не подключён к датапату: " + (knowledge.link_note || "состояние недоступно") + ". Панель показывает прошлое знание, но не происходящее.", "quiet"));
    } else if (Array.isArray(knowledge.searches) && knowledge.searches.length) {
      var hunts = append(live, node(doc, "ul", undefined, "hunt"));
      knowledge.searches.forEach(function (search) {
        var li = append(hunts, node(doc, "li"));
        append(li, node(doc, "span", search.target, "target"));
        append(li, node(doc, "span", search.phase, "phase"));
        var counts = append(li, node(doc, "span", undefined, "counts"));
        append(counts, node(doc, "span", "попыток " + (search.attempts || 0)));
        append(counts, node(doc, "span", "зондов " + (search.probes || 0)));
        if (search.candidate) append(counts, node(doc, "span", "кандидат " + search.candidate));
      });
      append(live, node(doc, "p", "Поиск не записывается. Если он кончится ничем, от него не останется следа — ни в каталоге, ни здесь.", "quiet"));
    } else {
      append(live, node(doc, "p", "Ничего не ищется. Поиск начинается, только когда соединение вызвало подозрение.", "quiet"));
    }

    var learned = append(rootNode, node(doc, "section", undefined, "learned"));
    heading(doc, learned, 2, "Изученные коробки");
    var boxes = Array.isArray(knowledge.boxes) ? knowledge.boxes : [];
    if (!boxes.length) {
      append(learned, node(doc, "p", "Пока ничего не изучено. Это не сбой: база начинается пустой, и запись появляется только вместе с подтверждённым решением.", "quiet"));
    } else {
      var boxList = append(learned, node(doc, "div", undefined, "boxes"));
      boxes.forEach(function (box) { renderBox(doc, boxList, box); });
    }

    append(rootNode, node(doc, "p", "Панель только читает. Изменяющих запросов нет.", "warn"));
    var footer = append(rootNode, node(doc, "footer", undefined, "foot"));
    append(footer, node(doc, "span", "снимок " + (snapshot.taken || "время неизвестно")));
    var api = append(footer, node(doc, "a", "данные: /api/status"));
    api.setAttribute("href", "/api/status");
    rootNode.setAttribute("aria-busy", "false");
  }

  function renderBox(doc, parent, box) {
    var article = append(parent, node(doc, "article", undefined, "box"));
    var head = append(article, node(doc, "header"));
    heading(doc, head, 3, box.id || "коробка без идентификатора");
    if (box.created) append(head, node(doc, "span", "узнана " + box.created, "when"));
    heading(doc, article, 4, "Чем себя выдаёт");
    var signals = append(article, node(doc, "dl", undefined, "print"));
    (Array.isArray(box.signals) ? box.signals : []).forEach(function (signal) {
      append(signals, node(doc, "dt", signal.kind || "примета"));
      var detail = node(doc, "dd");
      append(detail, doc.createTextNode(signal.human || "описание не записано"));
      append(detail, node(doc, "span", " — наблюдалось " + (signal.seen || 0), "seen"));
      append(signals, detail);
    });
    heading(doc, article, 4, "Цели");
    var bindings = append(article, node(doc, "ul", undefined, "targets"));
    (Array.isArray(box.bindings) ? box.bindings : []).forEach(function (binding) {
      var li = append(bindings, node(doc, "li"));
      append(li, node(doc, "span", binding.target || "цель не названа", "name" + (binding.enabled ? "" : " off")));
      var meter = append(li, node(doc, "span", undefined, "rule5"));
      meter.setAttribute("role", "img");
      meter.setAttribute("aria-label", "доказательство: " + (binding.level || 0) + " из 5, " + (binding.level_name || "уровень не определён"));
      for (var i = 0; i < 5; i++) append(meter, node(doc, "i", undefined, i < (binding.level || 0) ? "on" : ""));
      append(li, node(doc, "span", binding.level_name || "уровень не определён", "level"));
      append(li, node(doc, "span", "подтверждений " + (binding.successes || 0), "hits"));
    });
    (Array.isArray(box.plans) ? box.plans : []).forEach(function (plan) {
      var section = append(article, node(doc, "div", undefined, "plan"));
      append(section, node(doc, "p", plan.human || (plan.proto || "план") + ": описание отсутствует", plan.enabled ? "" : "off"));
      var details = append(section, node(doc, "details"));
      append(details, node(doc, "summary", "техническое представление плана " + (plan.id || "без ID")));
      append(details, node(doc, "pre", plan.text || "текст плана отсутствует"));
    });
  }

  async function refresh() {
    var app = root.document.getElementById("app");
    try {
      var response = await root.fetch("/api/status", { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      render(app, await response.json(), root.document);
    } catch (err) {
      app.replaceChildren();
      append(app, node(root.document, "h1", "d2k"));
      append(app, node(root.document, "p", "Не удалось прочитать состояние панели. Обновите страницу; если ошибка повторяется, проверьте журнал d2k-panel.", "warn"));
      app.setAttribute("aria-busy", "false");
    }
  }

  var api = { render: render, renderBox: renderBox, refresh: refresh };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root.document) {
    root.document.addEventListener("DOMContentLoaded", function () {
      refresh();
      root.setInterval(refresh, 5000);
    });
  }
})(typeof window !== "undefined" ? window : globalThis);
