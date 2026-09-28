(function (root) {
  "use strict";

  var currentFilter = "";
  var controlMessage = "";
  var controlInFlight = false;

  function node(doc, tag, text, className) {
    var out = doc.createElement(tag);
    if (text !== undefined && text !== null) out.textContent = String(text);
    if (className) out.className = className;
    return out;
  }

  function append(parent, child) { parent.appendChild(child); return child; }

  function setAttr(element, name, value) {
    element.setAttribute(name, String(value));
    return element;
  }

  function heading(doc, parent, level, text) {
    return append(parent, node(doc, "h" + level, text));
  }

  function section(doc, parent, id, title, note) {
    var out = append(parent, node(doc, "section", undefined, "section-block"));
    setAttr(out, "id", id);
    var head = append(out, node(doc, "div", undefined, "section-heading"));
    heading(doc, head, 2, title);
    if (note) append(head, node(doc, "p", note, "section-note"));
    return out;
  }

  function russianCount(value, one, few, many) {
    var n = Math.abs(Number(value) || 0);
    var last = n % 10, lastTwo = n % 100;
    return n + " " + (last === 1 && lastTwo !== 11 ? one :
      last >= 2 && last <= 4 && (lastTwo < 12 || lastTwo > 14) ? few : many);
  }

  function protocolName(proto) {
    return ({ tls12: "TLS 1.2", tls13: "TLS 1.3", tls: "TLS", quic: "QUIC", stun: "STUN" })[proto] || proto || "Сетевой план";
  }

  function modeName(mode) {
    return ({ off: "Подбор выключен", observe: "Только наблюдение", apply: "Автоматический подбор" })[mode] || "режим не определён";
  }

  function searchPhase(phase) {
    var names = {
      "ждём форму приветствия": "Изучаем особенности соединения",
      "распознаём поведение": "Определяем тип блокировки",
      "спрашиваем коробку о свойствах": "Сравниваем с похожими блокировками",
      "выводим планы": "Подбираем вариант обхода",
      "проверяем готовое узнанной коробки": "Проверяем найденный ранее обход",
      "проверяем выведенный план": "Проверяем новый обход",
      "подтверждено, смотрим живой трафик": "Обход сработал — следим за результатом",
      "цель отдыхает после неудачи": "Повторная проверка будет позже",
      "измеряем живой голосовой поток": "Проверяем качество звонка",
      "приём голоса стоит, ждём разговора": "Ждём начала звонка",
      "приём применился к разговору, ждём ответа сервера": "Проверяем связь во время звонка"
    };
    return names[phase] || "Проверяем обход";
  }

  function safeDate(value) {
    if (!value) return "время не записано";
    var date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("ru-RU", {
      day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
    });
  }

  function metric(doc, parent, number, label, tone) {
    var item = append(parent, node(doc, "div", undefined, "metric" + (tone ? " " + tone : "")));
    append(item, node(doc, "span", number, "metric-value"));
    append(item, node(doc, "span", label, "metric-label"));
    return item;
  }

  function updateChrome(doc, knowledge, snapshot) {
    if (!doc.getElementById) return;
    var linked = !!(knowledge && knowledge.linked) && !(snapshot && snapshot.live_fresh === false) &&
      !(snapshot && snapshot.engine_running === false) &&
      !(snapshot && snapshot.controller_running === false);
    var rail = doc.getElementById("rail-state");
    var updated = doc.getElementById("rail-updated");
    var indicator = doc.getElementById("live-indicator");
    if (rail) rail.textContent = linked ? "D2K на связи" : "D2K не на связи";
    if (updated) updated.textContent = linked ? "обновлено " + safeDate(snapshot && snapshot.taken) : "нет свежих данных";
    if (indicator) {
      indicator.setAttribute("data-state", linked ? "connected" : "disconnected");
      var text = indicator.querySelector && indicator.querySelector("span");
      if (text) text.textContent = linked ? "Обновляется автоматически" : "Связь потеряна";
    }
  }

  function render(rootNode, payload, doc) {
    doc = doc || root.document;
    var active = doc.activeElement && rootNode.contains && rootNode.contains(doc.activeElement)
      ? doc.activeElement : null;
    var focusedId = active ? active.id : "";
    var focusedKey = active && active.getAttribute ? active.getAttribute("data-ui-key") : null;
    var selectionStart = focusedId === "box-filter" ? active.selectionStart : null;
    var selectionEnd = focusedId === "box-filter" ? active.selectionEnd : null;
    var openDetails = Object.create(null);
    if (rootNode.querySelectorAll) {
      Array.prototype.forEach.call(rootNode.querySelectorAll("details[data-ui-key]"), function (item) {
        if (item.open) openDetails[item.getAttribute("data-ui-key")] = true;
      });
    }
    var snapshot = payload && payload.snapshot ? payload.snapshot : {};
    var knowledge = payload && payload.knowledge ? payload.knowledge : {};
    var linked = !!knowledge.linked && snapshot.live_fresh !== false &&
      snapshot.engine_running !== false && snapshot.controller_running !== false;
    var linkNote = snapshot.engine_running === false
      ? "D2K остановлен. Всё, что он уже запомнил, осталось сохранено."
      : (snapshot.controller_running === false
        ? "Служба подбора не запущена. Сохранённые результаты на месте."
        : (snapshot.live_fresh === false
        ? "Давно не было свежих данных. Сохранённые результаты на месте."
        : "Нет связи с D2K. Проверьте, включён ли он на роутере."));
    var stages = Array.isArray(snapshot.stages) ? snapshot.stages : [];
    var boxes = Array.isArray(knowledge.boxes) ? knowledge.boxes : [];
    var searches = Array.isArray(knowledge.searches) ? knowledge.searches : [];
    rootNode.replaceChildren();

    var title = append(rootNode, node(doc, "header", undefined, "page-heading"));
    var titleCopy = append(title, node(doc, "div"));
    append(titleCopy, node(doc, "p", "D2K · помощник вашего роутера", "overline"));
    heading(doc, titleCopy, 1, "Ваш интернет под присмотром");
    append(titleCopy, node(doc, "p", "Если сайт не открывается, D2K попробует найти обход и запомнит, что сработало.", "page-intro"));
    append(title, node(doc, "span", "Обновлено " + safeDate(snapshot.taken), "updated-at"));

    var hero = append(rootNode, node(doc, "section", undefined, "hero" + (linked ? " connected" : " disconnected")));
    setAttr(hero, "id", "overview");
    var heroCopy = append(hero, node(doc, "div", undefined, "hero-copy"));
    var state = append(heroCopy, node(doc, "span", undefined, "state-label"));
    append(state, node(doc, "i", undefined, "state-dot"));
    append(state, node(doc, "span", linked ? "D2K на связи" : "D2K не на связи"));
    heading(doc, heroCopy, 2, linked ? "D2K подключён" : "D2K пока не подключён");
    append(heroCopy, node(doc, "p", linked
      ? (snapshot.mode === "apply"
        ? "Если что-то заблокировано, D2K подберёт обход и запомнит его."
        : (snapshot.mode === "observe"
          ? "Сейчас D2K только наблюдает. Для подбора обходов включите автоматический режим."
          : "Подбор выключен. Ранее найденные обходы остаются сохранёнными."))
      : linkNote, "hero-description"));
    var heroFoot = append(heroCopy, node(doc, "div", undefined, "hero-foot"));
    append(heroFoot, node(doc, "span", modeName(snapshot.mode), "mode-tag"));
    append(heroFoot, node(doc, "span", "Обновляется каждые 5 секунд", "poll-note"));
    var mascot = node(doc, "img", undefined, "mascot");
    mascot.setAttribute("src", "/assets/mascot-d2k.png");
    mascot.setAttribute("alt", "Зонд — маскот D2K, разведчик сетевого сигнала");
    mascot.setAttribute("width", "196");
    mascot.setAttribute("height", "196");
    append(hero, mascot);

    var metrics = append(rootNode, node(doc, "div", undefined, "metrics"));
    metric(doc, metrics, snapshot.catalog_available === false ? "—" : russianCount(knowledge.targets, "результат", "результата", "результатов"),
      snapshot.catalog_available === false ? "результаты недоступны" : "сохранено на роутере", "metric-blue");
    metric(doc, metrics, linked
      ? russianCount(knowledge.confirms, "подтверждение", "подтверждения", "подтверждений") : "—",
      linked ? "обходы проверены" : "нет свежих данных", "metric-mint");
    metric(doc, metrics, linked
      ? russianCount(searches.length, "поиск", "поиска", "поисков") : "—",
      linked ? "D2K проверяет сейчас" : "статус неизвестен", searches.length && linked ? "metric-amber" : "");
    metric(doc, metrics, snapshot.catalog_available === false ? "—" : String(boxes.length),
      snapshot.catalog_available === false ? "результаты недоступны" : "типов блокировки", "");
    append(rootNode, node(doc, "p", snapshot.catalog_available === false
      ? "Сохранённые результаты пока недоступны. Это не значит, что D2K ничего не находил."
      : "Найденное хранится на роутере и используется повторно.", "metric-footnote"));

    var searchSection = section(doc, rootNode, "searches", "Подбор сейчас",
      "Здесь видны сайты, которые D2K проверяет в эту минуту.");
    if (!linked) {
      append(searchSection, node(doc, "p", "Не могу проверить, идёт ли сейчас подбор: D2K не на связи.", "empty-state empty-warning"));
    } else if (!searches.length) {
      var calm = append(searchSection, node(doc, "div", undefined, "empty-state"));
      append(calm, node(doc, "span", "○", "empty-mark"));
      var calmCopy = append(calm, node(doc, "div"));
      heading(doc, calmCopy, 3, "Сейчас всё спокойно");
      append(calmCopy, node(doc, "p", "Когда D2K заметит блокировку, проверка появится здесь автоматически."));
    } else {
      var list = append(searchSection, node(doc, "div", undefined, "search-list"));
      searches.forEach(function (search) { renderSearch(doc, list, search); });
    }

    var boxSection = section(doc, rootNode, "boxes", "Изученные коробки",
      "Рабочие обходы сохраняются и повторно проверяются для похожих блокировок.");
    var boxToolbar = append(boxSection, node(doc, "div", undefined, "box-toolbar"));
    var filterLabel = append(boxToolbar, node(doc, "label", "Найти сайт или результат", "filter-label"));
    var filter = append(filterLabel, node(doc, "input", undefined, "box-filter"));
    filter.setAttribute("id", "box-filter");
    filter.setAttribute("type", "search");
    filter.setAttribute("placeholder", "Например, youtube.com");
    filter.setAttribute("autocomplete", "off");
    filter.setAttribute("aria-label", "Поиск по сайту или типу блокировки");
    filter.value = currentFilter;
    append(boxToolbar, node(doc, "span", snapshot.catalog_available === false
      ? "результаты недоступны" : russianCount(boxes.length, "тип блокировки", "типа блокировки", "типов блокировки"), "box-total"));
    if (!boxes.length) {
      append(boxSection, node(doc, "p", snapshot.catalog_available === false
        ? "Сохранённые результаты сейчас недоступны."
        : "Пока нет сохранённых обходов. D2K добавит результат, когда проверит, что он работает.",
        snapshot.catalog_available === false ? "empty-state empty-warning" : "empty-state"));
    } else {
      var boxList = append(boxSection, node(doc, "div", undefined, "box-list"));
      boxes.forEach(function (box, index) { renderBox(doc, boxList, box, index); });
      filterBoxes(rootNode, currentFilter);
      if (rootNode.addEventListener && !rootNode.__d2kFilterBound) {
        rootNode.__d2kFilterBound = true;
        rootNode.addEventListener("input", function (event) {
          if (!event.target || event.target.id !== "box-filter") return;
          currentFilter = event.target.value;
          filterBoxes(rootNode, event.target.value);
        });
      }
      if (rootNode.addEventListener && !rootNode.__d2kCopyBound) {
        rootNode.__d2kCopyBound = true;
        rootNode.addEventListener("click", function (event) {
          var button = event.target && event.target.closest ? event.target.closest("[data-copy]") : null;
          if (!button) return;
          var value = button.getAttribute("data-copy");
          copyValue(doc, value).then(function (ok) {
            if (!ok) return;
            var old = button.textContent;
            button.textContent = "Скопировано";
            root.setTimeout(function () { button.textContent = old; }, 1400);
          });
        });
      }
    }

    var diagnostics = append(rootNode, node(doc, "details", undefined, "diagnostics"));
    setAttr(diagnostics, "id", "diagnostics");
    setAttr(diagnostics, "data-ui-key", "diagnostics");
    append(diagnostics, node(doc, "summary", "Технические сведения для диагностики"));
    var system = section(doc, diagnostics, "system", "Как устроена работа D2K",
      "Сведения о подключении, настройках и доступных измерениях.");
    var stageList = append(system, node(doc, "div", undefined, "stage-list"));
    stages.forEach(function (stage) {
      var row = append(stageList, node(doc, "article", undefined, "stage-row" + (stage.built ? " stage-present" : " stage-absent")));
      var icon = append(row, node(doc, "span", stage.built ? "✓" : "—", "stage-icon"));
      icon.setAttribute("aria-hidden", "true");
      var text = append(row, node(doc, "div", undefined, "stage-copy"));
      heading(doc, text, 3, stage.title || "Звено обработки");
      append(text, node(doc, "p", stage.detail || "Сведения отсутствуют."));
      append(row, node(doc, "span", stage.built ? "доступно" : "не подтверждено", "stage-state"));
    });
    var facts = append(system, node(doc, "dl", undefined, "system-facts"));
    [
      ["Режим", snapshot.mode || "неизвестен"], ["Версия", snapshot.version || "неизвестна"],
      ["Коммит", snapshot.commit ? String(snapshot.commit).slice(0, 12) : "неизвестен"],
      ["Конфигурация", snapshot.config_path || "неизвестна"], ["Очередь", snapshot.queue_num === undefined ? "неизвестна" : snapshot.queue_num],
      ["Панель", snapshot.panel_listen || "неизвестна"], ["Каталог состояния", snapshot.state_dir || "неизвестен"],
      ["Состояние каталога", snapshot.state_dir_note || "неизвестно"]
    ].forEach(function (pair) {
      append(facts, node(doc, "dt", pair[0]));
      append(facts, node(doc, "dd", pair[1]));
    });
    if (snapshot.dirty) append(system, node(doc, "p", "Эта сборка создана с незакоммиченными изменениями.", "notice notice-amber"));
    if (snapshot.config_exists === false) append(system, node(doc, "p", "Файла конфигурации нет, действуют значения по умолчанию.", "notice"));
    if (Array.isArray(snapshot.unknown_keys) && snapshot.unknown_keys.length) {
      var unknown = append(system, node(doc, "p", undefined, "notice notice-amber"));
      append(unknown, doc.createTextNode("Незнакомые этой сборке параметры сохранены: "));
      snapshot.unknown_keys.forEach(function (key, index) {
        if (index) append(unknown, doc.createTextNode(", "));
        append(unknown, node(doc, "code", key));
      });
    }
    if (Array.isArray(snapshot.absent) && snapshot.absent.length) {
      var absent = append(system, node(doc, "div", undefined, "not-measured"));
      heading(doc, absent, 3, "Чего панель не измеряет");
      snapshot.absent.forEach(function (item) {
        var row = append(absent, node(doc, "p"));
        append(row, node(doc, "b", item.title || "Нет измерения"));
        append(row, doc.createTextNode(" — " + (item.detail || "Причина не указана.")));
      });
    }
    if (!linked && snapshot.catalog_available !== false) append(system, node(doc, "p", "Каталог ниже отображает последнее сохранённое знание; живые события сейчас недоступны.", "notice notice-amber"));
    if (linked) append(system, node(doc, "p", "Зондов использовано: " + (knowledge.probes_used || 0) +
      " · неподходящих применений к клиенту: " + (knowledge.client_unfit || 0), "notice"));
    var api = append(system, node(doc, "a", "Открыть данные для поддержки"));
    api.setAttribute("href", "/api/status");
    var controls = section(doc, rootNode, "controls", "Управление D2K",
      "Остановка подбора не удаляет уже сохранённые результаты.");
    append(controls, node(doc, "p", snapshot.controls_enabled
      ? (snapshot.mode === "off"
        ? "Подбор выключен в настройках. Включите его там, чтобы D2K снова искал обходы."
        : "Эти действия управляют D2K на роутере. Найденные результаты останутся сохранены.")
      : "Управление доступно только на самом роутере.", "control-note"));
    var controlButtons = append(controls, node(doc, "div", undefined, "control-buttons"));
    [
      ["start", "Включить подбор", "button-primary"],
      ["stop", "Приостановить", "button-danger"],
      ["restart", "Перезапустить D2K", "button-quiet"],
      ["reapply", "Восстановить подключение", "button-quiet"],
    ].forEach(function (item) {
      var button = append(controlButtons, node(doc, "button", item[1], "control-button " + item[2]));
      button.setAttribute("type", "button");
      button.setAttribute("data-control", item[0]);
      button.disabled = !snapshot.controls_enabled || controlInFlight ||
        ((item[0] === "start" || item[0] === "restart") && snapshot.mode === "off");
    });
    var result = append(controls, node(doc, "p", controlMessage, "control-result"));
    result.setAttribute("id", "control-result");
    if (rootNode.addEventListener && !rootNode.__d2kControlBound) {
      rootNode.__d2kControlBound = true;
      rootNode.addEventListener("click", function (event) {
        var button = event.target && event.target.closest ? event.target.closest("[data-control]") : null;
        if (!button || button.disabled) return;
        var action = button.getAttribute("data-control");
        if ((action === "stop" || action === "restart") && root.confirm &&
            !root.confirm(action === "stop" ? "Приостановить подбор? Сохранённые результаты останутся на месте." : "Перезапустить D2K? Текущие соединения могут на короткое время переключиться на прямое подключение.")) return;
        runControl(action, button, doc);
      });
    }
    var footer = append(rootNode, node(doc, "footer", undefined, "page-footer"));
    append(footer, node(doc, "span", "D2K · работает на вашем роутере"));
    append(footer, node(doc, "span", "Ваши результаты остаются на роутере"));
    updateChrome(doc, knowledge, snapshot);
    if (rootNode.querySelectorAll) {
      Array.prototype.forEach.call(rootNode.querySelectorAll("details[data-ui-key]"), function (item) {
        item.open = !!openDetails[item.getAttribute("data-ui-key")];
      });
      if (focusedKey) {
        Array.prototype.forEach.call(rootNode.querySelectorAll("[data-ui-key]"), function (item) {
          if (item.getAttribute("data-ui-key") === focusedKey && item.focus) item.focus();
        });
      }
    }
    if (focusedId === "box-filter" && filter.focus) {
      filter.focus();
      if (selectionStart !== null && filter.setSelectionRange) filter.setSelectionRange(selectionStart, selectionEnd);
    }
    rootNode.setAttribute("aria-busy", "false");
  }

  function renderSearch(doc, parent, search) {
    var card = append(parent, node(doc, "article", undefined, "search-item"));
    var top = append(card, node(doc, "div", undefined, "search-top"));
    append(top, node(doc, "strong", search.target || "цель без имени", "search-target"));
    append(top, node(doc, "span", searchPhase(search.phase), "phase-tag"));
    var meta = append(card, node(doc, "div", undefined, "search-meta"));
    append(meta, node(doc, "span", "Начато " + safeDate(search.since)));
    var counts = append(card, node(doc, "div", undefined, "search-counts"));
    append(counts, node(doc, "span", "Проверено вариантов: " + (search.attempts || 0)));
    var detail = append(card, node(doc, "details", undefined, "search-detail"));
    setAttr(detail, "data-ui-key", "search:" + (search.target || "unnamed"));
    append(detail, node(doc, "summary", "Подробности проверки"));
    append(detail, node(doc, "p", "Исходный сигнал: " + (search.source || "не указан")));
    append(detail, node(doc, "p", "Текущий этап: " + (search.phase || "не указан")));
    append(detail, node(doc, "p", "Зондов отправлено: " + (search.probes || 0)));
    if (search.candidate) append(detail, node(doc, "p", "Текущий вариант: " + search.candidate));
  }

  function renderBox(doc, parent, box, index) {
    var article = append(parent, node(doc, "article", undefined, "box-item"));
    var head = append(article, node(doc, "header", undefined, "box-header"));
    var identity = append(head, node(doc, "div"));
    heading(doc, identity, 3, "Тип блокировки " + (index + 1));
    append(identity, node(doc, "span", "Сохранено " + safeDate(box.created), "box-created"));
    var supportDetails = append(article, node(doc, "details", undefined, "box-support-detail"));
    setAttr(supportDetails, "data-ui-key", "support:" + (box.id || index));
    append(supportDetails, node(doc, "summary", "Для диагностики"));
    append(supportDetails, node(doc, "code", "Внутренний код: " + (box.id || "не записан")));
    var activeCount = (Array.isArray(box.bindings) ? box.bindings : []).filter(function (b) { return b.enabled; }).length;
    append(head, node(doc, "span", russianCount(activeCount, "результат", "результата", "результатов"), "box-badge"));
    var signals = Array.isArray(box.signals) ? box.signals : [];
    if (signals.length) {
      var signalDetails = append(article, node(doc, "details", undefined, "signal-detail"));
      setAttr(signalDetails, "data-ui-key", "signals:" + (box.id || index));
      append(signalDetails, node(doc, "summary", "Как D2K распознал эту блокировку"));
      var signalList = append(signalDetails, node(doc, "div", undefined, "signal-list"));
      signals.forEach(function (signal) {
      var signalRow = append(signalList, node(doc, "div", undefined, "signal-row"));
      append(signalRow, node(doc, "span", signal.kind || "примета", "signal-kind"));
      append(signalRow, node(doc, "span", signal.human || "Описание не записано."));
      append(signalRow, node(doc, "span", "×" + (signal.seen || 0), "signal-seen"));
      });
    }
    var targets = append(article, node(doc, "div", undefined, "target-list"));
    heading(doc, targets, 4, "Адреса и обходы");
    (Array.isArray(box.bindings) ? box.bindings : []).forEach(function (binding) {
      var row = append(targets, node(doc, "div", undefined, "target-row" + (binding.enabled ? "" : " target-disabled")));
      var target = append(row, node(doc, "div", undefined, "target-identity"));
      append(target, node(doc, "strong", binding.target || "цель не названа", "target-name"));
      append(target, node(doc, "span", binding.kind || "сетевой поток", "target-kind"));
      var evidence = append(row, node(doc, "div", undefined, "evidence"));
      var meter = append(evidence, node(doc, "span", undefined, "evidence-meter"));
      meter.setAttribute("role", "img");
      meter.setAttribute("aria-label", "уровень доказательства " + (binding.level || 0) + " из 5: " + (binding.level_name || "неизвестен"));
      for (var i = 0; i < 5; i++) append(meter, node(doc, "i", undefined, i < (binding.level || 0) ? "filled" : ""));
      append(evidence, node(doc, "span", binding.level_name || "уровень не определён", "evidence-label"));
      var successes = append(row, node(doc, "span", (binding.successes || 0) + " подтверждений", "target-successes"));
      var copy = append(row, node(doc, "button", "Копировать", "copy-button"));
      copy.setAttribute("type", "button");
      copy.setAttribute("data-copy", binding.target || "");
      copy.setAttribute("data-ui-key", "copy:" + (binding.target || ""));
      copy.setAttribute("aria-label", "Скопировать адрес " + (binding.target || ""));
      void successes;
    });
    (Array.isArray(box.plans) ? box.plans : []).forEach(function (plan, index) {
      var planKey = "plan:" + (box.id || "") + ":" + index;
      var detail = append(article, node(doc, "details", undefined, "plan-detail"));
      detail.setAttribute("data-ui-key", planKey);
      var summary = append(detail, node(doc, "summary"));
      summary.setAttribute("data-ui-key", "summary:" + planKey);
      append(summary, node(doc, "span", protocolName(plan.proto), "protocol-tag"));
      append(summary, doc.createTextNode(plan.enabled ? "Проверенный обход" : "Обход отключён"));
      if (plan.human) append(detail, node(doc, "p", plan.human, "plan-human"));
      var technical = append(detail, node(doc, "details", undefined, "technical-detail"));
      technical.setAttribute("data-ui-key", "technical:" + (box.id || "") + ":" + index);
      var technicalSummary = append(technical, node(doc, "summary", "Технические данные"));
      technicalSummary.setAttribute("data-ui-key", "technical-summary:" + (box.id || "") + ":" + index);
      append(technical, node(doc, "pre", plan.text || "План не записан."));
    });
    if (!signals.length) append(article, node(doc, "p", "D2K пока не записал признаки этой блокировки.", "quiet"));
  }

  function filterBoxes(rootNode, query) {
    var term = String(query || "").trim().toLocaleLowerCase("ru-RU");
    var list = rootNode.querySelectorAll ? rootNode.querySelectorAll(".box-item") : [];
    Array.prototype.forEach.call(list, function (item) {
      item.hidden = !!term && !item.textContent.toLocaleLowerCase("ru-RU").includes(term);
    });
  }

  function copyValue(doc, value) {
    if (root.navigator && root.navigator.clipboard && root.navigator.clipboard.writeText) {
      return root.navigator.clipboard.writeText(value).then(function () { return true; }).catch(function () { return false; });
    }
    if (!doc.body || !doc.execCommand) return Promise.resolve(false);
    var field = doc.createElement("textarea");
    field.value = value;
    field.setAttribute("readonly", "");
    field.setAttribute("aria-hidden", "true");
    field.style.position = "fixed";
    field.style.opacity = "0";
    doc.body.appendChild(field);
    field.select();
    var copied = false;
    try { copied = doc.execCommand("copy"); } catch (err) { copied = false; }
    doc.body.removeChild(field);
    return Promise.resolve(!!copied);
  }

  async function runControl(action, button, doc) {
    var result = doc.getElementById("control-result");
    controlInFlight = true;
    button.disabled = true;
    controlMessage = "Выполняется команда службы…";
    if (result) result.textContent = controlMessage;
    try {
      var response = await root.fetch("/api/control/" + encodeURIComponent(action), {
        method: "POST", cache: "no-store",
      });
      var payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.message || ("HTTP " + response.status));
      controlMessage = payload.message || "Команда выполнена.";
    } catch (err) {
      controlMessage = "Не выполнено: " + (err && err.message ? err.message : "ошибка связи с панелью");
    } finally {
      controlInFlight = false;
      await refresh();
      button.disabled = false;
    }
  }

  async function refresh() {
    var app = root.document.getElementById("app");
    try {
      var response = await root.fetch("/api/status", { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      render(app, await response.json(), root.document);
    } catch (err) {
      app.replaceChildren();
      var warning = node(root.document, "section", undefined, "connection-error");
      append(warning, node(root.document, "span", "×", "error-mark"));
      heading(root.document, warning, 1, "Не удалось получить состояние");
      append(warning, node(root.document, "p", "Проверьте журнал d2kpanel и доступность локального процесса. Последнее состояние не подменяется нулями."));
      app.appendChild(warning);
      app.setAttribute("aria-busy", "false");
      var indicator = root.document.getElementById("live-indicator");
      if (indicator) {
        indicator.setAttribute("data-state", "disconnected");
        var label = indicator.querySelector && indicator.querySelector("span");
        if (label) label.textContent = "Панель недоступна";
      }
      var rail = root.document.getElementById("rail-state");
      var updated = root.document.getElementById("rail-updated");
      if (rail) rail.textContent = "Нет связи с панелью";
      if (updated) updated.textContent = "состояние неизвестно";
    }
  }

  var api = { render: render, renderBox: renderBox, renderSearch: renderSearch, filterBoxes: filterBoxes, refresh: refresh };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root.document) {
    root.document.addEventListener("DOMContentLoaded", function () {
      refresh();
      root.setInterval(refresh, 5000);
    });
    root.addEventListener("hashchange", function () {
      var current = root.location.hash || "#overview";
      var links = root.document.querySelectorAll(".nav-link");
      Array.prototype.forEach.call(links, function (link) {
        if (link.getAttribute("href") === current) link.classList.add("active");
        else link.classList.remove("active");
      });
    });
  }
})(typeof window !== "undefined" ? window : globalThis);
