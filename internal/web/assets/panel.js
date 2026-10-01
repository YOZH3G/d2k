(function (root) {
  "use strict";

  var currentFilter = "";
  var controlMessage = "";
  var controlInFlight = false;
  var refreshInFlight = false;
  var refreshTimer = null;
  var refreshAbort = null;
  var selectedSlide = "";

  function arrangeSlides(cards) {
    var index = cards.findIndex(function (card) { return card.getAttribute("data-slide-key") === selectedSlide; });
    if (index < 0) index = Math.min(1, cards.length - 1);
    if (index >= 0) selectedSlide = cards[index].getAttribute("data-slide-key");
    cards.forEach(function (card, i) {
      var slot = i === index ? "center" :
        i === (index - 1 + cards.length) % cards.length ? "left" :
        i === (index + 1) % cards.length ? "right" : "hidden";
      card.setAttribute("data-slot", slot);
      card.setAttribute("data-selected", i === index ? "true" : "false");
      card.inert = slot === "hidden";
      var button = card.querySelector && card.querySelector("[data-select-slide]");
      if (button) {
        button.setAttribute("aria-pressed", i === index ? "true" : "false");
        button.querySelector(".slide-number").textContent = String(i + 1).padStart(2, "0");
        button.querySelector(".slide-label").textContent = i === index ? "Выбранный подбор" : "Подбор";
      }
    });
  }

  function transferSlide(card, rootNode, doc) {
    if (!doc.body || !card.cloneNode || !card.getBoundingClientRect) return;
    var source = JSON.parse(card.getAttribute("data-slide-key"));
    var target = Array.prototype.find.call(rootNode.querySelectorAll("[data-family-context]"), function (item) {
      var family = JSON.parse(item.getAttribute("data-family-context"));
      return (source[0] === family[0] || source[0].endsWith("." + family[0])) &&
        source[1] === family[1] && source[2] === family[2] && source[3] === family[3] &&
        source[5] === family[4] && source[6] === family[5] && !family[6].includes(source[0]);
    });
    if (!target) return;
    var from = card.getBoundingClientRect(), to = target.getBoundingClientRect();
    if (to.top >= root.innerHeight || to.bottom <= 0 || to.left >= root.innerWidth ||
        to.right <= 0 || !to.width || from.bottom <= 0) return;
    var ghost = card.cloneNode(true);
    ghost.removeAttribute("data-motion");
    ghost.setAttribute("aria-hidden", "true");
    ghost.inert = true;
    Object.assign(ghost.style, { position:"fixed", left:from.left+"px", top:from.top+"px",
      width:from.width+"px", height:from.height+"px", minHeight:"0", margin:"0",
      zIndex:"25", pointerEvents:"none", transformOrigin:"top left", transition:"none" });
    doc.body.appendChild(ghost);
    var flight = ghost.animate([
      {transform:"translate(0,0) scale(1)",opacity:.9},
      {transform:"translate("+(to.left-from.left)+"px,"+(to.top-from.top)+"px) scale("+(to.width/from.width)+","+(to.height/from.height)+")",opacity:0}
    ], {duration:660,easing:"cubic-bezier(.22,.7,.2,1)"});
    var remove = function () { ghost.remove(); };
    flight.onfinish = remove;
    flight.oncancel = remove;
  }

  function slideEvents(previous, current) {
    if (!previous) return [];
    var stages = new Map(previous.map(function (item) { return [item.key, item.stage]; }));
    return current.reduce(function (events, item) {
      if (!stages.has(item.key)) events.push({ key: item.key, kind: "arrive" });
      else if (stages.get(item.key) !== item.stage) {
        events.push({ key: item.key, kind: item.stage === "confirmed" ? "confirm" : "advance" });
      }
      return events;
    }, []);
  }

  function animateSlides(rootNode, doc) {
    if (!rootNode.querySelectorAll) return;
    var cards = Array.prototype.slice.call(rootNode.querySelectorAll("[data-slide-key]"));
    var current = cards.map(function (card) {
      return { key: card.getAttribute("data-slide-key"), stage: card.getAttribute("data-slide-stage") };
    });
    arrangeSlides(cards);
    if (rootNode.addEventListener && !rootNode.__slideSelectBound) {
      rootNode.__slideSelectBound = true;
      rootNode.addEventListener("click", function (event) {
        var button = event.target && event.target.closest && event.target.closest("[data-select-slide]");
        var step = event.target && event.target.closest && event.target.closest("[data-slide-step]");
        if (!button && !step) return;
        var all = Array.prototype.slice.call(rootNode.querySelectorAll("[data-slide-key]"));
        var oldIndex = all.findIndex(function (card) { return card.getAttribute("data-slide-key") === selectedSlide; });
        selectedSlide = button ? button.getAttribute("data-select-slide") :
          all[(oldIndex + Number(step.getAttribute("data-slide-step")) + all.length) % all.length].getAttribute("data-slide-key");
        arrangeSlides(all);
        var reduced = root.matchMedia && root.matchMedia("(prefers-reduced-motion: reduce)").matches;
        var chosen = all.find(function (card) { return card.getAttribute("data-slide-key") === selectedSlide; });
        if (chosen && chosen.animate && !reduced) chosen.animate([
          {transform:"translateY(18px)",filter:"brightness(.88)"},
          {transform:"translateY(-4px)",filter:"brightness(1.04)",offset:.7},
          {transform:"translateY(0)",filter:"brightness(1)"}
        ],{duration:520,easing:"cubic-bezier(.16,1,.3,1)"});
      });
    }
    var events = slideEvents(rootNode.__slideSnapshot, current);
    rootNode.__slideSnapshot = current;
    if (doc.hidden) return;
    var reduced = root.matchMedia && root.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var byKey = new Map(cards.map(function (card) { return [card.getAttribute("data-slide-key"), card]; }));
    events.forEach(function (event) {
      var card = byKey.get(event.key);
      if (!card || !card.animate || card.getAttribute("data-slot") === "hidden") return;
      card.setAttribute("data-motion", event.kind);
      if (reduced) {
        card.animate([{ opacity: .72 }, { opacity: 1 }], { duration: 120 });
        return;
      }
      if (event.kind === "confirm") transferSlide(card, rootNode, doc);
      var frames = event.kind === "arrive"
        ? [{ transform: "perspective(1100px) translateY(36px) rotateX(8deg)", opacity: .45 },
           { transform: "perspective(1100px) translateY(0) rotateX(0)", opacity: 1 }]
        : event.kind === "confirm"
        ? [{ transform: "translateY(0)", filter: "brightness(1)" },
           { transform: "translateY(-14px)", filter: "brightness(1.16)", offset: .35 },
           { transform: "translateY(0)", filter: "brightness(1)" }]
        : [{ filter: "brightness(1)" }, { filter: "brightness(1.2)", offset: .3 }, { filter: "brightness(1)" }];
      card.animate(frames, { duration: event.kind === "confirm" ? 620 : 440,
        easing: "cubic-bezier(.16,1,.3,1)" });
    });
  }

  async function requestJSON(url, options, timeout) {
    var controller = new root.AbortController();
    var timer = root.setTimeout(function () { controller.abort(); }, timeout);
    options.signal = controller.signal;
    try {
      var response = await root.fetch(url, options);
      var payload = await response.json();
      if (!response.ok) throw new Error(payload.message || ("HTTP " + response.status));
      return payload;
    } finally { root.clearTimeout(timer); }
  }

  function node(doc, tag, text, className) {
    var out = doc.createElement(tag);
    if (text !== undefined && text !== null) out.textContent = String(text);
    if (className) out.className = className;
    return out;
  }

  function append(parent, child) { parent.appendChild(child); return child; }

  function icon(doc, kind) {
    if (!doc.createElementNS) return node(doc, "span", undefined, "ui-icon");
    var svg = doc.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("class", "ui-icon");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.7");
    var paths = {
      document:"M5 2h14v20H5z M8 7h8 M8 12h8 M8 17h6",
      arrow:"M4 12h16 M14 6l6 6-6 6",
      start:"M7 4l13 8-13 8z",
      stop:"M5 5h14v14H5z",
      restart:"M20 9a8 8 0 1 0 0 6 M20 3v6h-6",
      reapply:"M8 8l-3 4 3 4 M16 8l3 4-3 4 M14 4l-4 16",
      power:"M12 2v10 M6 5a9 9 0 1 0 12 0",
      confirmed:"M8 12l3 3 5-6",
      check:"M5 12l4 4L19 6",
      minus:"M5 12h14",
      error:"M6 6l12 12 M18 6 6 18",
      telegram:"M2 10 22 2l-5 20-6-7-5 3 1-7z M7 11 22 2 M11 15 22 2"
    };
    var path = doc.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", paths[kind] || paths.document);
    if (kind === "stop") path.setAttribute("fill", "currentColor");
    if (kind === "restart" || kind === "power") svg.setAttribute("stroke-width", "2.7");
    if (kind === "confirmed") {
      var circle = doc.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", "12"); circle.setAttribute("cy", "12"); circle.setAttribute("r", "11");
      circle.setAttribute("fill", "currentColor"); circle.setAttribute("stroke", "none");
      svg.appendChild(circle);
      path.setAttribute("stroke", "var(--glass)");
      path.setAttribute("stroke-width", "2.5");
    }
    svg.appendChild(path);
    return svg;
  }

  function syncControls(current, next) {
    if (current.nodeType === 3) {
      if (current.nodeValue !== next.nodeValue) current.nodeValue = next.nodeValue;
      return;
    }
    Array.prototype.slice.call(current.attributes).forEach(function (attribute) {
      if (!next.hasAttribute(attribute.name)) current.removeAttribute(attribute.name);
    });
    Array.prototype.forEach.call(next.attributes, function (attribute) {
      if (current.getAttribute(attribute.name) !== attribute.value) current.setAttribute(attribute.name, attribute.value);
    });
    Array.prototype.forEach.call(next.childNodes, function (child, index) {
      var existing = current.childNodes[index];
      if (!existing) current.appendChild(child.cloneNode(true));
      else if (existing.nodeType !== child.nodeType || existing.nodeName !== child.nodeName) {
        current.replaceChild(child.cloneNode(true), existing);
      } else syncControls(existing, child);
    });
    while (current.childNodes.length > next.childNodes.length) current.lastChild.remove();
  }

  function clearContent(rootNode) {
    var controls = rootNode.querySelector && rootNode.querySelector("#controls");
    if (!controls) { rootNode.replaceChildren(); return null; }
    Array.prototype.slice.call(rootNode.childNodes).forEach(function (child) {
      if (child !== controls) child.remove();
    });
    return controls;
  }

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
      "распознаём поведение": "Изучаем соединение",
      "спрашиваем коробку о свойствах": "Сравниваем с похожими блокировками",
      "выводим планы": "Подбираем вариант обхода",
      "проверяем готовое узнанной коробки": "Проверяем найденный ранее обход",
      "проверяем выведенный план": "Проверяем обход",
      "подтверждено, смотрим живой трафик": "Подтверждено",
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
    if (rail) {
      rail.textContent = linked ? "D2K на связи" : "D2K не на связи";
      rail.setAttribute("data-connected", linked ? "true" : "false");
    }
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
    var serverControlBusy = snapshot.control_state === "running";
    if (snapshot.control_state && snapshot.control_state !== "idle") {
      controlMessage = ({ running: "Выполняется команда службы…", done: "Команда выполнена.",
        failed: "Команда завершилась ошибкой. Проверьте журнал панели.",
        timeout: "Команда не завершилась вовремя и остановлена. Проверьте состояние служб." })[snapshot.control_state] || controlMessage;
    }
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
    var groups = Array.isArray(knowledge.groups) ? knowledge.groups.filter(function (g) {
      return g && typeof g.suffix === "string" && g.suffix;
    }) : [];
    var stableControls = clearContent(rootNode);

    var title = append(rootNode, node(doc, "header", undefined, "page-heading"));
    var titleCopy = append(title, node(doc, "div"));
    heading(doc, titleCopy, 1, "Замер. План. Результат.");
    append(titleCopy, node(doc, "p", "Автоматический подбор рабочих решений для доступа к нужным сайтам.", "page-intro"));
    append(title, node(doc, "span", (snapshot.preview ? "Демонстрационные данные · " : "Обновлено ") + safeDate(snapshot.taken), "updated-at"));

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
    var rackCaption = append(searchSection, node(doc, "aside", undefined, "rack-caption"));
    heading(doc, rackCaption, 2, "Одним подбором больше свободы");
    append(rackCaption, node(doc, "p", "Реальные замеры. Найденные решения. Автоматическое применение."));
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
      if (searches.length > 1) {
        var pager = append(searchSection, node(doc, "div", undefined, "slide-pager"));
        [["-1","Предыдущий"],["1","Следующий"]].forEach(function (entry) {
          var button = append(pager, node(doc, "button"));
          append(button, icon(doc, "arrow"));
          setAttr(button, "type", "button");
          setAttr(button, "aria-label", entry[1] + " подбор");
          setAttr(button, "title", entry[1] + " подбор");
          setAttr(button, "data-slide-step", entry[0]);
          setAttr(button, "data-ui-key", "slide-step:" + entry[0]);
        });
      }
    }

    if (groups.length) {
      var families = section(doc, rootNode, "families", "Сохранённые семейства",
        "Новые адреса используют найденное решение");
      var familyList = append(families, node(doc, "div", undefined, "family-list"));
      groups.forEach(function (group, index) {
        renderFamily(doc, familyList, group, linked, index);
      });
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
        : groups.length ? "Обходы объединены в семейства выше. Точные решения вне семейств появятся здесь."
        : "Пока нет сохранённых обходов. D2K добавит результат, когда проверит, что он работает.",
        snapshot.catalog_available === false ? "empty-state empty-warning" : "empty-state"));
    } else {
      var boxList = append(boxSection, node(doc, "div", undefined, "box-list"));
      boxes.forEach(function (box, index) { renderBox(doc, boxList, box, index, groups); });
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
      var stageIcon = append(row, icon(doc, stage.built ? "check" : "minus"));
      stageIcon.setAttribute("class", "ui-icon stage-icon");
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
    var controls = section(doc, stableControls ? node(doc, "div") : rootNode, "controls", "Управление D2K",
      "Остановка подбора не удаляет уже сохранённые результаты.");
    var tgStatusNames = {
      not_configured: "Не настроен", stopped: "Выключен",
      connecting: "Подключается", connected: "Работает"
    };
    var tgCard = append(controls, node(doc, "div", undefined, "telegram-control"));
    var tgCopy = append(tgCard, node(doc, "div", undefined, "telegram-copy"));
    var tgTitle = append(tgCopy, node(doc, "strong"));
    append(tgTitle, icon(doc, "telegram"));
    append(tgTitle, node(doc, "span", "Telegram-туннель"));
    var tgState = append(tgCopy, node(doc, "span", tgStatusNames[snapshot.telegram_status] || "Состояние неизвестно", "telegram-state"));
    tgState.setAttribute("data-state", snapshot.telegram_status || "unknown");
    append(tgCopy, node(doc, "p", snapshot.telegram_configured
      ? "Отдельный TCP-туннель для Telegram; подбор D2K управляется независимо."
      : "Настройка туннеля не завершена. Повторите установку D2K для автоматической регистрации роутера."));
    var tgAction = snapshot.telegram_enabled ? "telegram-disable" : "telegram-enable";
    var tgButton = append(tgCard, node(doc, "button",
      undefined, "control-button " + (snapshot.telegram_enabled ? "button-danger" : "button-primary")));
    append(tgButton, icon(doc, "power"));
    append(tgButton, node(doc, "span", snapshot.telegram_enabled ? "Выключить" : "Включить"));
    tgButton.setAttribute("type", "button");
    tgButton.setAttribute("data-control", tgAction);
    tgButton.setAttribute("data-ui-key", "control:telegram");
    tgButton.disabled = !snapshot.controls_enabled || !snapshot.telegram_configured || controlInFlight || serverControlBusy;
    append(controls, node(doc, "p", snapshot.controls_enabled
      ? (snapshot.mode === "off"
        ? "Подбор выключен в настройках. Включите его там, чтобы D2K снова искал обходы."
        : "Эти действия управляют D2K на роутере. Команды принимаются только с того же адреса панели.")
      : "Управление отключено для текущей привязки панели.", "control-note"));
    var controlButtons = append(controls, node(doc, "div", undefined, "control-buttons"));
    append(controlButtons, node(doc, "strong", "D2K / " + (snapshot.engine_running === true
      ? (snapshot.controller_running === true ? "Работает" : "Без подбора")
      : snapshot.engine_running === false ? "Остановлен" : "Неизвестно"), "control-engine-state"));
    [
      ["start", "Запустить", "button-primary"],
      ["stop", "Остановить", "button-danger"],
      ["restart", "Перезапустить", "button-quiet"],
      ["reapply", "Восстановить", "button-quiet"],
    ].forEach(function (item) {
      var button = append(controlButtons, node(doc, "button", undefined, "control-button " + item[2]));
      append(button, icon(doc, item[0]));
      append(button, node(doc, "span", item[1]));
      button.setAttribute("type", "button");
      button.setAttribute("data-control", item[0]);
      button.setAttribute("data-ui-key", "control:" + item[0]);
      button.disabled = !snapshot.controls_enabled || controlInFlight || serverControlBusy ||
        ((item[0] === "start" || item[0] === "restart") && snapshot.mode === "off");
    });
    var result = append(controls, node(doc, "p", controlMessage, "control-result"));
    result.setAttribute("id", "control-result");
    if (stableControls) syncControls(stableControls, controls);
    if (rootNode.addEventListener && !rootNode.__d2kControlBound) {
      rootNode.__d2kControlBound = true;
      rootNode.addEventListener("click", function (event) {
        var button = event.target && event.target.closest ? event.target.closest("[data-control]") : null;
        if (!button || button.disabled) return;
        var action = button.getAttribute("data-control");
        if ((action === "stop" || action === "restart" || action === "telegram-disable") && root.confirm &&
            !root.confirm(action === "stop" ? "Приостановить подбор? Сохранённые результаты останутся на месте." :
              action === "telegram-disable" ? "Выключить Telegram-туннель? Новые Telegram-соединения пойдут напрямую." :
              "Перезапустить D2K? Текущие соединения могут на короткое время переключиться на прямое подключение.")) return;
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
    animateSlides(rootNode, doc);
  }

  function networkContext(item) {
    var family = item.family || 4;
    var transport = item.transport || 6;
    return (family === 6 ? "IPv6" : family === 4 ? "IPv4" : "Семейство не определено") +
      (transport === 6 ? " / TCP" : transport === 17 ? " / UDP" : "");
  }

  function contextKey(item) {
    return [item.target || "", item.family || 4, item.transport || 6];
  }

  function renderSearch(doc, parent, search) {
    var card = append(parent, node(doc, "article", undefined, "search-item"));
    if (card.style) card.style.setProperty("--name-length", Math.max(8, String(search.target || "").length));
    setAttr(card, "data-slide-key", JSON.stringify(contextKey(search).concat(
      [search.shape || 0, search.proto || "", search.ech_origin || "", search.probe_path || "/"])));
    setAttr(card, "data-slide-stage", search.phase === "подтверждено, смотрим живой трафик"
      ? "confirmed" : search.phase || "unknown");
    var content = append(card, node(doc, "div", undefined, "slide-content"));
    var select = append(content, node(doc, "button", undefined, "slide-select"));
    append(select, node(doc, "span", "", "slide-number"));
    append(select, node(doc, "span", "Подбор", "slide-label"));
    setAttr(select, "type", "button");
    setAttr(select, "data-select-slide", card.getAttribute("data-slide-key"));
    setAttr(select, "data-ui-key", "select:" + card.getAttribute("data-slide-key"));
    setAttr(select, "aria-label", "Выбрать подбор " + (search.target || "без имени"));
    setAttr(select, "aria-pressed", "false");
    var top = append(content, node(doc, "div", undefined, "search-top"));
    var targetLabel = append(top, node(doc, "strong", search.target || "цель без имени", "search-target"));
    setAttr(targetLabel, "title", search.target || "цель без имени");
    var stageIndex = ({
      "ждём форму приветствия":0, "распознаём поведение":0,
      "спрашиваем коробку о свойствах":0, "выводим планы":1,
      "проверяем готовое узнанной коробки":2, "проверяем выведенный план":2,
      "подтверждено, смотрим живой трафик":3
    })[search.phase];
    if (stageIndex !== undefined) {
      var steps = node(doc, "ol", undefined, "slide-stages");
      setAttr(steps, "aria-label", "Этапы подбора");
      ["Замер", "Создание", "Проверка", "Сохранено"].forEach(function (label, index) {
        var step = append(steps, node(doc, "li", label));
        if (index === stageIndex) setAttr(step, "aria-current", "step");
      });
    }
    var meta = append(content, node(doc, "div", undefined, "search-meta"));
    var protocol = search.proto ? protocolName(search.proto) :
      ({1:"TLS 1.3",2:"TLS 1.2",3:"QUIC",6:"TLS 1.3 с ECH"})[search.shape];
    append(meta, node(doc, "span", (protocol ? protocol + " · " : "") + networkContext(search)));
    append(meta, node(doc, "span", "Начато " + safeDate(search.since)));
    if (steps) append(content, steps);
    var phase = append(content, node(doc, "p", undefined, "phase-tag"));
    if (stageIndex === 3) append(phase, icon(doc, "confirmed"));
    append(phase, node(doc, "span", searchPhase(search.phase)));
    var counts = append(content, node(doc, "div", undefined, "search-counts"));
    append(counts, node(doc, "span", "Проверено вариантов: " + (search.attempts || 0)));
    var detail = append(content, node(doc, "details", undefined, "search-detail"));
    setAttr(detail, "data-ui-key", "search:" + JSON.stringify(contextKey(search)));
    var summary = append(detail, node(doc, "summary"));
    append(summary, icon(doc, "document"));
    append(summary, node(doc, "span", "Подробности"));
    append(summary, icon(doc, "arrow"));
    append(detail, node(doc, "p", "Цель: " + (search.target || "без имени")));
    append(detail, node(doc, "p", "Исходный сигнал: " + (search.source || "не указан")));
    append(detail, node(doc, "p", "Текущий этап: " + (search.phase || "не указан")));
    append(detail, node(doc, "p", "Зондов отправлено: " + (search.probes || 0)));
    if (search.candidate) append(detail, node(doc, "p", "Текущий вариант: " + search.candidate));
  }

  function coveredByFamily(binding, groups) {
    if (binding.kind && binding.kind !== "name") return false;
    var name = String(binding.target || "").toLowerCase().replace(/\.$/, "");
    return groups.some(function (group) {
      var suffix = group.suffix.toLowerCase().replace(/\.$/, "");
      if (!group.active || (binding.transport || 6) !== group.transport ||
          (binding.family || 4) !== group.family || (binding.shape || 0) !== group.shape ||
          (binding.probe_path || "/") !== (group.probe_path || "/") ||
          (binding.ech_origin || "") !== (group.ech_origin || "")) return false;
      if (name !== suffix && !name.endsWith("." + suffix)) return false;
      return !(Array.isArray(group.exceptions) ? group.exceptions : []).some(function (exception) {
        return exception && String(exception.name || "").toLowerCase().replace(/\.$/, "") === name;
      });
    });
  }

  function renderFamily(doc, parent, group, linked, index) {
    var item = append(parent, node(doc, "article", undefined, "family-item"));
    setAttr(item, "data-active", !!(linked && group.active));
    var tab = append(item, node(doc, "span", "S" + (index + 1), "family-tab"));
    setAttr(tab, "aria-hidden", "true");
    if (linked && group.active) setAttr(item, "data-family-context",
      JSON.stringify([group.suffix, group.family, group.transport, group.shape,
        group.ech_origin || "", group.probe_path || "/",
        (Array.isArray(group.exceptions) ? group.exceptions : []).map(function (item) { return item.name; })]));
    var head = append(item, node(doc, "header", undefined, "family-header"));
    heading(doc, head, 3, group.suffix);
    append(head, node(doc, "span", linked && group.active ? "Применяется" : "Сохранено, применение не подтверждено",
      "family-state"));
    var shape = group.shape === 1 ? "TLS 1.3" : group.shape === 2 ? "TLS 1.2" :
      group.shape === 3 ? "QUIC" : group.shape === 6 ? "TLS 1.3 с ECH" : "Протокол не указан";
    append(item, node(doc, "p", shape + " · " + (group.family === 6 ? "IPv6" : "IPv4"),
      "family-context"));
    var details = append(item, node(doc, "details", undefined, "family-detail"));
    details.setAttribute("data-ui-key", "family:" + JSON.stringify([group.suffix, group.transport,
      group.family, group.shape, group.probe_path, group.ech_origin]));
    var summary = append(details, node(doc, "summary"));
    append(summary, icon(doc, "document"));
    append(summary, node(doc, "span", "Подробности"));
    append(summary, icon(doc, "arrow"));
    append(details, node(doc, "p", russianCount(group.evidence_count,
      "исходное подтверждение", "исходных подтверждения", "исходных подтверждений")));
    append(details, node(doc, "p", "План: " + (group.plan_id || "не записан")));
    if (group.probe_path) append(details, node(doc, "p", "Проверенный путь: " + group.probe_path));
    if (group.ech_origin) append(details, node(doc, "p", "ECH-origin: " + group.ech_origin));
    var evidence = Array.isArray(group.evidence) ? group.evidence : [];
    if (evidence.length) {
      append(details, node(doc, "p", "Собственные измерения, на которых обучена область:"));
      var list = append(details, node(doc, "ul"));
      evidence.forEach(function (name) { if (typeof name === "string") append(list, node(doc, "li", name)); });
    }
    var exceptions = Array.isArray(group.exceptions) ? group.exceptions.filter(function (e) { return e && e.name; }) : [];
    if (exceptions.length) {
      append(details, node(doc, "p", "Исключения не используют общий обход:"));
      var excluded = append(details, node(doc, "ul"));
      exceptions.forEach(function (e) { append(excluded, node(doc, "li", e.name + " — " + (e.reason || "отдельное решение"))); });
    }
  }

  function renderBox(doc, parent, box, index, groups) {
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
    (Array.isArray(box.bindings) ? box.bindings : []).filter(function (binding) {
      return !coveredByFamily(binding, groups);
    }).forEach(function (binding) {
      var row = append(targets, node(doc, "div", undefined, "target-row" + (binding.enabled ? "" : " target-disabled")));
      var target = append(row, node(doc, "div", undefined, "target-identity"));
      append(target, node(doc, "strong", binding.target || "цель не названа", "target-name"));
      append(target, node(doc, "span", networkContext(binding), "target-kind"));
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
      copy.setAttribute("data-ui-key", "copy:" + JSON.stringify(
        [box.id || index, binding.kind || "name", binding.shape || 0].concat(contextKey(binding))));
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
      var payload = await requestJSON("/api/control/" + encodeURIComponent(action), {
        method: "POST", cache: "no-store",
      }, 10000);
      if (!payload.ok) throw new Error(payload.message || "Ошибка команды");
      controlMessage = payload.message || "Команда выполнена.";
    } catch (err) {
      controlMessage = "Не удалось получить результат команды. Проверьте состояние службы: " +
        (err && err.message ? err.message : "ошибка связи с панелью");
    } finally {
      controlInFlight = false;
      await refresh();
    }
  }

  async function refresh() {
    if (refreshInFlight || root.document.hidden) return;
    root.clearTimeout(refreshTimer);
    refreshInFlight = true;
    refreshAbort = new root.AbortController();
    var deadline = root.setTimeout(function () { refreshAbort.abort(); }, 10000);
    var app = root.document.getElementById("app");
    try {
      var response = await root.fetch("/api/status", { cache: "no-store", signal: refreshAbort.signal });
      if (!response.ok) throw new Error("HTTP " + response.status);
      render(app, await response.json(), root.document);
    } catch (err) {
      if (root.document.hidden) return;
      var staleControls = clearContent(app);
      if (staleControls) {
        Array.prototype.forEach.call(staleControls.querySelectorAll("button"), function (button) { button.disabled = true; });
      }
      var warning = node(root.document, "section", undefined, "connection-error");
      var errorIcon = append(warning, icon(root.document, "error"));
      errorIcon.setAttribute("class", "ui-icon error-mark");
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
      if (rail) { rail.textContent = "Нет связи с панелью"; rail.setAttribute("data-connected", "false"); }
      if (updated) updated.textContent = "состояние неизвестно";
    } finally {
      root.clearTimeout(deadline);
      refreshAbort = null;
      refreshInFlight = false;
      if (!root.document.hidden) refreshTimer = root.setTimeout(refresh, 5000);
    }
  }

  var api = { render: render, renderBox: renderBox, renderSearch: renderSearch, filterBoxes: filterBoxes, refresh: refresh,
    slideEvents: slideEvents };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root.document) {
    root.document.addEventListener("DOMContentLoaded", function () {
      refresh();
    });
    root.document.addEventListener("visibilitychange", function () {
      root.clearTimeout(refreshTimer);
      if (root.document.hidden) { if (refreshAbort) refreshAbort.abort(); }
      else refresh();
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
