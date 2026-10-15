/* Lista dupla «Disponíveis | Escolhidas» (como no Django admin, mas com pesquisa, contadores e atalhos).
   As <select multiple> são reais: no envio, todas as opções da lista «Escolhidas» ficam selecionadas. */
(function () {
  function init(root) {
    const avail = root.querySelector(".dl-available"), chosen = root.querySelector(".dl-chosen");
    const rules = root.dataset.rules === "modules";
    const form = root.closest("form");

    const visible = sel => [...sel.options].filter(o => !o.hidden);
    const selectedOf = sel => [...sel.selectedOptions];

    function putOption(select, opt) {
      opt.selected = false;
      let parent = select;
      const label = opt.dataset.group;
      if (label) {
        parent = [...select.querySelectorAll("optgroup")].find(g => g.label === label);
        if (!parent) {
          parent = document.createElement("optgroup");
          parent.label = label;
          parent.dataset.order = opt.dataset.gorder;
          const next = [...select.querySelectorAll("optgroup")].find(g => +g.dataset.order > +parent.dataset.order);
          select.insertBefore(parent, next || null);
        }
      }
      const siblings = [...parent.querySelectorAll(":scope > option")];
      const after = siblings.find(o => +o.dataset.order > +opt.dataset.order);
      parent.insertBefore(opt, after || null);
    }

    function cleanup(select) { select.querySelectorAll("optgroup").forEach(g => { if (!g.querySelector("option")) g.remove(); }); }

    function refresh() {
      cleanup(avail); cleanup(chosen);
      root.querySelector(".dl-count-available").textContent = avail.options.length;
      root.querySelector(".dl-count-chosen").textContent = chosen.options.length;
      root.querySelectorAll(".dl-filter").forEach(f => f.dispatchEvent(new Event("input")));
    }

    function move(from, to, opts) {
      let list = new Set(opts);
      if (rules) {
        if (to === chosen) {  // escolher uma permissão do módulo escolhe também o acesso a esse módulo
          opts.forEach(o => { if (o.dataset.module && o.dataset.access !== "1") {
            const acc = [...avail.options].find(x => x.dataset.module === o.dataset.module && x.dataset.access === "1");
            if (acc) list.add(acc); } });
        } else {  // retirar o acesso retira também as permissões desse módulo
          opts.forEach(o => { if (o.dataset.access === "1")
            [...chosen.options].filter(x => x.dataset.module === o.dataset.module).forEach(x => list.add(x)); });
        }
      }
      list.forEach(o => putOption(to, o));
      refresh();
    }

    root.querySelector(".dl-add").onclick = () => move(avail, chosen, selectedOf(avail));
    root.querySelector(".dl-remove").onclick = () => move(chosen, avail, selectedOf(chosen));
    root.querySelector(".dl-add-all").onclick = () => move(avail, chosen, visible(avail));
    root.querySelector(".dl-remove-all").onclick = () => move(chosen, avail, visible(chosen));
    avail.addEventListener("dblclick", ev => { if (ev.target.tagName === "OPTION") move(avail, chosen, [ev.target]); });
    chosen.addEventListener("dblclick", ev => { if (ev.target.tagName === "OPTION") move(chosen, avail, [ev.target]); });
    [avail, chosen].forEach((sel, i) => sel.addEventListener("keydown", ev => {
      if (ev.key === "Enter") { ev.preventDefault(); move(sel, i ? avail : chosen, selectedOf(sel)); }
    }));

    root.querySelectorAll(".dl-filter").forEach(input => input.addEventListener("input", () => {
      const sel = input.closest(".dl-pane").querySelector("select"), q = input.value.trim().toLowerCase();
      [...sel.options].forEach(o => { o.hidden = q && !(o.textContent + " " + (o.title || "")).toLowerCase().includes(q); });
      sel.querySelectorAll("optgroup").forEach(g => { g.hidden = ![...g.querySelectorAll("option")].some(o => !o.hidden); });
    }));

    if (form) form.addEventListener("submit", () => { [...chosen.options].forEach(o => { o.selected = true; }); });
    refresh();
  }
  document.querySelectorAll(".duallist").forEach(init);
})();
