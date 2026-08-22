// The only DOM primitives the view layer uses.
//
// Rows are rendered as HTML strings and re-rendered wholesale, so per-row
// listeners would have to be re-attached on every repaint — the pattern that
// leaked listeners and made "which handler is bound right now?" unanswerable.
// `delegate` installs one listener on a container that survives every
// re-render, and matches the event's target against a selector instead.

export function el(id: string): HTMLElement {
  const found = document.getElementById(id);
  if (!found) throw new Error(`missing #${id}`);
  return found;
}

export function elOpt(id: string): HTMLElement | null {
  return document.getElementById(id);
}

export function inputEl(id: string): HTMLInputElement {
  return el(id) as HTMLInputElement;
}

export function selectEl(id: string): HTMLSelectElement {
  return el(id) as HTMLSelectElement;
}

export type Unbind = () => void;

/** One delegated listener. `handler` receives the matched ancestor element. */
export function delegate<K extends keyof HTMLElementEventMap>(
  root: HTMLElement,
  type: K,
  selector: string,
  handler: (matched: HTMLElement, event: HTMLElementEventMap[K]) => void,
): Unbind {
  const listener = (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const matched = target.closest(selector);
    if (matched instanceof HTMLElement && root.contains(matched)) {
      handler(matched, event as HTMLElementEventMap[K]);
    }
  };
  root.addEventListener(type, listener);
  return () => root.removeEventListener(type, listener);
}

/** Collects unbinds so a screen can drop everything it installed at once. */
export function bindings(): { add(unbind: Unbind): void; dispose(): void } {
  const registered: Unbind[] = [];
  return {
    add(unbind) {
      registered.push(unbind);
    },
    dispose() {
      while (registered.length > 0) registered.pop()?.();
    },
  };
}
