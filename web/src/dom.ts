// Tiny DOM builder. Uses createElement/textContent only — never HTML strings —
// so the app works under `require-trusted-types-for 'script'` and cannot be
// tricked into interpreting server- or peer-supplied text as markup.

export type Child = Node | string | number | null | undefined | false | Child[];

type Listeners = { [K in keyof HTMLElementEventMap]?: (ev: HTMLElementEventMap[K]) => void };

export interface Props {
  class?: string;
  testid?: string;
  text?: string;
  title?: string;
  attrs?: Record<string, string | number | boolean | null | undefined>;
  on?: Listeners;
}

const FORBIDDEN_ATTR = /^(on|style$|srcdoc$|formaction$)/i;
const URL_ATTR = /^(href|src|action|xlink:href)$/i;

function setAttr(el: Element, name: string, value: string | number | boolean | null | undefined): void {
  if (FORBIDDEN_ATTR.test(name)) throw new Error(`attribute ${name} is not allowed`);
  if (value === null || value === undefined || value === false) return;
  const v = value === true ? "" : String(value);
  if (URL_ATTR.test(name) && !/^(https?:|blob:|#|\/(?!\/)|mailto:)/i.test(v)) throw new Error(`unsafe URL in ${name}`);
  el.setAttribute(name, v);
}

export function append(el: Node, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(el, ...c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, props?: Props | null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props) {
    if (props.class) el.className = props.class;
    if (props.testid) el.dataset["testid"] = props.testid;
    if (props.title) el.title = props.title;
    if (props.attrs) for (const [k, v] of Object.entries(props.attrs)) setAttr(el, k, v);
    if (props.on) {
      for (const [k, fn] of Object.entries(props.on)) {
        if (fn) el.addEventListener(k, fn as EventListener);
      }
    }
    if (props.text !== undefined) el.textContent = props.text;
  }
  append(el, ...children);
  return el;
}

export function clear(el: Node): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function replace(el: Node, ...children: Child[]): void {
  clear(el);
  append(el, ...children);
}

export function show(el: HTMLElement, visible: boolean): void {
  el.hidden = !visible;
}

const SVG_NS = "http://www.w3.org/2000/svg";

export function svgEl<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number>): SVGElementTagNameMap[K] {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) setAttr(el, k, v);
  return el;
}
