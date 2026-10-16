// Monochrome line icons, drawn for this app (24×24, stroke = currentColor).

import { svgEl } from "./dom";

type Shape = ["p", string] | ["c", number, number, number] | ["r", number, number, number, number, number];

const ICONS = {
  heart: [["p", "M12 20s-7.5-4.6-7.5-10.2A4.3 4.3 0 0 1 12 7a4.3 4.3 0 0 1 7.5 2.8C19.5 15.4 12 20 12 20z"]],
  display: [["r", 3, 4, 18, 12.5, 2], ["p", "M8.5 20.5h7M12 16.5v4"]],
  laptop: [["r", 4.5, 5, 15, 10.5, 1.5], ["p", "M2.5 19h19"]],
  phone: [["r", 7, 2.5, 10, 19, 2.5], ["p", "M11 18.5h2"]],
  check: [["p", "M5 12.5l4.5 4.5L19 7.5"]],
  close: [["p", "M6.5 6.5l11 11M17.5 6.5l-11 11"]],
  warning: [["p", "M12 4L2.8 19.5h18.4L12 4z"], ["p", "M12 10v4.5M12 17.2v.1"]],
  lock: [["r", 5, 11, 14, 9.5, 2], ["p", "M8 11V8a4 4 0 0 1 8 0v3"]],
  shield: [["p", "M12 3l7 3v5.5c0 4.5-3 8-7 9.5-4-1.5-7-5-7-9.5V6z"], ["p", "M9 12l2 2 4-4"]],
  power: [["p", "M12 3.5v8M7.1 6.6a7 7 0 1 0 9.8 0"]],
  fullscreen: [["p", "M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"]],
  "fullscreen-exit": [["p", "M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"]],
  sliders: [["p", "M4 7h9.5M18.5 7H20M4 17h3.5M12.5 17H20"], ["c", 16, 7, 2.3], ["c", 10, 17, 2.3]],
  speaker: [["p", "M4 9.5h3.5L12 5.5v13l-4.5-4H4z"], ["p", "M15.5 9a4 4 0 0 1 0 6M18 6.5a7.5 7.5 0 0 1 0 11"]],
  "speaker-off": [["p", "M4 9.5h3.5L12 5.5v13l-4.5-4H4z"], ["p", "M16 9.5l5 5M21 9.5l-5 5"]],
  clipboard: [["r", 6, 4.5, 12, 16, 2], ["r", 9, 3, 6, 3, 1], ["p", "M9 11h6M9 14.5h4"]],
  folder: [["p", "M3.5 7.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"]],
  file: [["p", "M7 3.5h7l4 4V19a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 6 19V5A1.5 1.5 0 0 1 7 3.5z"], ["p", "M14 3.5V8h4"]],
  upload: [["p", "M12 15V4.5M7.5 9L12 4.5 16.5 9M5 15v3.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V15"]],
  download: [["p", "M12 4.5V15M7.5 10.5L12 15l4.5-4.5M5 15v3.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V15"]],
  command: [
    [
      "p",
      "M9 9h6v6H9zM9 9H6.5A2.5 2.5 0 1 1 9 6.5V9M15 9V6.5A2.5 2.5 0 1 1 17.5 9H15M15 15h2.5a2.5 2.5 0 1 1-2.5 2.5V15M9 15v2.5A2.5 2.5 0 1 1 6.5 15H9",
    ],
  ],
  keyboard: [
    ["r", 2.5, 6, 19, 12, 2],
    ["p", "M6 9.8h.01M9 9.8h.01M12 9.8h.01M15 9.8h.01M18 9.8h.01M6.5 12.6h.01M9.5 12.6h.01M12.5 12.6h.01M15.5 12.6h.01M8 15.4h8"],
  ],
  help: [["c", 12, 12, 9], ["p", "M9.6 9.4a2.5 2.5 0 1 1 3.6 2.3c-.7.3-1.2.9-1.2 1.7v.4M12 16.8v.1"]],
  trash: [["p", "M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 12.5h9l1-12.5"]],
  plus: [["p", "M12 5v14M5 12h14"]],
  key: [["c", 8, 12, 3.5], ["p", "M11.5 12H21M18 12v3M15 12v2.5"]],
  refresh: [["p", "M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4"]],
  back: [["p", "M15 5l-7 7 7 7"]],
  forward: [["p", "M9 5l7 7-7 7"]],
  up: [["p", "M12 19V6M6.5 11.5L12 6l5.5 5.5"]],
  signout: [["p", "M14.5 4h3.5a1.5 1.5 0 0 1 1.5 1.5v13a1.5 1.5 0 0 1-1.5 1.5h-3.5M10 8l-4 4 4 4M6 12h10"]],
  block: [["c", 12, 12, 8.5], ["p", "M6 6l12 12"]],
  play: [["c", 12, 12, 8.5], ["p", "M10.2 8.8v6.4l5.3-3.2z"]],
  more: [["p", "M6 12h.01M12 12h.01M18 12h.01"]],
  info: [["c", 12, 12, 9], ["p", "M12 11v5.5M12 7.8v.1"]],
} satisfies Record<string, Shape[]>;

export type IconName = keyof typeof ICONS;

export function icon(name: IconName, cls = "icon"): SVGSVGElement {
  const svg = svgEl("svg", {
    viewBox: "0 0 24 24",
    width: 24,
    height: 24,
    fill: "none",
    stroke: "currentColor",
    "stroke-width": 1.8,
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
    focusable: "false",
    class: cls,
  });
  for (const s of ICONS[name] as Shape[]) {
    if (s[0] === "p") svg.appendChild(svgEl("path", { d: s[1] }));
    else if (s[0] === "c") svg.appendChild(svgEl("circle", { cx: s[1], cy: s[2], r: s[3] }));
    else svg.appendChild(svgEl("rect", { x: s[1], y: s[2], width: s[3], height: s[4], rx: s[5] }));
  }
  return svg;
}
