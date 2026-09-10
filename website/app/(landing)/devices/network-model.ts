/** A deterministic illustration of Controller -> Host work. No network calls.
 * Source devices are desktop-class Controllers supported in README.md. */
export const DEVICES = [
  { id: 'laptop', label: 'Laptop', os: 'macOS', shape: 'laptop' },
  { id: 'desktop', label: 'Desktop', os: 'Windows', shape: 'desktop' },
  { id: 'rack', label: 'Server rack', os: 'Linux', shape: 'rack' },
  { id: 'notebook', label: 'Notebook', os: 'Linux', shape: 'notebook' },
  { id: 'mini', label: 'Mini PC', os: 'macOS', shape: 'mini' },
  { id: 'workstation', label: 'Workstation', os: 'Windows', shape: 'workstation' },
] as const;
export type DeviceShape = (typeof DEVICES)[number]['shape'];
export type Point = { x: number; y: number };
export const SEND_ORDER = [0, 3, 1, 4, 2, 5] as const;
export const TIMING = {
  send: 800,
  arrive: 1800,
  work: 2050,
  complete: 4550,
  acknowledge: 4750,
  cooldown: 5750,
  rest: 6200,
  cycle: 6600,
} as const;
export const ORBIT_MS = 90000;
export const PLAYBACK_RATE = 1.25;
export const clamp = (n: number) => Math.max(0, Math.min(1, n));
export const smooth = (p: number) => { const t = clamp(p); return t * t * (3 - 2 * t); };
const timeValue = (ms: number) => Number.isFinite(ms) ? Math.max(0, ms) : 0;
const envelope = (ms: number, start: number, end: number, edge: number) =>
  smooth((ms - start) / edge) * smooth((end - ms) / edge);

const DEVICE_EXTENTS: Record<DeviceShape, { x: number; y: number }> = {
  laptop: { x: 47, y: 36 },
  desktop: { x: 40, y: 37 },
  rack: { x: 27, y: 43 },
  notebook: { x: 47, y: 36 },
  mini: { x: 36, y: 39 },
  workstation: { x: 50, y: 38 },
};
const HOST_EXTENTS = { x: 119, y: 77.5 };

export function layout(compact: boolean) {
  return compact
    ? { width: 520, height: 600, cx: 260, cy: 300, rx: 196, ry: 220, deviceScale: 0.76, hostScale: 0.82 }
    : { width: 1120, height: 540, cx: 560, cy: 262, rx: 390, ry: 196, deviceScale: 1, hostScale: 1 };
}
export function devicePoint(index: number, elapsed: number, compact: boolean): Point & { tilt: number } {
  const box = layout(compact);
  // Upright silhouettes orbit, instead of rotating the devices upside down.
  const angle = -Math.PI / 6 + index * Math.PI / 3 + timeValue(elapsed) / ORBIT_MS * Math.PI * 2;
  const bob = Math.sin(timeValue(elapsed) / 1900 + index * 1.7) * 4;
  return { x: box.cx + Math.cos(angle) * box.rx, y: box.cy + Math.sin(angle) * box.ry + bob, tilt: Math.sin(angle * 2) * 5 };
}

/** Distance from a device center to the visible silhouette edge in a world-space direction.
 * The device group applies the same tilt/scale; using the inverse transform keeps the
 * route attached to the actual device edge instead of a fixed radius. */
export function deviceBoundaryDistance(shape: DeviceShape, direction: Point, tilt: number, scale: number) {
  const length = Math.hypot(direction.x, direction.y);
  if (!length) return 0;
  const angle = tilt * Math.PI / 180, c = Math.cos(angle), s = Math.sin(angle);
  const localX = (c * direction.x + s * direction.y) / length;
  const localY = (-s * direction.x + c * direction.y) / length;
  const extent = DEVICE_EXTENTS[shape];
  return Math.min(extent.x / Math.max(Math.abs(localX), Number.EPSILON),
    extent.y / Math.max(Math.abs(localY), Number.EPSILON)) * scale;
}
function hostPort(compact: boolean) {
  const box = layout(compact);
  return { x: box.cx, y: box.cy - 13.5 * box.hostScale };
}
export function signalPath(index: number, elapsed: number, compact: boolean) {
  const box = layout(compact), node = devicePoint(index, elapsed, compact), destination = hostPort(compact);
  const dx = node.x - destination.x, dy = node.y - destination.y, length = Math.hypot(dx, dy);
  const sourceDistance = deviceBoundaryDistance(DEVICES[index].shape, { x: dx, y: dy }, node.tilt, box.deviceScale);
  const a = { x: node.x - dx / length * sourceDistance, y: node.y - dy / length * sourceDistance };
  const hostPortDistance = 1 / Math.sqrt((dx / (HOST_EXTENTS.x * box.hostScale)) ** 2 + (dy / (HOST_EXTENTS.y * box.hostScale)) ** 2);
  const b = { x: destination.x + dx * hostPortDistance, y: destination.y + dy * hostPortDistance };
  const bend = index % 2 ? 22 : -22;
  const control = { x: (a.x + b.x) / 2 - dy / length * bend, y: (a.y + b.y) / 2 + dx / length * bend };
  return {
    a, b, control,
    sourceDistance,
    hostDistance: Math.hypot(b.x - destination.x, b.y - destination.y),
    d: 'M ' + a.x + ' ' + a.y + ' Q ' + control.x + ' ' + control.y + ' ' + b.x + ' ' + b.y,
  };
}
export function pointOnSignal(path: ReturnType<typeof signalPath>, progress: number): Point {
  const t = clamp(progress), u = 1 - t;
  return { x: u * u * path.a.x + 2 * u * t * path.control.x + t * t * path.b.x,
    y: u * u * path.a.y + 2 * u * t * path.control.y + t * t * path.b.y };
}
export function networkFrame(elapsed: number) {
  const safe = timeValue(elapsed), cycle = Math.floor(safe / TIMING.cycle), local = safe % TIMING.cycle;
  const sender = SEND_ORDER[cycle % SEND_ORDER.length];
  const phase = local < TIMING.send ? 'idle' : local < TIMING.arrive ? 'sending' : local < TIMING.work ? 'receiving'
    : local < TIMING.complete ? 'working' : local < TIMING.acknowledge ? 'complete'
    : local < TIMING.cooldown ? 'acknowledging' : local < TIMING.rest ? 'cooling' : 'idle';
  const heat = local < TIMING.arrive ? 0 : local < TIMING.work ? smooth((local - TIMING.arrive) / (TIMING.work - TIMING.arrive))
    : local < TIMING.cooldown ? 1 : local < TIMING.rest ? 1 - smooth((local - TIMING.cooldown) / (TIMING.rest - TIMING.cooldown)) : 0;
  const signal = clamp((local - TIMING.send) / (TIMING.arrive - TIMING.send));
  const ackSignal = clamp((local - TIMING.acknowledge) / (TIMING.cooldown - TIMING.acknowledge));
  const ackArrival = smooth((ackSignal - 0.8) / 0.2);
  const ackSettle = local < TIMING.cooldown ? 1 : 1 - smooth((local - TIMING.cooldown) / (TIMING.rest - TIMING.cooldown));
  return {
    elapsed: safe, cycle, local, sender, phase, heat,
    signal, ackSignal,
    signalFade: envelope(local, TIMING.send, TIMING.arrive, 180),
    ackFade: envelope(local, TIMING.acknowledge, TIMING.cooldown, 180),
    ackEffect: ackArrival * ackSettle,
    progress: clamp((local - TIMING.work) / (TIMING.complete - TIMING.work)),
    working: phase === 'working',
    sending: phase === 'sending',
    acknowledging: phase === 'acknowledging',
    cooling: phase === 'cooling',
    idle: phase === 'idle',
  };
}
export type NetworkFrame = ReturnType<typeof networkFrame>;
