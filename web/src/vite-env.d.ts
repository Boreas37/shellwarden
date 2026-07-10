/// <reference types="vite/client" />

declare module "asciinema-player" {
  export function create(
    src: string,
    element: HTMLElement,
    opts?: Record<string, unknown>
  ): { dispose: () => void };
}
declare module "asciinema-player/dist/bundle/asciinema-player.css";

// guacamole-common-js ships without TypeScript types. Declare the minimal
// surface used by RdpCanvas.tsx.
declare module "guacamole-common-js" {
  export class WebSocketTunnel {
    constructor(url: string);
  }
  export class Client {
    constructor(tunnel: WebSocketTunnel);
    getDisplay(): {
      getElement(): HTMLElement;
      getWidth(): number;
      getHeight(): number;
    };
    connect(data?: string): void;
    disconnect(): void;
    sendMouseState(state: unknown): void;
    sendKeyEvent(pressed: number, keysym: number): void;
    onerror: ((error: unknown) => void) | null;
  }
  export class Mouse {
    constructor(element: HTMLElement);
    onmousedown: ((state: unknown) => void) | null;
    onmouseup: ((state: unknown) => void) | null;
    onmousemove: ((state: unknown) => void) | null;
  }
  export class Keyboard {
    constructor(element: HTMLElement | Document);
    onkeydown: ((keysym: number) => void) | null;
    onkeyup: ((keysym: number) => void) | null;
  }
}
