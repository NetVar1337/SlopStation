// app/src/components/TooltipLayer.tsx
// one global tooltip instead of the native title attribute, any element can
// opt in with data-tip

import { useEffect, useLayoutEffect, useRef, useState } from "react";

type Placed = {
  text: string;
  left: number;
  top: number;
  below: boolean;
  /** Host edges, so the measured bubble can flip to the side that fits. */
  hostTop: number;
  hostBottom: number;
};

/** Long enough not to flicker while the cursor crosses a toolbar. */
const kDelayMs = 380;
const kGap = 7;
const kMargin = 6;

export default function TooltipLayer() {
  const [tip, setTip] = useState<Placed | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const bubbleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const cancel = () => {
      if (timer.current !== null) {
        clearTimeout(timer.current);
        timer.current = null;
      }
      setTip(null);
    };

    const show = (host: HTMLElement, delay: number) => {
      const text = host.dataset.tip ?? "";
      if (text === "") {
        cancel();
        return;
      }
      if (timer.current !== null) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        const r = host.getBoundingClientRect();
        // Prefer below; the layout effect flips above once the bubble's real
        // height shows it would run off the bottom edge
        setTip({
          text,
          left: r.left + r.width / 2,
          top: r.bottom + kGap,
          below: true,
          hostTop: r.top,
          hostBottom: r.bottom,
        });
      }, delay);
    };

    const onOver = (e: PointerEvent) => {
      const host = (e.target as Element | null)?.closest?.("[data-tip]");
      if (!(host instanceof HTMLElement)) {
        cancel();
        return;
      }
      show(host, kDelayMs);
    };

    // Keyboard users get the same hint when tabbing onto a control; mouse
    // clicks also move focus but do not match :focus-visible
    const onFocusIn = (e: FocusEvent) => {
      const el = e.target;
      if (!(el instanceof HTMLElement) || !el.matches(":focus-visible")) return;
      const host = el.closest("[data-tip]");
      if (host instanceof HTMLElement) show(host, 120);
    };

    // Any interaction dismisses: a tooltip lingering over a menu that just
    // opened is worse than no tooltip
    document.addEventListener("pointerover", onOver, true);
    document.addEventListener("pointerdown", cancel, true);
    document.addEventListener("wheel", cancel, true);
    document.addEventListener("keydown", cancel, true);
    document.addEventListener("focusin", onFocusIn, true);
    document.addEventListener("focusout", cancel, true);
    window.addEventListener("blur", cancel);
    return () => {
      document.removeEventListener("pointerover", onOver, true);
      document.removeEventListener("pointerdown", cancel, true);
      document.removeEventListener("wheel", cancel, true);
      document.removeEventListener("keydown", cancel, true);
      document.removeEventListener("focusin", onFocusIn, true);
      document.removeEventListener("focusout", cancel, true);
      window.removeEventListener("blur", cancel);
      if (timer.current !== null) clearTimeout(timer.current);
    };
  }, []);

  // Clamp horizontally and pick the vertical side once the bubble is measured
  useLayoutEffect(() => {
    const el = bubbleRef.current;
    if (el === null || tip === null) return;
    const half = el.offsetWidth / 2;
    const h = el.offsetHeight;
    const clamped = Math.min(
      Math.max(tip.left, half + kMargin),
      window.innerWidth - half - kMargin,
    );
    const fitsBelow = tip.hostBottom + kGap + h <= window.innerHeight - kMargin;
    const fitsAbove = tip.hostTop - kGap - h >= kMargin;
    // Flip only toward a side that fits, so a tip too tall for both settles
    const below = tip.below ? fitsBelow || !fitsAbove : !(fitsAbove || !fitsBelow);
    if (Math.abs(clamped - tip.left) > 0.5 || below !== tip.below)
      setTip({
        ...tip,
        left: clamped,
        below,
        top: below ? tip.hostBottom + kGap : tip.hostTop - kGap,
      });
  }, [tip]);

  if (tip === null) return null;

  return (
    <div
      ref={bubbleRef}
      className="tooltip"
      role="tooltip"
      style={{
        left: tip.left,
        top: tip.top,
        transform: `translate(-50%, ${tip.below ? "0" : "-100%"})`,
      }}
    >
      {tip.text}
    </div>
  );
}
