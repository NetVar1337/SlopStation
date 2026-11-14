// app/src/lib/guide.ts
// The engine's `guide` tool: task recipes (topic -> exact tool-call sequence)
// surfaced in Help > Guides and the command palette

import { call } from "@/lib/rpc";

export type GuideTopic = { topic: string; title: string; summary: string };
export type GuideStep = { tool: string; action: string; params: unknown; why: string };
export type Guide = GuideTopic & { steps: GuideStep[] };

let topics: Promise<GuideTopic[]> | null = null;

/** Topic list, fetched once per session; a failed fetch is retried next time. */
export function listGuides(): Promise<GuideTopic[]> {
  topics ??= call<{ topics: GuideTopic[] }>("guide", "list").then(
    (r) => r.topics,
    (e: unknown) => {
      topics = null;
      throw e;
    },
  );
  return topics;
}

export function getGuide(topic: string): Promise<Guide> {
  return call<Guide>("guide", "get", { topic });
}
