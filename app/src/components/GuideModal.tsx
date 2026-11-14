// app/src/components/GuideModal.tsx
// Help > Guides: the engine's task recipes (guide.list / guide.get). An empty
// topic lists every guide; a topic shows its summary and exact tool calls

import { useEffect, useState } from "react";
import Modal from "@/components/Modal";
import { useT } from "@/i18n";
import { getGuide, listGuides, type Guide, type GuideTopic } from "@/lib/guide";
import { useUi } from "@/store/ui";

export default function GuideModal({ topic }: { topic: string }) {
  const t = useT();
  const openGuide = useUi((s) => s.openGuide);
  const [topics, setTopics] = useState<GuideTopic[] | null>(null);
  const [guide, setGuide] = useState<Guide | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setError(null);
    setGuide(null);
    const fail = (e: unknown) => alive && setError(e instanceof Error ? e.message : String(e));
    if (topic === "")
      listGuides()
        .then((list) => alive && setTopics(list))
        .catch(fail);
    else
      getGuide(topic)
        .then((g) => alive && setGuide(g))
        .catch(fail);
    return () => {
      alive = false;
    };
  }, [topic]);

  const close = () => openGuide(null);

  return (
    <Modal title={guide?.title ?? t("guide.title")} onClose={close} className="guide-modal">
      <div className="modal-body guide-body">
        {error !== null ? (
          <p className="error-text" role="alert">
            {t("guide.error", { error })}
          </p>
        ) : topic === "" ? (
          topics === null ? (
            <p className="dim">{t("common.loading")}</p>
          ) : topics.length === 0 ? (
            <p className="dim">{t("guide.empty")}</p>
          ) : (
            <ul className="guide-list">
              {topics.map((g) => (
                <li key={g.topic}>
                  <button type="button" className="guide-item" onClick={() => openGuide(g.topic)}>
                    <span className="guide-item-title">{g.title}</span>
                    <span className="guide-item-sum">{g.summary}</span>
                  </button>
                </li>
              ))}
            </ul>
          )
        ) : guide === null ? (
          <p className="dim">{t("common.loading")}</p>
        ) : (
          <>
            <p className="guide-summary">{guide.summary}</p>
            <div className="settings-label">{t("guide.steps")}</div>
            <ol className="guide-steps">
              {guide.steps.map((s, i) => (
                <li key={i}>
                  <code className="mono">
                    {s.tool}.{s.action}{" "}
                    {typeof s.params === "string" ? s.params : JSON.stringify(s.params)}
                  </code>
                  <span className="dim">{s.why}</span>
                </li>
              ))}
            </ol>
          </>
        )}
        {topic !== "" && (
          <button type="button" className="row-action guide-back" onClick={() => openGuide("")}>
            {t("guide.back")}
          </button>
        )}
      </div>
    </Modal>
  );
}
