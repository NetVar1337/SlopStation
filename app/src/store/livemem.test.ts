import { beforeEach, describe, expect, it } from "vitest";
import { useScanner } from "@/store/scanner";
import { mockApi } from "@/test/api";

const initial = useScanner.getState();

beforeEach(() => {
  useScanner.setState(initial, true);
});

describe("scanner store paging and value parsing", () => {
  it("sends normalized value text and pages with scan_results", async () => {
    const { calls } = mockApi(({ action, params }) => {
      if (action === "scan")
        return {
          hits: [{ addr: 0x10, bits: 100, formatted: "100", type: "u32" }],
          total: 2500,
          offset: 0,
          next_offset: 1000,
        };
      if (action === "scan_results")
        return {
          total: 2500,
          offset: params.offset,
          results: [{ address: 0x20, value: 100, address_hex: "0x20" }],
          next_offset: 2000,
        };
      return {};
    });
    useScanner.setState({ width: "u32", kind: "exact", value: "0x64" });
    await useScanner.getState().scan(false);
    expect(calls[0].params).toMatchObject({ value: "100", offset: 0, limit: 1000 });
    expect(useScanner.getState().total).toBe(2500);

    await useScanner.getState().page(1000);
    const s = useScanner.getState();
    expect(calls[1]).toMatchObject({
      action: "scan_results",
      params: { offset: 1000, limit: 1000 },
    });
    expect(s.offset).toBe(1000);
    expect(s.hits).toEqual([{ addr: 0x20, bits: 100, formatted: "100", type: "u32" }]);
  });

  it("refuses a value the width cannot hold without calling the engine", async () => {
    const { calls } = mockApi(() => ({}));
    useScanner.setState({ width: "u8", kind: "exact", value: "1.5" });
    await useScanner.getState().scan(false);
    expect(calls).toHaveLength(0);
    expect(useScanner.getState().error).toContain("f32 or f64");
  });
});
