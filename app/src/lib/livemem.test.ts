import { describe, expect, it } from "vitest";
import {
  accessLenFor,
  encodeTyped,
  formatChain,
  formatOffset,
  pageInfo,
  parseScanValue,
  sparkPoints,
  type Parsed,
} from "@/lib/livemem";

describe("parseScanValue", () => {
  it("normalizes integers per width", () => {
    expect(parseScanValue("100", "u32")).toEqual({ ok: true, value: "100" });
    expect(parseScanValue(" 0x64 ", "u32")).toEqual({ ok: true, value: "100" });
    expect(parseScanValue("1_000", "i32")).toEqual({ ok: true, value: "1000" });
    // decimal, never octal like strtoll(…, 0)
    expect(parseScanValue("010", "u16")).toEqual({ ok: true, value: "10" });
    expect(parseScanValue("-5", "i8")).toEqual({ ok: true, value: "-5" });
    // an unsigned spelling of a signed width wraps to two's complement
    expect(parseScanValue("0xFF", "i8")).toEqual({ ok: true, value: "-1" });
    expect(parseScanValue("0xFFFFFFFFFFFFFFFF", "i64")).toEqual({ ok: true, value: "-1" });
    expect(parseScanValue("0xFFFFFFFFFFFFFFFF", "u64")).toEqual({
      ok: true,
      value: "18446744073709551615",
    });
  });

  it("rejects what the width cannot hold", () => {
    expect(parseScanValue("", "u32")).toEqual({ ok: false, error: "empty" });
    expect(parseScanValue("abc", "u32")).toEqual({ ok: false, error: "syntax" });
    expect(parseScanValue("1.5", "u32")).toEqual({ ok: false, error: "float_for_int" });
    expect(parseScanValue("-1", "u8")).toEqual({ ok: false, error: "negative_unsigned" });
    expect(parseScanValue("256", "u8")).toEqual({ ok: false, error: "range" });
    expect(parseScanValue("-129", "i8")).toEqual({ ok: false, error: "range" });
  });

  it("keeps float text and accepts a decimal comma", () => {
    expect(parseScanValue("1.25", "f32")).toEqual({ ok: true, value: "1.25" });
    expect(parseScanValue("1,25", "f64")).toEqual({ ok: true, value: "1.25" });
    expect(parseScanValue("1e3", "f64")).toEqual({ ok: true, value: "1e3" });
    expect(parseScanValue("0x10", "f32")).toEqual({ ok: true, value: "16" });
    expect(parseScanValue("1.2.3", "f32")).toEqual({ ok: false, error: "syntax" });
    expect(parseScanValue("2.5", "all")).toEqual({ ok: true, value: "2.5" });
  });
});

describe("encodeTyped", () => {
  const bytes = (r: Parsed<Uint8Array>) => (r.ok ? [...r.value] : r.error);

  it("writes little-endian integers and floats", () => {
    expect(bytes(encodeTyped("u32", "0x11223344"))).toEqual([0x44, 0x33, 0x22, 0x11]);
    expect(bytes(encodeTyped("i16", "-2"))).toEqual([0xfe, 0xff]);
    expect(bytes(encodeTyped("u8", "300"))).toBe("range");
    expect(bytes(encodeTyped("f32", "1"))).toEqual([0, 0, 0x80, 0x3f]);
    expect(bytes(encodeTyped("f64", "1"))).toEqual([0, 0, 0, 0, 0, 0, 0xf0, 0x3f]);
  });

  it("writes strings and hex byte lists", () => {
    expect(bytes(encodeTyped("string", "AB"))).toEqual([0x41, 0x42]);
    expect(bytes(encodeTyped("bytes", "DE AD be ef"))).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(bytes(encodeTyped("bytes", "ABC"))).toBe("syntax");
    expect(bytes(encodeTyped("string", ""))).toBe("empty");
  });
});

describe("pageInfo", () => {
  it("places a page inside the total", () => {
    expect(pageInfo(0, 1000, 2500, 1000)).toEqual({
      from: 1,
      to: 1000,
      page: 1,
      pages: 3,
      prevOffset: null,
      nextOffset: 1000,
      lastOffset: 2000,
    });
    const last = pageInfo(2000, 500, 2500, 1000);
    expect(last).toMatchObject({
      from: 2001,
      to: 2500,
      page: 3,
      prevOffset: 1000,
      nextOffset: null,
    });
  });

  it("handles an empty result set", () => {
    expect(pageInfo(0, 0, 0, 1000)).toMatchObject({
      from: 0,
      to: 0,
      pages: 1,
      prevOffset: null,
      nextOffset: null,
      lastOffset: 0,
    });
  });
});

describe("pointer chains", () => {
  const moduleChain = {
    addresses: [0x140001000, 0x2000, 0x3000],
    offsets: [0x10, -0x8, 0x1a0],
    module: "game.exe",
    module_offset: 0x1000,
  };

  it("formats module-relative and absolute roots", () => {
    expect(formatOffset(-8)).toBe("-0x8");
    expect(formatChain(moduleChain)).toBe("game.exe+0x1000 → +0x10 → -0x8 → +0x1A0");
    expect(formatChain({ addresses: [0x7ff000], offsets: [0x20] })).toBe("0x7FF000 → +0x20");
  });
});

describe("accessLenFor", () => {
  it("maps value widths to debug-register lengths", () => {
    expect(accessLenFor("u8")).toBe(1);
    expect(accessLenFor("i16")).toBe(2);
    expect(accessLenFor("f32")).toBe(4);
    expect(accessLenFor("f64")).toBe(8);
    expect(accessLenFor("all")).toBe(4);
  });
});

describe("sparkPoints", () => {
  it("scales into the box and survives flat or single series", () => {
    expect(sparkPoints([], 100, 20)).toBe("");
    expect(sparkPoints([0, 10], 100, 20)).toBe("0.0,20.0 100.0,0.0");
    expect(sparkPoints([5, 5, 5], 100, 20)).toBe("0.0,10.0 50.0,10.0 100.0,10.0");
    expect(sparkPoints([7], 100, 20)).toBe("0,10.0 100,10.0");
  });
});
