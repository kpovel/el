import { describe, test, expect } from "bun:test";
import {
  exponentialSmoothing,
  buildSlotProbabilities,
  buildDayOfWeekWeights,
  predictDuration,
  predictDurationByTimeOfDay,
  computeHourlyRisk,
  predict,
} from "./prediction.js";
import type { Incident } from "./db/index.js";

function makeIncident(
  startDate: Date,
  durationMin: number,
): Incident {
  const start = startDate.getTime();
  return {
    start,
    end: start + durationMin * 60_000,
    durationMin,
  };
}

const FIXED_NOW = new Date(2026, 1, 10, 10, 0, 0, 0).getTime();

function daysAgo(days: number, hour: number = 14, minute: number = 0): Date {
  const d = new Date(FIXED_NOW);
  d.setDate(d.getDate() - days);
  d.setHours(hour, minute, 0, 0);
  return d;
}

describe("exponentialSmoothing", () => {
  test("empty input returns zero", () => {
    const result = exponentialSmoothing([]);
    expect(result.smoothed).toBe(0);
    expect(result.error).toBe(0);
  });

  test("single value returns itself", () => {
    const result = exponentialSmoothing([42]);
    expect(result.smoothed).toBe(42);
  });

  test("constant series converges to that constant", () => {
    const values = new Array(20).fill(30);
    const result = exponentialSmoothing(values, 0.3);
    expect(result.smoothed).toBeCloseTo(30, 5);
    expect(result.error).toBeCloseTo(0, 5);
  });

  test("recent values have more weight than older ones", () => {
    const values = [10, 10, 10, 10, 10, 50, 50, 50];
    const result = exponentialSmoothing(values, 0.3);
    expect(result.smoothed).toBeGreaterThan(30);
  });

  test("alpha=1 always returns the last value", () => {
    const values = [10, 20, 30, 40, 50];
    const result = exponentialSmoothing(values, 1.0);
    expect(result.smoothed).toBe(50);
  });

  test("alpha=0 always returns the first value", () => {
    const values = [10, 20, 30, 40, 50];
    const result = exponentialSmoothing(values, 0.0);
    expect(result.smoothed).toBe(10);
  });

  test("upward trend produces higher smoothed value than mean", () => {
    const values = [10, 15, 20, 25, 30, 35, 40];
    const mean = values.reduce((a, b) => a + b) / values.length;
    const result = exponentialSmoothing(values, 0.3);
    expect(result.smoothed).toBeGreaterThan(mean);
  });
});

describe("buildSlotProbabilities", () => {
  test("no incidents produces all-zero probabilities", () => {
    const probs = buildSlotProbabilities([], Date.now());
    expect(probs).toHaveLength(96);
    expect(probs.every((p) => p === 0)).toBe(true);
  });

  test("single incident raises probability for its time slot", () => {
    const inc = makeIncident(daysAgo(1, 14, 0), 30);
    const probs = buildSlotProbabilities([inc], FIXED_NOW);

    const slot14h = 14 * 4;
    expect(probs[slot14h]).toBeGreaterThan(0);

    const slot3am = 3 * 4;
    expect(probs[slot3am]).toBe(0);
  });

  test("repeated outages at the same time increase probability", () => {
    const incidents = [
      makeIncident(daysAgo(1, 14, 0), 15),
      makeIncident(daysAgo(2, 14, 0), 15),
      makeIncident(daysAgo(3, 14, 0), 15),
    ];
    const probs = buildSlotProbabilities(incidents, FIXED_NOW);
    const slot14h = 14 * 4;

    expect(probs[slot14h]).toBeGreaterThan(0.5);
  });

  test("longer outages cover more slots", () => {
    const inc = makeIncident(daysAgo(1, 10, 0), 120);
    const probs = buildSlotProbabilities([inc], FIXED_NOW);

    const slot10h = 10 * 4;
    const slot11h = 11 * 4;
    expect(probs[slot10h]).toBeGreaterThan(0);
    expect(probs[slot11h]).toBeGreaterThan(0);
  });

  test("probabilities never exceed 1", () => {
    const incidents = Array.from({ length: 30 }, (_, i) =>
      makeIncident(daysAgo(i + 1, 14, 0), 15),
    );
    const probs = buildSlotProbabilities(incidents, FIXED_NOW);
    expect(probs.every((p) => p <= 1)).toBe(true);
  });
});

describe("buildDayOfWeekWeights", () => {
  test("no incidents returns uniform weights", () => {
    const weights = buildDayOfWeekWeights([]);
    expect(weights).toHaveLength(7);
    expect(weights.every((w) => w === 1)).toBe(true);
  });

  test("incidents concentrated on one day give that day higher weight", () => {
    const incidents: Incident[] = [];
    for (let i = 1; i <= 28; i++) {
      const d = daysAgo(i, 14, 0);
      if (d.getDay() === 1) {
        incidents.push(makeIncident(d, 30));
      }
    }

    if (incidents.length === 0) return;

    const weights = buildDayOfWeekWeights(incidents);
    const mondayWeight = weights[1];

    const otherWeights = weights.filter((_, i) => i !== 1);
    for (const ow of otherWeights) {
      expect(mondayWeight).toBeGreaterThanOrEqual(ow);
    }
  });

  test("evenly spread incidents produce roughly equal weights", () => {
    const incidents: Incident[] = [];
    for (let i = 1; i <= 14; i++) {
      incidents.push(makeIncident(daysAgo(i, 14, 0), 20));
    }

    const weights = buildDayOfWeekWeights(incidents);
    const avg = weights.reduce((a, b) => a + b) / 7;

    for (const w of weights) {
      expect(w).toBeGreaterThan(avg * 0.3);
      expect(w).toBeLessThan(avg * 3);
    }
  });
});

describe("predictDuration", () => {
  test("no incidents returns zero", () => {
    const result = predictDuration([]);
    expect(result.expectedMin).toBe(0);
    expect(result.range.min).toBe(0);
    expect(result.range.max).toBe(0);
  });

  test("constant durations converge to that duration", () => {
    const incidents = Array.from({ length: 10 }, (_, i) =>
      makeIncident(daysAgo(i + 1, 14, 0), 45),
    );
    const result = predictDuration(incidents, 0.3);
    expect(result.expectedMin).toBe(45);
    expect(result.range.min).toBeLessThanOrEqual(45);
    expect(result.range.max).toBeGreaterThanOrEqual(45);
  });

  test("increasing durations bias prediction upward", () => {
    const incidents = [
      makeIncident(daysAgo(5, 14), 10),
      makeIncident(daysAgo(4, 14), 20),
      makeIncident(daysAgo(3, 14), 30),
      makeIncident(daysAgo(2, 14), 40),
      makeIncident(daysAgo(1, 14), 50),
    ];
    const result = predictDuration(incidents, 0.3);
    const simpleMean = 30;
    expect(result.expectedMin).toBeGreaterThan(simpleMean);
  });

  test("range min is always >= 1 for non-empty input", () => {
    const incidents = [makeIncident(daysAgo(1, 14), 2)];
    const result = predictDuration(incidents);
    expect(result.range.min).toBeGreaterThanOrEqual(1);
  });
});

describe("predictDurationByTimeOfDay", () => {
  test("returns null with insufficient incidents near the hour", () => {
    const incidents = [makeIncident(daysAgo(1, 14), 30)];
    const result = predictDurationByTimeOfDay(incidents, 3);
    expect(result).toBeNull();
  });

  test("returns prediction for hours with enough nearby incidents", () => {
    const incidents = [
      makeIncident(daysAgo(1, 14), 30),
      makeIncident(daysAgo(2, 15), 40),
      makeIncident(daysAgo(3, 13), 20),
    ];
    const result = predictDurationByTimeOfDay(incidents, 14);
    expect(result).not.toBeNull();
    expect(result!.expectedMin).toBeGreaterThan(0);
  });

  test("morning incidents don't influence evening predictions", () => {
    const morningIncidents = [
      makeIncident(daysAgo(1, 6), 30),
      makeIncident(daysAgo(2, 7), 40),
      makeIncident(daysAgo(3, 5), 20),
    ];
    const result = predictDurationByTimeOfDay(morningIncidents, 20);
    expect(result).toBeNull();
  });
});

describe("computeHourlyRisk", () => {
  test("zero probabilities produce zero risk", () => {
    const slotProbs = new Array(96).fill(0);
    const dayWeights = new Array(7).fill(1);
    const risk = computeHourlyRisk(slotProbs, dayWeights, FIXED_NOW);
    expect(risk).toHaveLength(24);
    expect(risk.every((r) => r.probability === 0)).toBe(true);
  });

  test("produces 24 entries by default", () => {
    const slotProbs = new Array(96).fill(0.1);
    const dayWeights = new Array(7).fill(1);
    const risk = computeHourlyRisk(slotProbs, dayWeights, FIXED_NOW);
    expect(risk).toHaveLength(24);
  });

  test("higher slot probability produces higher hourly risk", () => {
    const slotProbs = new Array(96).fill(0);
    slotProbs[14 * 4] = 0.8;
    slotProbs[14 * 4 + 1] = 0.8;
    slotProbs[14 * 4 + 2] = 0.8;
    slotProbs[14 * 4 + 3] = 0.8;

    const dayWeights = new Array(7).fill(1);
    const risk = computeHourlyRisk(slotProbs, dayWeights, FIXED_NOW);

    const risk14 = risk.find(
      (r) => r.hour.getHours() === 14,
    );
    const risk3 = risk.find(
      (r) => r.hour.getHours() === 3,
    );

    expect(risk14).toBeDefined();
    expect(risk3).toBeDefined();
    expect(risk14!.probability).toBeGreaterThan(risk3!.probability);
  });

  test("day-of-week weight scales probability correctly", () => {
    const slotProbs = new Array(96).fill(0.5);
    const dayWeights = new Array(7).fill(0);
    const fixedDate = new Date(FIXED_NOW);
    const today = fixedDate.getDay();
    dayWeights[today] = 2;

    const tomorrow = (today + 1) % 7;
    dayWeights[tomorrow] = 0.1;

    const risk = computeHourlyRisk(slotProbs, dayWeights, FIXED_NOW);

    const todayRisks = risk.filter(
      (r) => r.hour.getDay() === today,
    );
    const tomorrowRisks = risk.filter(
      (r) => r.hour.getDay() === tomorrow,
    );

    expect(todayRisks.length).toBeGreaterThan(0);
    expect(tomorrowRisks.length).toBeGreaterThan(0);
    const avgToday =
      todayRisks.reduce((s, r) => s + r.probability, 0) / todayRisks.length;
    const avgTomorrow =
      tomorrowRisks.reduce((s, r) => s + r.probability, 0) /
      tomorrowRisks.length;
    expect(avgToday).toBeGreaterThan(avgTomorrow);
  });

  test("probabilities are capped at 1", () => {
    const slotProbs = new Array(96).fill(0.9);
    const dayWeights = new Array(7).fill(3);
    const risk = computeHourlyRisk(slotProbs, dayWeights, FIXED_NOW);
    expect(risk.every((r) => r.probability <= 1)).toBe(true);
  });
});

describe("predict (integration)", () => {
  test("no data returns null predictions with low confidence", () => {
    const result = predict([], "UP", FIXED_NOW);
    expect(result.nextOutage).toBeNull();
    expect(result.currentOutageEnd).toBeNull();
    expect(result.hourlyRisk).toHaveLength(24);
    expect(result.meta.dataPoints).toBe(0);
    expect(result.meta.confidence).toBe("low");
  });

  test("single incident returns low confidence", () => {
    const incidents = [makeIncident(daysAgo(1, 14), 30)];
    const result = predict(incidents, "UP", FIXED_NOW);
    expect(result.meta.confidence).toBe("low");
    expect(result.meta.dataPoints).toBe(1);
  });

  test("3+ incidents over 3+ days gives medium confidence", () => {
    const incidents = [
      makeIncident(daysAgo(5, 14), 30),
      makeIncident(daysAgo(3, 14), 25),
      makeIncident(daysAgo(1, 14), 35),
    ];
    const result = predict(incidents, "UP", FIXED_NOW);
    expect(result.meta.confidence).toBe("medium");
  });

  test("10+ incidents over 7+ days gives high confidence", () => {
    const incidents = Array.from({ length: 12 }, (_, i) =>
      makeIncident(daysAgo(i + 1, 14), 20 + i),
    );
    const result = predict(incidents, "UP", FIXED_NOW);
    expect(result.meta.confidence).toBe("high");
  });

  test("when UP, nextOutage is populated if enough data", () => {
    const incidents = Array.from({ length: 10 }, (_, i) =>
      makeIncident(daysAgo(i + 1, 14), 30),
    );
    const result = predict(incidents, "UP", FIXED_NOW);
    expect(result.nextOutage).not.toBeNull();
    expect(result.nextOutage!.expectedDurationMin).toBeGreaterThan(0);
    expect(result.nextOutage!.probability).toBeGreaterThan(0);
    expect(result.currentOutageEnd).toBeNull();
  });

  test("when DOWN, currentOutageEnd is populated", () => {
    const incidents = [
      makeIncident(daysAgo(3, 14), 60),
      makeIncident(daysAgo(2, 14), 45),
      makeIncident(daysAgo(1, 14), 50),
      {
        start: FIXED_NOW - 10 * 60_000,
        end: FIXED_NOW,
        durationMin: 10,
      },
    ];
    const result = predict(incidents, "DOWN", FIXED_NOW);
    expect(result.currentOutageEnd).not.toBeNull();
    expect(result.currentOutageEnd!.expectedEnd.getTime()).toBeGreaterThan(FIXED_NOW);
    expect(result.nextOutage).toBeNull();
  });

  test("hourlyRisk always has 24 entries", () => {
    const incidents = [makeIncident(daysAgo(1, 14), 30)];
    const result = predict(incidents, "UP", FIXED_NOW);
    expect(result.hourlyRisk).toHaveLength(24);
  });

  test("regular daily outage pattern produces high probability at that time", () => {
    const incidents = Array.from({ length: 14 }, (_, i) =>
      makeIncident(daysAgo(i + 1, 14), 30),
    );
    const result = predict(incidents, "UP", FIXED_NOW);

    const risk14 = result.hourlyRisk.find((r) => r.hour.getHours() === 14);
    const risk4 = result.hourlyRisk.find((r) => r.hour.getHours() === 4);

    expect(risk14).toBeDefined();
    expect(risk4).toBeDefined();
    expect(risk14!.probability).toBeGreaterThan(risk4!.probability);
  });

  test("predicted duration matches pattern of historical durations", () => {
    const incidents = Array.from({ length: 10 }, (_, i) =>
      makeIncident(daysAgo(i + 1, 14), 30),
    );
    const result = predict(incidents, "UP", FIXED_NOW);
    expect(result.nextOutage).not.toBeNull();
    expect(result.nextOutage!.expectedDurationMin).toBeCloseTo(30, 0);
  });

  test("dataSpanDays reflects actual span of incident data", () => {
    const incidents = [
      makeIncident(daysAgo(20, 14), 30),
      makeIncident(daysAgo(1, 14), 30),
    ];
    const result = predict(incidents, "UP", FIXED_NOW);
    expect(result.meta.dataSpanDays).toBeGreaterThanOrEqual(19);
    expect(result.meta.dataSpanDays).toBeLessThanOrEqual(21);
  });

  test("null status is treated like UP (no currentOutageEnd)", () => {
    const incidents = [
      makeIncident(daysAgo(2, 14), 30),
      makeIncident(daysAgo(1, 14), 30),
      makeIncident(daysAgo(3, 14), 30),
    ];
    const result = predict(incidents, null, FIXED_NOW);
    expect(result.currentOutageEnd).toBeNull();
  });
});
