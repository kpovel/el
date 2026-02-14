import type { Incident } from "./db/index.js";

export interface DurationRange {
  min: number;
  max: number;
}

export interface OutagePrediction {
  nextOutage: {
    expectedStart: Date;
    probability: number;
    expectedDurationMin: number;
    durationRange: DurationRange;
  } | null;

  currentOutageEnd: {
    expectedEnd: Date;
    durationRange: DurationRange;
  } | null;

  hourlyRisk: Array<{
    hour: Date;
    probability: number;
  }>;

  meta: {
    dataPoints: number;
    dataSpanDays: number;
    confidence: "low" | "medium" | "high";
  };
}

const SLOTS_PER_DAY = 96;
const SLOT_MS = 15 * 60 * 1000;
const HOURS_PER_DAY = 24;

export function exponentialSmoothing(
  values: number[],
  alpha: number = 0.3,
): { smoothed: number; error: number } {
  if (values.length === 0) return { smoothed: 0, error: 0 };
  if (values.length === 1) return { smoothed: values[0], error: values[0] * 0.5 };

  let s = values[0];
  let totalAbsError = 0;

  for (let i = 1; i < values.length; i++) {
    const err = Math.abs(values[i] - s);
    totalAbsError += err;
    s = alpha * values[i] + (1 - alpha) * s;
  }

  const mae = totalAbsError / (values.length - 1);
  return { smoothed: s, error: mae };
}

export function buildSlotProbabilities(
  incidents: Incident[],
  now: number,
): number[] {
  const probs = new Array(SLOTS_PER_DAY).fill(0);
  if (incidents.length === 0) return probs;

  const oldest = Math.min(...incidents.map((i) => i.start));
  const totalDays = Math.max(1, Math.ceil((now - oldest) / (24 * 60 * 60 * 1000)));

  const slotHits = new Array(SLOTS_PER_DAY).fill(0);

  for (const inc of incidents) {
    const d = new Date(inc.start);
    const minuteOfDay = d.getHours() * 60 + d.getMinutes();
    const startSlot = Math.floor(minuteOfDay / 15);

    const slotsSpanned = Math.max(1, Math.ceil(inc.durationMin / 15));
    for (let s = 0; s < slotsSpanned && s + startSlot < SLOTS_PER_DAY; s++) {
      slotHits[startSlot + s]++;
    }
  }

  for (let i = 0; i < SLOTS_PER_DAY; i++) {
    probs[i] = Math.min(1, slotHits[i] / totalDays);
  }

  return probs;
}

export function buildDayOfWeekWeights(incidents: Incident[]): number[] {
  const counts = new Array(7).fill(0);
  const dayCoverage = new Array(7).fill(0);

  if (incidents.length === 0) return new Array(7).fill(1);

  const oldest = Math.min(...incidents.map((i) => i.start));
  const newest = Math.max(...incidents.map((i) => i.start));
  const d = new Date(oldest);
  d.setHours(0, 0, 0, 0);
  while (d.getTime() <= newest) {
    dayCoverage[d.getDay()]++;
    d.setDate(d.getDate() + 1);
  }

  for (const inc of incidents) {
    const day = new Date(inc.start).getDay();
    counts[day]++;
  }

  const weights = new Array(7).fill(0);
  const totalIncidents = incidents.length;
  const avgPerDay = totalIncidents / 7;

  for (let i = 0; i < 7; i++) {
    if (dayCoverage[i] === 0) {
      weights[i] = 1;
    } else {
      const rate = counts[i] / dayCoverage[i];
      const avgRate = totalIncidents / Math.max(1, dayCoverage.reduce((a: number, b: number) => a + b, 0));
      weights[i] = avgRate > 0 ? rate / avgRate : 1;
    }
  }

  return weights;
}

export function predictDuration(
  incidents: Incident[],
  alpha: number = 0.3,
): { expectedMin: number; range: DurationRange } {
  if (incidents.length === 0) {
    return { expectedMin: 0, range: { min: 0, max: 0 } };
  }

  const durations = incidents.map((i) => i.durationMin);
  const { smoothed, error } = exponentialSmoothing(durations, alpha);

  return {
    expectedMin: Math.round(smoothed),
    range: {
      min: Math.max(1, Math.round(smoothed - 1.5 * error)),
      max: Math.round(smoothed + 1.5 * error),
    },
  };
}

export function predictDurationByTimeOfDay(
  incidents: Incident[],
  hour: number,
  alpha: number = 0.3,
): { expectedMin: number; range: DurationRange } | null {
  const hourIncidents = incidents.filter((i) => {
    const h = new Date(i.start).getHours();
    return Math.abs(h - hour) <= 2 || Math.abs(h - hour) >= 22;
  });

  if (hourIncidents.length < 2) return null;
  return predictDuration(hourIncidents, alpha);
}

export function computeHourlyRisk(
  slotProbs: number[],
  dayWeights: number[],
  now: number,
  hours: number = 24,
): Array<{ hour: Date; probability: number }> {
  const result: Array<{ hour: Date; probability: number }> = [];
  const currentHour = new Date(now);
  currentHour.setMinutes(0, 0, 0);

  for (let h = 0; h < hours; h++) {
    const hourDate = new Date(currentHour.getTime() + h * 60 * 60 * 1000);
    const dayWeight = dayWeights[hourDate.getDay()];
    const hourOfDay = hourDate.getHours();

    const slot1 = hourOfDay * 4;
    const slot2 = slot1 + 1;
    const slot3 = slot1 + 2;
    const slot4 = slot1 + 3;

    const avgSlotProb =
      (slotProbs[slot1] + slotProbs[slot2] + slotProbs[slot3] + slotProbs[slot4]) / 4;

    const combined = Math.min(1, avgSlotProb * dayWeight);

    result.push({ hour: hourDate, probability: Math.round(combined * 1000) / 1000 });
  }

  return result;
}

function findNextHighRiskWindow(
  hourlyRisk: Array<{ hour: Date; probability: number }>,
  threshold: number = 0.05,
): { hour: Date; probability: number } | null {
  for (const entry of hourlyRisk) {
    if (entry.probability >= threshold) {
      return entry;
    }
  }

  if (hourlyRisk.length === 0) return null;

  let best = hourlyRisk[0];
  for (const entry of hourlyRisk) {
    if (entry.probability > best.probability) {
      best = entry;
    }
  }

  return best.probability > 0 ? best : null;
}

function computeConfidence(
  dataPoints: number,
  dataSpanDays: number,
): "low" | "medium" | "high" {
  if (dataPoints < 3 || dataSpanDays < 3) return "low";
  if (dataPoints < 10 || dataSpanDays < 7) return "medium";
  return "high";
}

export function predict(
  incidents: Incident[],
  currentStatus: "UP" | "DOWN" | null,
  now: number = Date.now(),
  alpha: number = 0.3,
): OutagePrediction {
  const dataPoints = incidents.length;
  const dataSpanDays =
    dataPoints > 0
      ? Math.ceil(
          (now - Math.min(...incidents.map((i) => i.start))) /
            (24 * 60 * 60 * 1000),
        )
      : 0;

  const confidence = computeConfidence(dataPoints, dataSpanDays);

  if (dataPoints === 0) {
    return {
      nextOutage: null,
      currentOutageEnd: null,
      hourlyRisk: computeHourlyRisk(
        new Array(SLOTS_PER_DAY).fill(0),
        new Array(7).fill(1),
        now,
      ),
      meta: { dataPoints: 0, dataSpanDays: 0, confidence: "low" },
    };
  }

  const slotProbs = buildSlotProbabilities(incidents, now);
  const dayWeights = buildDayOfWeekWeights(incidents);
  const hourlyRisk = computeHourlyRisk(slotProbs, dayWeights, now);
  const { expectedMin, range } = predictDuration(incidents, alpha);

  let nextOutage: OutagePrediction["nextOutage"] = null;
  if (currentStatus !== "DOWN") {
    const nextWindow = findNextHighRiskWindow(hourlyRisk);
    if (nextWindow) {
      const hourSpecific = predictDurationByTimeOfDay(
        incidents,
        nextWindow.hour.getHours(),
        alpha,
      );
      const duration = hourSpecific ?? { expectedMin: expectedMin, range };

      nextOutage = {
        expectedStart: nextWindow.hour,
        probability: nextWindow.probability,
        expectedDurationMin: duration.expectedMin,
        durationRange: duration.range,
      };
    }
  }

  let currentOutageEnd: OutagePrediction["currentOutageEnd"] = null;
  if (currentStatus === "DOWN") {
    const ongoingIncident = incidents.find(
      (i) => i.end >= now - 60_000 && i.start <= now,
    );
    const elapsedMin = ongoingIncident
      ? Math.round((now - ongoingIncident.start) / 60_000)
      : 0;

    const currentHour = new Date(now).getHours();
    const hourSpecific = predictDurationByTimeOfDay(
      incidents,
      currentHour,
      alpha,
    );
    const duration = hourSpecific ?? { expectedMin: expectedMin, range };

    const remainingMin = Math.max(1, duration.expectedMin - elapsedMin);
    const expectedEnd = new Date(now + remainingMin * 60_000);

    currentOutageEnd = {
      expectedEnd,
      durationRange: {
        min: Math.max(1, duration.range.min - elapsedMin),
        max: Math.max(1, duration.range.max - elapsedMin),
      },
    };
  }

  return {
    nextOutage,
    currentOutageEnd,
    hourlyRisk,
    meta: { dataPoints, dataSpanDays, confidence },
  };
}
