/**
 * Small input validators shared by the controllers. Every value that reaches a
 * query, an update path or a stored document is checked here first
 * (CWE-20: improper input validation).
 */

const OBJECT_ID_RE = /^[a-f\d]{24}$/i;

export const isObjectId = (value) =>
  typeof value === "string" && OBJECT_ID_RE.test(value);

export const isBoundedString = (value, maxLength, { allowEmpty = false } = {}) =>
  typeof value === "string" &&
  value.length <= maxLength &&
  (allowEmpty || value.trim().length > 0);

/**
 * Addresses arrive as a JSON string (multipart forms) or an object (JSON
 * bodies). Only { line1, line2 } strings are kept; anything else, including
 * malformed JSON, extra keys and nested objects, is rejected or dropped.
 */
export function parseAddress(raw) {
  let value = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;

  const { line1 = "", line2 = "" } = value;
  if (
    !isBoundedString(line1, 200, { allowEmpty: true }) ||
    !isBoundedString(line2, 200, { allowEmpty: true })
  ) {
    return null;
  }
  return { line1, line2 };
}

export const GENDERS = ["Male", "Female", "Not Selected"];

export const isValidPhone = (value) =>
  typeof value === "string" && /^\+?[\d\s()-]{7,20}$/.test(value);

// "YYYY-MM-DD" (from <input type="date">) that is a real date in the past,
// or the schema default "Not Selected".
export function isValidDob(value) {
  if (value === "Not Selected") return true;
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return (
    !Number.isNaN(date.getTime()) &&
    date.toISOString().startsWith(value) &&
    date.getTime() <= Date.now()
  );
}

// Consultation fee: a finite, non-negative number with a sane upper bound.
export function parseFees(value) {
  const number =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim() !== ""
        ? Number(value)
        : NaN;
  return Number.isFinite(number) && number >= 0 && number <= 1_000_000 ? number : null;
}

// Slot dates are written by the frontend as "<day>_<month>_<year>" and used as
// a key inside doctor.slots_booked, so they must never contain '.', '$' or
// prototype keys such as "__proto__".
const SLOT_DATE_RE = /^(\d{1,2})_(\d{1,2})_(\d{4})$/;
const MAX_DAYS_AHEAD = 60;
const DAY_MS = 24 * 60 * 60 * 1000;

export function isValidSlotDate(value, now = new Date()) {
  if (typeof value !== "string") return false;
  const match = SLOT_DATE_RE.exec(value);
  if (!match) return false;

  const [day, month, year] = match.slice(1).map(Number);
  const date = new Date(year, month - 1, day);
  // Reject impossible dates such as 31_2_2026 (Date would roll them over).
  if (
    date.getFullYear() !== year ||
    date.getMonth() !== month - 1 ||
    date.getDate() !== day
  ) {
    return false;
  }

  // Allow one day of slack for client/server time-zone differences.
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const earliest = today.getTime() - DAY_MS;
  const latest = today.getTime() + MAX_DAYS_AHEAD * DAY_MS;
  return date.getTime() >= earliest && date.getTime() <= latest;
}

// Times come from toLocaleTimeString(): "10:30 AM", "10:30", "10:30 a.m.";
// recent ICU versions put a narrow no-break space (U+202F) before AM/PM.
const SLOT_TIME_RE = /^\d{1,2}[:.]\d{2}(?:[\s  ]?[AaPp]\.?\s?[Mm]\.?)?$/;

export const isValidSlotTime = (value) =>
  typeof value === "string" && value.length <= 16 && SLOT_TIME_RE.test(value);
