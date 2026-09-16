import doctorModel from "../models/doctorModel.js";
import { isValidSlotDate } from "./validation.js";

const SLOT_DATE_KEY_RE = /^\d{1,2}_\d{1,2}_\d{4}$/;

export const slotPath = (slotDate) => `slots_booked.${slotDate}`;

/**
 * Atomically reserve a slot. The filter only matches when the doctor exists,
 * is available and the time is not already in that day's list, and $push runs
 * in the same single-document operation, so two concurrent requests can never
 * both book the same slot (CWE-362 race condition).
 *
 * Resolves to the doctor's pre-update data (without password/email/slots) or
 * null when the reservation was not possible.
 */
export function reserveDoctorSlot(docId, slotDate, slotTime) {
  if (!isValidSlotDate(slotDate)) return Promise.resolve(null);
  return doctorModel
    .findOneAndUpdate(
      { _id: docId, available: true, [slotPath(slotDate)]: { $ne: slotTime } },
      { $push: { [slotPath(slotDate)]: slotTime } },
      { new: false }
    )
    .select("name image speciality degree experience about fees address")
    .lean();
}

/**
 * Release a booked slot with an atomic $pull instead of read-modify-write of
 * the whole slots_booked object (which could lose concurrent changes).
 */
export async function releaseDoctorSlot({ docId, slotDate, slotTime }) {
  // Stored dates were validated at booking time; still refuse anything that
  // could be interpreted as a nested path or operator.
  if (typeof slotDate !== "string" || !SLOT_DATE_KEY_RE.test(slotDate)) return;
  await doctorModel.updateOne(
    { _id: docId },
    { $pull: { [slotPath(slotDate)]: slotTime } }
  );
}
