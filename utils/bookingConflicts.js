/**
 * A booking blocks its time range while it is "scheduled", and also while it is "pending_sync"
 * (created, but the Google Calendar call has not committed yet). Ignoring pending_sync lets a
 * second request book the same slot during the external API call. A pending_sync row older than
 * PENDING_SYNC_TTL_MS is treated as an abandoned crash leftover so it cannot block a slot forever.
 */
const PENDING_SYNC_TTL_MS = 2 * 60 * 1000;

function activeBookingFilter(now = new Date()) {
  return {
    $or: [
      { status: "scheduled" },
      { status: "pending_sync", createdAt: { $gt: new Date(now.getTime() - PENDING_SYNC_TTL_MS) } },
    ],
  };
}

/**
 * Query for bookings that conflict with a requested [start, end) range, using the same buffer
 * semantics as the slot picker (a slot is blocked when start < bookingEnd + bufferAfter and
 * end > bookingStart - bufferBefore).
 */
function buildConflictQuery({ userId, start, end, bufferBeforeMs = 0, bufferAfterMs = 0, now = new Date() }) {
  return {
    userId,
    ...activeBookingFilter(now),
    startTime: { $lt: new Date(end.getTime() + bufferBeforeMs) },
    endTime: { $gt: new Date(start.getTime() - bufferAfterMs) },
  };
}

module.exports = { PENDING_SYNC_TTL_MS, activeBookingFilter, buildConflictQuery };
