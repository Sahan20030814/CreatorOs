/**
 * Regression tests for double-booking protection:
 *  - lock ownership (a stale holder must never free a newer holder's lock)
 *  - pending_sync bookings and buffers count as conflicts in createBooking
 * Models are replaced with small in-memory fakes so no database is needed.
 */
const mockBookings = [];
jest.mock("../../model/meetingBooking", () => {
  const get = (o, k) => o[k];
  const match = (doc, q) =>
    Object.entries(q).every(([k, c]) => {
      if (k === "$or") return c.some((sub) => match(doc, sub));
      const v = get(doc, k);
      if (c && typeof c === "object" && !(c instanceof Date) && !(c && c._bsontype) && !Array.isArray(c)) {
        if ("$lt" in c && !(v < c.$lt)) return false;
        if ("$gt" in c && !(v > c.$gt)) return false;
        return true;
      }
      return String(v) === String(c);
    });
  return {
    findOne: jest.fn(async (q) => mockBookings.find((d) => match(d, q)) || null),
    create: jest.fn(async (data) => {
      const doc = { _id: `b${mockBookings.length + 1}`, createdAt: new Date(), ...data };
      doc.save = jest.fn(async () => doc);
      mockBookings.push(doc);
      return doc;
    }),
    deleteOne: jest.fn(async ({ _id }) => {
      const i = mockBookings.findIndex((d) => d._id === _id);
      if (i >= 0) mockBookings.splice(i, 1);
    }),
  };
});
jest.mock("../../model/eventType", () => ({ findOne: jest.fn() }));
jest.mock("../../model/user", () => ({ findOne: jest.fn(), findById: jest.fn() }));
jest.mock("../../services/googleCalendarService", () => ({
  createCalendarEvent: jest.fn(),
  deleteCalendarEvent: jest.fn(),
}));

const EventType = require("../../model/eventType");
const User = require("../../model/user");
const Google = require("../../services/googleCalendarService");
const { acquireLock, releaseLock } = require("../../utils/distributedLock");
const { buildConflictQuery } = require("../../utils/bookingConflicts");
const { createBooking } = require("../../controller/meetingController");

const res = () => {
  const r = {};
  r.status = jest.fn().mockReturnValue(r);
  r.json = jest.fn().mockReturnValue(r);
  return r;
};

describe("distributedLock ownership (in-memory fallback)", () => {
  afterEach(() => jest.useRealTimers());

  it("only the current owner can release; a stale token is ignored", async () => {
    const a = await acquireLock(null, "k1", 30);
    expect(a).toBeTruthy();
    expect(await acquireLock(null, "k1", 30)).toBeNull();
    expect(await releaseLock(null, "k1", a)).toBe(true);

    const b = await acquireLock(null, "k1", 30);
    expect(b).toBeTruthy();
    expect(await releaseLock(null, "k1", a)).toBe(false); // stale holder
    expect(await acquireLock(null, "k1", 30)).toBeNull(); // b still holds it
    await releaseLock(null, "k1", b);
  });

  it("an old timer never frees a lock re-acquired later", async () => {
    jest.useFakeTimers();
    const a = await acquireLock(null, "k3", 15); // timer at t=15s
    await releaseLock(null, "k3", a);
    jest.advanceTimersByTime(10000);
    const b = await acquireLock(null, "k3", 15); // timer at t=25s
    jest.advanceTimersByTime(6000); // t=16s: a's old timer has fired
    expect(await acquireLock(null, "k3", 15)).toBeNull(); // b must still own it
    await releaseLock(null, "k3", b);
  });
});

describe("distributedLock ownership (redis)", () => {
  it("uses compare-and-delete so a stale token cannot free the lock", async () => {
    const store = new Map();
    const redis = {
      set: jest.fn(async (k, v, _ex, _ttl, nx) => (nx === "NX" && store.has(k) ? null : (store.set(k, v), "OK"))),
      eval: jest.fn(async (_s, _n, k, token) => (store.get(k) === token ? (store.delete(k), 1) : 0)),
    };
    const a = await acquireLock(redis, "r", 30);
    store.delete("r"); // simulate TTL expiry
    const b = await acquireLock(redis, "r", 30);
    expect(await releaseLock(redis, "r", a)).toBe(false);
    expect(store.get("r")).toBe(b);
    expect(await releaseLock(redis, "r", b)).toBe(true);
  });
});

describe("buildConflictQuery", () => {
  it("widens the range by the buffers", () => {
    const start = new Date("2026-11-02T10:00:00Z");
    const end = new Date("2026-11-02T10:30:00Z");
    const q = buildConflictQuery({ userId: "u", start, end, bufferBeforeMs: 600000, bufferAfterMs: 900000 });
    expect(q.startTime.$lt.toISOString()).toBe("2026-11-02T10:40:00.000Z");
    expect(q.endTime.$gt.toISOString()).toBe("2026-11-02T09:45:00.000Z");
  });
});

describe("createBooking conflicts", () => {
  const creator = { _id: "c1", name: "Host", email: "h@x.com" };
  const eventType = {
    _id: "e1", title: "Call", duration: 30, locationType: "google_meet",
    availability: { days: ["mon", "tue", "wed", "thu", "fri"], startTime: "09:00", endTime: "17:00", timeZone: "UTC" },
    bufferBefore: 0, bufferAfter: 15,
  };
  const body = (startTime) => ({ attendeeName: "A", attendeeEmail: "a@x.com", startTime });
  const book = async (startTime) => {
    const r = res();
    await createBooking({ params: { alias: "host", slug: "call" }, body: body(startTime) }, r);
    return r;
  };

  beforeEach(() => {
    mockBookings.length = 0;
    User.findOne.mockResolvedValue(creator);
    EventType.findOne.mockResolvedValue(eventType);
    Google.createCalendarEvent.mockReset().mockResolvedValue({ eventId: "g1", meetingLink: "https://meet" });
    Google.deleteCalendarEvent.mockReset().mockResolvedValue({ success: true });
  });

  const base = { userId: "c1", eventTypeId: "e1", attendeeName: "X", attendeeEmail: "x@x.com" };

  it("rejects a slot that overlaps a fresh pending_sync booking", async () => {
    mockBookings.push({ _id: "p", ...base, status: "pending_sync", createdAt: new Date(),
      startTime: new Date("2026-11-02T10:00:00Z"), endTime: new Date("2026-11-02T10:30:00Z") });
    expect((await book("2026-11-02T10:00:00.000Z")).status).toHaveBeenCalledWith(409);
  });

  it("ignores an abandoned (stale) pending_sync booking", async () => {
    mockBookings.push({ _id: "p", ...base, status: "pending_sync", createdAt: new Date(Date.now() - 10 * 60 * 1000),
      startTime: new Date("2026-11-02T10:00:00Z"), endTime: new Date("2026-11-02T10:30:00Z") });
    expect((await book("2026-11-02T10:00:00.000Z")).status).toHaveBeenCalledWith(201);
  });

  it("enforces bufferAfter on the booking API, not only in the slot list", async () => {
    mockBookings.push({ _id: "s", ...base, status: "scheduled",
      startTime: new Date("2026-11-02T10:00:00Z"), endTime: new Date("2026-11-02T10:30:00Z") });
    expect((await book("2026-11-02T10:30:00.000Z")).status).toHaveBeenCalledWith(409); // inside 15 min buffer
    expect((await book("2026-11-02T10:45:00.000Z")).status).toHaveBeenCalledWith(201);
  });

  it("serialises two concurrent bookings for the same slot (exactly one wins)", async () => {
    Google.createCalendarEvent.mockImplementation(() => new Promise((r) => setTimeout(() => r({ eventId: "g", meetingLink: "m" }), 30)));
    const [r1, r2] = await Promise.all([book("2026-11-02T13:00:00.000Z"), book("2026-11-02T13:00:00.000Z")]);
    const codes = [r1, r2].map((r) => r.status.mock.calls[0][0]).sort();
    expect(codes).toEqual([201, 409]);
  });

  it("cleans up the calendar event and the booking when the commit step fails", async () => {
    const MeetingBooking = require("../../model/meetingBooking");
    MeetingBooking.create.mockImplementationOnce(async (data) => {
      const doc = { _id: "bx", createdAt: new Date(), ...data, save: jest.fn().mockRejectedValue(new Error("db down")) };
      mockBookings.push(doc);
      return doc;
    });
    const r = await book("2026-11-02T14:00:00.000Z");
    expect(r.status).toHaveBeenCalledWith(500);
    expect(Google.deleteCalendarEvent).toHaveBeenCalledWith(creator, "g1");
    expect(mockBookings.find((b) => b._id === "bx")).toBeUndefined();
  });
});
