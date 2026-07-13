-- Enforce the assumptions used by plan allocation at the data boundary.

ALTER TABLE metering_daily
    ADD CONSTRAINT metering_daily_events_nonnegative CHECK (events >= 0);
