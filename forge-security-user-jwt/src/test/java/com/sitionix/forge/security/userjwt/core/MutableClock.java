package com.sitionix.forge.security.userjwt.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicReference;

class MutableClock extends Clock {

    private final AtomicReference<Instant> instant;
    private final ZoneId zone;

    MutableClock(final Instant instant, final ZoneId zone) {
        this.instant = new AtomicReference<>(instant);
        this.zone = zone;
    }

    void advance(final Duration duration) {
        this.instant.updateAndGet(current -> current.plus(duration));
    }

    @Override
    public ZoneId getZone() {
        return this.zone;
    }

    @Override
    public Clock withZone(final ZoneId zone) {
        return new MutableClock(this.instant.get(), zone);
    }

    @Override
    public Instant instant() {
        return this.instant.get();
    }
}
