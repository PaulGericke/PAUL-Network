"""Internet-loss policy, independent of hardware and wall-clock changes."""

class Policy:
    def __init__(self, delay=300, recovery=30):
        self.delay, self.recovery = delay, recovery
        self.lost_at = None
        self.good_at = None
        self.automatic_on = False

    def step(self, mode, internet, now):
        if mode not in ('auto', 'on', 'off'):
            raise ValueError('Invalid hotspot mode')
        if internet:
            self.lost_at = None
            if self.good_at is None:
                self.good_at = now
            if now - self.good_at >= self.recovery:
                self.automatic_on = False
        else:
            self.good_at = None
            if self.lost_at is None:
                self.lost_at = now
            if now - self.lost_at >= self.delay:
                self.automatic_on = True
        if mode == 'off':
            self.automatic_on = False
            # Explicit off cancels the outage countdown. Returning to auto
            # starts a fresh uninterrupted five-minute grace period.
            self.lost_at = None
            return False
        return mode == 'on' or self.automatic_on
