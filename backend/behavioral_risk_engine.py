yclass BehavioralRiskEngine:

    def __init__(self):
        self.risk_score = 0
        self.last_event_time = None

        self.failure_count = 0
        self.anomaly_count = 0
        self.automation_count = 0
        self.sensitive_count = 0

        self.had_sensitive_intent = False
        self.login_time = None

        self.clean_event_streak = 0
        self.reasons = set()

    # --------------------------------------------------
    # MAIN EVENT PROCESSOR
    # --------------------------------------------------

    def process_event(self, event):
        now = event["timestamp"]

        self.apply_time_decay(now)

        event_type = event["event_type"]

        # ---------------- LOGIN FAILURE ----------------
        if event_type == "LOGIN_FAILURE":
            self.failure_count += 1
            self.add_risk(6, "Failed login attempt")

            # Escalation tiers
            if self.failure_count >= 3:
                self.add_risk(8, "Multiple login failures")

            if self.failure_count >= 5:
                self.add_risk(15, "Excessive login failures")

        # ---------------- LOGIN SUCCESS ----------------
        elif event_type == "LOGIN_SUCCESS":
            self.login_time = now

        # ---------------- ANOMALIES ----------------
        elif event_type == "NEW_DEVICE":
            self.anomaly_count += 1
            self.add_risk(12, "Login from new device")

        elif event_type == "TRAVEL_ANOMALY":
            self.anomaly_count += 1
            self.add_risk(15, "Suspicious location change")

        elif event_type == "ODD_LOGIN_TIME":
            self.anomaly_count += 1
            self.add_risk(8, "Login at unusual hour")

        # ---------------- AUTOMATION ----------------
        elif event_type == "RAPID_RETRY":
            self.automation_count += 1
            self.add_risk(12, "Rapid login retries detected")

            if self.automation_count >= 2:
                self.add_risk(15, "Automated attack pattern detected")

        elif event_type == "BURST_ACTION":
            self.automation_count += 1
            self.add_risk(20, "Unusually fast action sequence")

        # ---------------- SENSITIVE ----------------
        elif event_type in ["DOWNLOAD_STATEMENT", "CHANGE_PASSWORD"]:
            self.handle_sensitive_action(now)

        # ---------------- CLEAN ----------------
        else:
            self.handle_clean_event()

        self.last_event_time = now

    # --------------------------------------------------
    # SENSITIVE ACTION LOGIC
    # --------------------------------------------------

    def handle_sensitive_action(self, now):
        self.sensitive_count += 1
        self.had_sensitive_intent = True

        base_risk = 25

        # Immediate sensitive after login
        if self.login_time and (now - self.login_time) < 10:
            base_risk = 35

        # Sensitive after failures
        if self.failure_count > 0:
            base_risk = max(base_risk, 40)

        # Amplify if anomalies present
        if self.anomaly_count > 0:
            base_risk += 10

        # Amplify if automation present
        if self.automation_count > 0:
            base_risk += 10

        # Multiple sensitive actions
        if self.sensitive_count > 1:
            base_risk += 15

        self.add_risk(base_risk, "Sensitive action with suspicious context")

    # --------------------------------------------------
    # CLEAN EVENT HANDLING
    # --------------------------------------------------

    def handle_clean_event(self):
        self.clean_event_streak += 1

        if self.clean_event_streak >= 3:
            self.reduce_risk(5)
            self.clean_event_streak = 0

    # --------------------------------------------------
    # TIME DECAY
    # --------------------------------------------------

    def apply_time_decay(self, now):
        if not self.last_event_time:
            return

        elapsed = now - self.last_event_time

        if elapsed < 30:
            return

        decay_steps = int(elapsed // 30)

        for _ in range(decay_steps):
            if self.risk_score > 60:
                self.reduce_risk(2)
            elif self.risk_score > 30:
                self.reduce_risk(4)
            else:
                self.reduce_risk(6)

    # --------------------------------------------------
    # UTILITIES
    # --------------------------------------------------

    def add_risk(self, amount, reason):
        self.risk_score += amount
        self.reasons.add(reason)
        self.clean_event_streak = 0

    def reduce_risk(self, amount):
        self.risk_score = max(0, self.risk_score - amount)

    # --------------------------------------------------
    # CLASSIFICATION LOGIC
    # --------------------------------------------------

    def get_risk_class(self):

        # HIGH requires sensitive intent
        if self.had_sensitive_intent and self.risk_score >= 60:
            return "HIGH"

        # Suspicious behavior even without sensitive action
        if self.failure_count >= 5:
            return "MEDIUM"

        if self.automation_count >= 2:
            return "MEDIUM"

        if self.risk_score >= 30:
            return "MEDIUM"

        return "LOW"

    # --------------------------------------------------
    # REPORT
    # --------------------------------------------------

    def get_risk_report(self):
        return {
            "risk_score": round(self.risk_score, 2),
            "risk_class": self.get_risk_class(),
            "reasons": list(self.reasons)
        }
