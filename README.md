# Behavioral Risk Detector

A behavioral security engine that analyzes user activity events and dynamically calculates a **risk score** to detect suspicious or potentially malicious behavior in real time.

The system evaluates login patterns, device anomalies, automation indicators, and sensitive user actions to determine whether a session is **LOW**, **MEDIUM**, or **HIGH risk**.

---

## 🚀 Features

* Real-time **behavioral risk scoring**
* Detection of **login attacks and suspicious access**
* Identification of **automation/bot behavior**
* Context-aware analysis for **sensitive actions**
* **Time-decay risk model** to reduce false positives
* Adaptive classification into **LOW / MEDIUM / HIGH risk**

---

## 🧠 Detection Signals

The engine evaluates multiple behavioral signals:

### Authentication Signals

* Login failures
* Excessive retry attempts
* Rapid login attempts

### Device & Location Anomalies

* Login from new device
* Sudden travel/location anomaly
* Login during unusual hours

### Automation Patterns

* Rapid retry attempts
* Burst action sequences indicating bots

### Sensitive Actions

* Password changes
* Statement downloads

Sensitive actions performed under suspicious conditions dramatically increase the risk score.

---

## ⚙️ Risk Scoring Model

The system assigns risk points based on detected behaviors.

Example signals:

| Event                       | Risk Impact |
| --------------------------- | ----------- |
| Failed Login                | +6          |
| New Device Login            | +12         |
| Travel Anomaly              | +15         |
| Rapid Retry                 | +12         |
| Burst Automation            | +20         |
| Suspicious Sensitive Action | +25 – +60   |

---

## ⏳ Time-Decay Mechanism

To prevent permanent risk escalation, the system gradually reduces the risk score over time.

Risk decreases every **30 seconds** depending on current risk level.

Higher risks decay slower while lower risks decay faster.

---

## 📊 Risk Classification

| Risk Score              | Classification |
| ----------------------- | -------------- |
| < 30                    | LOW            |
| 30 – 59                 | MEDIUM         |
| ≥ 60 + Sensitive Intent | HIGH           |

HIGH risk requires both a high score and a detected sensitive action.

---

## 🧩 Architecture

Event Stream → Behavioral Engine → Risk Score → Risk Classification

1. Events are processed sequentially
2. Risk score is dynamically updated
3. Suspicious patterns escalate risk
4. Clean behavior reduces risk over time
5. Final classification determines threat level

---

## 📦 Example Output

```
{
  "risk_score": 72,
  "risk_class": "HIGH",
  "reasons": [
    "Multiple login failures",
    "Login from new device",
    "Sensitive action with suspicious context"
  ]
}
```

---

## 🎯 Use Cases

* Banking fraud detection
* Account takeover prevention
* Bot detection
* Insider threat monitoring
* Security monitoring systems

---

## 👨‍💻 Author

Rehan Shaik
