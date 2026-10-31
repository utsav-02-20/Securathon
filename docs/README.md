# 📚 Securathon Documentation Suite

Welcome to the comprehensive technical documentation for the **Securathon Intelligent API Security Gateway**.

---

## 🎯 Executive Summary

**Securathon** is an enterprise-grade, hybrid **"Guard + Detective"** API reverse proxy designed to defend modern microservices against OWASP API Security Top 10 vulnerabilities. It focuses on zero-trust perimeter defense, cryptographic integrity, volumetric flood mitigation, and real-time behavioral AI anomaly detection (specifically targeting **BOLA/IDOR** and **high-entropy fuzzing**) while maintaining a strict **sub-15ms proxy latency SLA**.

---

## 🧭 Documentation Map

| Document | Description | Target Audience |
| :--- | :--- | :--- |
| **[Architecture & Core Logic](file:///home/dev/Desktop/Securathon/docs/architecture-and-logic.md)** | Full breakdown of the 6-stage security pipeline, threat detection algorithms, Shannon entropy math, and decision logic. | Architects, Security Engineers |
| **[Implementation Details](file:///home/dev/Desktop/Securathon/docs/implementation-details.md)** | Deep dive into codebase structure, modules, classes, async workers, database schemas, and data contracts. | Backend Developers, DevOps |
| **[API Reference](file:///home/dev/Desktop/Securathon/docs/api-reference.md)** | Complete specification of gateway endpoints, downstream mock services, WebSocket streams, and status codes. | API Developers, Integrators |
| **[Attack Scenarios & Mitigation](file:///home/dev/Desktop/Securathon/docs/attacks-and-mitigation.md)** | Step-by-step walkthrough of all 7 multi-layer attack scenarios, neutralization workflows, and automated responses. | Penetration Testers, SOC Analysts |
| **[Benchmarks & Performance](file:///home/dev/Desktop/Securathon/docs/benchmarks-and-performance.md)** | High-precision latency benchmarks, sub-millisecond ML inference measurements, and SLA verification reports. | Performance Engineers, SREs |
| **[Operations & Deployment](file:///home/dev/Desktop/Securathon/docs/operations-and-deployment.md)** | Setup instructions, environment variables configuration, Docker deployment, and testing procedures. | Operations, DevOps, SREs |

---

## 🚀 Quick Start Navigation

1. **New to the project?** Start with **[Architecture & Core Logic](file:///home/dev/Desktop/Securathon/docs/architecture-and-logic.md)** to understand how the Guard and Detective collaborate.
2. **Reviewing the code?** Check **[Implementation Details](file:///home/dev/Desktop/Securathon/docs/implementation-details.md)** to see how each module in `core/`, `gateway/`, `ml/`, and `db/` operates.
3. **Validating security efficacy?** Jump to **[Attack Scenarios & Mitigation](file:///home/dev/Desktop/Securathon/docs/attacks-and-mitigation.md)** to view real attack vectors and detection proofs.
4. **Deploying or running tests?** Head to **[Operations & Deployment](file:///home/dev/Desktop/Securathon/docs/operations-and-deployment.md)**.
