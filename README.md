# CODE_MARK
Multi-Layer AI System for GDPR Compliance & Personal Data Protection
1. Project Overview

Nordic organizations process large volumes of personal data across cloud systems, logs, apps, and APIs. Ensuring GDPR compliance manually is slow, error-prone, and often reactive.
CODE_MARK demonstrates an automated, scalable approach using layered privacy controls:

Detect PII inside raw data

Map and classify sensitive fields

Link related user identities

Apply anonymization or secure transformations

Log all actions for audit and compliance reporting

Visualize privacy posture and data distribution

The project showcases how modern privacy engineering works in real systems.

2. Core Features
✓ Layer 1 – Scanner

Detects PII inside CSV, JSON, log files, or structured/unstructured data

Uses rule-based patterns (emails, phone numbers, IDs, health information)

Stores detection results in SQLite (audit_logs.db)

✓ Layer 1 – Mapper

Maps detected PII into categories such as:

Direct Identifiers → Name, National ID, Email

Indirect Identifiers → Health data, address, date of birth

Maintains structured metadata in layer1_mapper.db

✓ Layer 1 – Linker

Connects related PII fields belonging to the same user

Simulates identity merging similar to BankID/MitID flows

Builds user-level data graphs

✓ Secure Data Handler (Security Layer)

Anonymization and masking operations

Validation of secure data storage

Ensures data transformations comply with GDPR processing rules

✓ Synthetic Data Generator

Generates privacy-safe datasets (synthetic.csv)

Used to demonstrate anonymization quality

✓ Audit Logs

Every scan, mapping, linking, or modification is logged

Logs stored in JSON under outputs/audit_logs/

Used for compliance investigation

✓ Visualization Layer

plot.py produces graphs on:

PII distribution

Risk exposure

Detected identifiers

Layer-wise processing results
. How the System Works (Pipeline)
Step 1 – Input ingestion

The system loads CSV/JSON logs from data/ or sample_data/.

Step 2 – Scanner Layer

layer1_scanner/scanner.py detects PII fields and stores results into audit_logs.db.

Step 3 – Mapper Layer

layer1_mapper/mapper.py classifies PII into categories and updates the mapper database.

Step 4 – Linker Layer

layer1_linker/linker.py links related data and builds identity clusters.

Step 5 – Security Layer

security/secure_data_handler.py performs:

masking

anonymization

secure attribute handling

Step 6 – Logging & Monitoring

JSON audit logs are written to outputs/audit_logs/.

Step 7 – Visualization

plot.py generates:

risk distribution charts

PII count summaries

before/after anonymization comparisons

5. Running the Project
1. Clone the Repository
git clone https://github.com/Yatheen28/CODE_MARK.git
cd CODE_MARK

2. Run the Full Pipeline
python app.py

3. View Generated Outputs

Detected PII → audit_logs.db

Mapped identities → layer1_mapper.db

Synthetic data → out/synthetic.csv

Audit logs → outputs/audit_logs/

Visual graphs → displayed via plot.py

6. Future Enhancements

Implement NLP-based contextual PII detection

Add real-time monitoring agent

Integration with Nordic identity APIs (BankID/MitID)

Advanced rule engine for GDPR violations

Web dashboard UI for compliance reporting

Role-Based Access Control (RBAC)

Integration with cloud storage systems

7. Purpose of This Project

This project demonstrates privacy engineering fundamentals including:

Automated GDPR compliance checks

Layered privacy protection architecture

Secure data pipeline design

Audit logging and monitoring

Identity graph building

Differential privacy & anonymization

It is suitable for research, academic demonstrations, and building awareness about practical GDPR implementation.
