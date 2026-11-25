# DPIA template: AI assistance through boxed.si

Fill in the bracketed parts. This template covers the use of boxed.si; the AI service itself needs its own assessment.

## 1. Processing

- Purpose: employees use [approved AI services] for [tasks: code and logs, documents, tables, correspondence] with personal data and confidential data masked on their computers by boxed.si.
- Controller: [company]. Users: [teams, number of employees].
- Data categories that may occur in the source material: [contact data of customers and staff, identifiers, financial data, HR data, health data].
- What the AI service receives: masked content at level [2 by default; 3 for finance, sales, HR; 4 for tables], set by the policy in [boxed.toml or the company profile].
- Recipients: [AI service, account type (company plan, API with zero retention, ...), its role (processor under a DPA / independent controller)].
- Transfers outside the EEA: [provider and jurisdiction; legal basis, for example SCCs]. Masking does not replace a legal basis.
- Retention: placeholder maps [N days]; journal [N months]; AI service [per its terms].

## 2. Necessity and proportionality

- Why AI assistance is needed: [...].
- Why masking is enough for these categories, and which categories stay local or are denied: [policy matrix].
- How employees are told: [policy clause, training].

## 3. Risks

| Risk | Likelihood | Impact | Notes |
|---|---|---|---|
| Re-identification from context in masked content | [ ] | [ ] | Placeholders hide direct identifiers, not context |
| A detector misses data | [ ] | [ ] | Benchmark rate: [link] |
| The AI service keeps or trains on content | [ ] | [ ] | Account type, training setting checked on [date] |
| Compromise of the employee's computer | [ ] | [ ] | The vault key is in the OS keychain |
| Content sent around boxed | [ ] | [ ] | boxed does not stop direct pasting; the journal shows only what went through boxed. Observation mode, when the employee turns it on, counts such sends by kind |

## 4. Measures

- Policy profile [no-confidential / approved-only] with [overrides].
- Approved accounts only: [list]; training on chats off, recorded by the employee in boxed and checked again [monthly] (`boxed check list` says what is due).
- API keys: kept in the OS keychain; account type for `boxed ask`: [corporate / api-zero-retention]; relay address (`BOXED_<PROVIDER>_BASE_URL`): [none / address].
- Journal export to [SIEM or the security team] every [period]; signatures verified with the device public key.
- `boxed audit` run at onboarding to find keys saved in local session records (possible exposure to the provider); real ones are rotated.

## 5. Residual risk and sign-off

- Residual risk: [low / medium / high], accepted by [name, role, date].
- Review date: [date].
