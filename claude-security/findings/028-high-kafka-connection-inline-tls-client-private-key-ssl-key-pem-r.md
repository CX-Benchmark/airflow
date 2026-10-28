# Kafka connection inline TLS client private key (ssl.key.pem) returned in clear by connections API

| Field | Value |
|---|---|
| ID | `find_01QwKAxm49EAqJrfD87pCofa` |
| Severity | **High** |
| Status | open |
| CWE | CWE-200 — Information exposure |
| Created | 2026-10-27T22:04:46.079308Z |
| Claude Security | https://claude.ai/security/findings/find_01QwKAxm49EAqJrfD87pCofa |

## Description

A logged-in user who can read connections through the API can get the TLS client private key of a Kafka connection in clear text. This needs a Kafka connection that uses mTLS with the key stored inline as `ssl.key.pem` in the connection `extra`. The API masks a key only if its name matches the default sensitive-name list or the provider declared it as a password, and neither is true for `ssl.key.pem`.

```mermaid
flowchart TD
  n1["user with Connection GET access"]
  n2["ConnectionResponse in connections API"]
  n3["ssl.key.pem private key in Kafka connection extra"]
  n4["format: password declaration by Kafka provider"]
  n5["DEFAULT_SENSITIVE_FIELDS name matching"]
  n1 -->|"requests the connection"| n2
  n2 -->|"returns key in clear"| n3
  n4 -->|"not declared, so no masking"| n2
  n5 -->|"no entry matches ssl_key_pem"| n2
  classDef actor stroke:#2563eb,stroke-width:2px
  classDef vulnerable_code stroke:#dc2626,stroke-width:2px
  classDef existing_control stroke:#16a34a,stroke-width:2px
  classDef missing_control stroke:#dc2626,stroke-width:2px,stroke-dasharray:5 5
  classDef asset stroke:#9333ea,stroke-width:2px
  classDef component stroke:#6b7280,stroke-width:1px
  class n1 actor
  class n2 vulnerable_code
  class n3 asset
  class n4 missing_control
  class n5 existing_control
```

1. **Connection owner** stores the Kafka client key inline in the connection `extra`. The Kafka provider passes the whole `extra` to the Kafka client as its configuration, and the documented mTLS option `ssl.key.pem` holds the PEM private key, so the key sits in `extra` under that name. ([`providers/apache/kafka/src/airflow/providers/apache/kafka/hooks/base.py:147-188`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/providers/apache/kafka/src/airflow/providers/apache/kafka/hooks/base.py#L147-L188))
2. **attacker** requests `GET /api/v2/connections/{conn_id}` or the list endpoint. The attacker is an authenticated user with Connection GET access, which the route checks with `requires_access_connection(method="GET")`. ([`airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py:203-258`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py#L203-L258))
3. **`ConnectionResponse`** checks the `extra` key names against the default sensitive-name list. `ssl.key.pem` is normalised to `ssl_key_pem`, which contains none of the listed names such as `private_key`, `secret`, `token` or `password`, so it is not masked. ([`shared/secrets_masker/src/airflow_shared/secrets_masker/secrets_masker.py:588-601`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/shared/secrets_masker/src/airflow_shared/secrets_masker/secrets_masker.py#L588-L601))
4. **`ConnectionResponse`** looks for provider-declared password keys and finds none for Kafka. `_sensitive_extra_keys()` adds only keys declared as `format: password`, and the Kafka provider declares no `conn-fields`. ([`airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py:36-52`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py#L36-L52))
5. **connections API** returns the private key and the certificate unmasked. The response includes the PEM private key, the public certificate and the bootstrap servers, which together form the full client identity. ([`airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py:203-258`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py#L203-L258))

## Assessment

The attacker is an authenticated user with Connection GET access. Under the security model this role should only be able to write credentials, not read them. The attack needs a Kafka connection that uses mTLS with the client key given inline as `ssl.key.pem`, not as a file path in `ssl.key.location`. This is a documented librdkafka option, and the report calls it the natural choice for containerised workers without a mounted key file. The attacker only calls `GET /api/v2/connections` or `GET /api/v2/connections/{conn_id}`. No user interaction is needed. The report assumes `confluent-kafka>=2.6.0` accepts `ssl.key.pem` as librdkafka documents.

Impact: The attacker reads the Kafka client's PEM private key, the matching public certificate and the bootstrap servers in clear. This breaks the rule that connection credentials are write-only for this role. Nothing in Airflow is modified or made unavailable.

Subsequent-system impact: With the key, certificate and bootstrap servers, anyone who can reach the Kafka brokers can impersonate the Airflow client. They can read every topic it may consume and write to every topic it may produce to. The exact reach depends on the ACLs set by the cluster.

## Recommendation

The Kafka provider keeps librdkafka credential options under their native names in `extra` without declaring the inline-key options sensitive. The core name heuristics do not recognise `ssl.key.pem`, so the API returns it unmasked.

Fix criteria: `GET /api/v2/connections[/{id}]` returns `***` for a non-empty `ssl.key.pem` of a `kafka` connection, and a PATCH that sends `***` keeps the stored key. `ssl.certificate.pem` and `ssl.ca.pem` may stay visible. Check it by storing a connection with `{"bootstrap.servers":"b:9092","ssl.key.pem":"-----BEGIN PRIVATE KEY-----XYZ"}` and confirming `XYZ` is absent from the response. Either of two changes meets this. One is to declare `ssl.key.pem`, and other librdkafka secret options the name check misses, as `format: password` conn-fields. The other is to add `key.pem` or `key_pem` to the default sensitive names.

## Evidence

**https://github.com/cx-benchmark/airflow**

- [`providers/apache/kafka/src/airflow/providers/apache/kafka/hooks/base.py:147-188`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/providers/apache/kafka/src/airflow/providers/apache/kafka/hooks/base.py#L147-L188)
- [`providers/apache/kafka/provider.yaml:120-134`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/providers/apache/kafka/provider.yaml#L120-L134)
- [`providers/apache/kafka/docs/connections/kafka.rst:38-41`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/providers/apache/kafka/docs/connections/kafka.rst#L38-L41)
- [`shared/secrets_masker/src/airflow_shared/secrets_masker/secrets_masker.py:588-601`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/shared/secrets_masker/src/airflow_shared/secrets_masker/secrets_masker.py#L588-L601)
- [`airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py:36-52`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py#L36-L52)
- [`airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py:203-258`](https://github.com/cx-benchmark/airflow/blob/a462d683469bb9f55646b0515ef84c41e16650fb/airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py#L203-L258)

