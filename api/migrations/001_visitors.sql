CREATE TABLE of_visitors (
    namespace text NOT NULL,
    site text NOT NULL,
    visitor_id text NOT NULL,
    profile jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, site, visitor_id)
);
CREATE TABLE of_fingerprints (
    namespace text NOT NULL,
    site text NOT NULL,
    schema_version integer NOT NULL,
    fingerprint text NOT NULL,
    visitor_id text NOT NULL,
    PRIMARY KEY (namespace, site, schema_version, fingerprint),
    FOREIGN KEY (namespace, site, visitor_id)
        REFERENCES of_visitors ON DELETE CASCADE
);
CREATE TABLE of_resolutions (
    namespace text NOT NULL,
    site text NOT NULL,
    identification_hash text NOT NULL,
    decision jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (namespace, site, identification_hash)
);
CREATE INDEX of_resolutions_expiry ON of_resolutions (expires_at);
