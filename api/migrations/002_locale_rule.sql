CREATE TABLE of_rule_indexes (
    namespace text NOT NULL,
    site text NOT NULL,
    rule text NOT NULL,
    signature text NOT NULL,
    visitor_id text NOT NULL,
    PRIMARY KEY (namespace, site, rule, signature, visitor_id),
    FOREIGN KEY (namespace, site, visitor_id)
        REFERENCES of_visitors ON DELETE CASCADE
);
INSERT INTO of_rule_indexes (namespace, site, rule, signature, visitor_id)
SELECT namespace, site, 'locale-v1', profile->>'localeSignature', visitor_id
FROM of_visitors
WHERE profile->>'localeSignature' IS NOT NULL;
