INSERT INTO of_rule_indexes (namespace, site, rule, signature, visitor_id)
SELECT namespace, site, 'gpu-v1',
    encode(sha256(convert_to('openfingerprint:visitor:gpu:1|' || array_to_string(evidence.hashes, '|'), 'UTF8')), 'hex'),
    visitor_id
FROM of_visitors
CROSS JOIN LATERAL (SELECT ARRAY[
    profile #>> '{components,audio}',
    profile #>> '{components,canvas}',
    profile #>> '{components,fontFallbacks}',
    profile #>> '{components,fontPreferences}',
    profile #>> '{components,fonts}',
    profile #>> '{hints,architecture}',
    profile #>> '{hints,browser}',
    profile #>> '{hints,display}',
    profile #>> '{hints,features}',
    profile #>> '{hints,hardware}',
    profile #>> '{hints,locale}',
    profile #>> '{hints,math}',
    profile #>> '{hints,media}',
    profile #>> '{hints,platform}',
    profile #>> '{hints,screen}'
] AS hashes) evidence
WHERE profile->>'schemaVersion' = '1'
    AND profile->'excluded' = '[]'::jsonb
    AND profile->>'localeSignature' IS NOT NULL
    AND profile->'components'->>'gpu' IS NOT NULL
    AND array_position(evidence.hashes, NULL) IS NULL;
