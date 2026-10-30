CREATE TABLE tenant_branding (
 tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
 display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 80),
 tagline TEXT NOT NULL DEFAULT '' CHECK(length(tagline)<=160),
 support_label TEXT NOT NULL DEFAULT '' CHECK(length(support_label)<=40),
 support_url TEXT NOT NULL DEFAULT '' CHECK(length(support_url)<=500),
 accent TEXT NOT NULL DEFAULT 'blue' CHECK(accent IN ('blue','violet','teal','amber','rose')),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
