
CREATE TYPE invite_code_regime AS ENUM('none', 'required', 'optional');

ALTER TABLE host_config
    ADD COLUMN invite_code_regime invite_code_regime NOT NULL DEFAULT 'none';