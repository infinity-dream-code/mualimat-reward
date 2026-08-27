-- Catatan penolakan admin pada aka_reward.
-- Jalankan sekali di Navicat, database yogya_muallimaat.
-- Abaikan error Duplicate column jika sudah pernah dijalankan.

ALTER TABLE aka_reward ADD COLUMN catatan_admin VARCHAR(500) NULL DEFAULT NULL AFTER approvedby;
