-- Jalankan sekali di Navicat, database yogya_muallimaat.
-- Tambah kolom NISN dan semester pada aka_reward.

ALTER TABLE aka_reward
  ADD COLUMN nisn VARCHAR(16) NOT NULL DEFAULT '' AFTER nocust,
  ADD COLUMN semester TINYINT NOT NULL DEFAULT 1 AFTER bta;
