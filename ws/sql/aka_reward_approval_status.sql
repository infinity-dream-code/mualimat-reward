-- Status aka_reward.isapproved: ENUM pending / approve / canceled
-- Jalankan sekali di Navicat, database yogya_muallimaat, satu pernyataan per kali.
-- Abaikan error Duplicate column jika langkah 1 sudah pernah dijalankan.
--
-- Nilai lama:
--   0 / NULL / pending  → pending
--   1 / approve         → approve
--   canceled            → canceled

ALTER TABLE aka_reward
  ADD COLUMN isapproved_new ENUM('pending', 'approve', 'canceled') NOT NULL DEFAULT 'pending' AFTER url;

UPDATE aka_reward
SET isapproved_new = CASE
  WHEN CAST(isapproved AS CHAR) IN ('1', 'approve', 'approved') THEN 'approve'
  WHEN CAST(isapproved AS CHAR) IN ('canceled', 'cancelled', 'reject', 'rejected', 'tolak') THEN 'canceled'
  ELSE 'pending'
END;

ALTER TABLE aka_reward DROP COLUMN isapproved;

ALTER TABLE aka_reward
  CHANGE isapproved_new isapproved ENUM('pending', 'approve', 'canceled') NOT NULL DEFAULT 'pending';
