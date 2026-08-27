-- Jalankan di Navicat, database yogya_muallimaat.
-- Tiap baris ALTER berdiri sendiri: jika muncul "Duplicate column", lanjut ke baris berikutnya.

ALTER TABLE aka_reward ADD COLUMN nisn VARCHAR(16) NOT NULL DEFAULT '' AFTER nocust;
ALTER TABLE aka_reward ADD COLUMN semester TINYINT NOT NULL DEFAULT 1 AFTER bta;
ALTER TABLE aka_reward ADD COLUMN prestasi_kategori_id INT NULL AFTER jenis_prestasi;
ALTER TABLE aka_reward ADD COLUMN prestasi_tingkat_id INT NULL AFTER prestasi_kategori_id;
ALTER TABLE aka_reward ADD COLUMN prestasi_poin_id INT NULL AFTER prestasi_tingkat_id;
ALTER TABLE aka_reward ADD COLUMN penyelenggara VARCHAR(150) NOT NULL DEFAULT '' AFTER keterangan;
ALTER TABLE aka_reward ADD COLUMN no_sertifikat VARCHAR(80) NOT NULL DEFAULT '' AFTER penyelenggara;
ALTER TABLE aka_reward MODIFY COLUMN url VARCHAR(500) NOT NULL DEFAULT '';
