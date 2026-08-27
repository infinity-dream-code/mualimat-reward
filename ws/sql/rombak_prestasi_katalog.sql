-- Jalankan sekali di Navicat, database yogya_muallimaat.
-- Jangan diulang jika admin sudah mengisi nilai poin (TRUNCATE mengosongkan master).
-- Jika ALTER gagal karena kolom sudah ada, abaikan bagian ALTER saja.
-- aka_prestasi_kategori.code01: NULL = semua unit; terisi = mst_sekolah.CODE01 (khusus unit itu).

CREATE TABLE IF NOT EXISTS aka_prestasi_kategori (
  id INT NOT NULL AUTO_INCREMENT,
  kode CHAR(1) NOT NULL,
  nama VARCHAR(150) NOT NULL,
  urut INT NOT NULL DEFAULT 0,
  code01 VARCHAR(20) NULL DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_prestasi_kategori_kode_unit (kode, code01),
  KEY idx_prestasi_kategori_code01 (code01)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS aka_prestasi_tingkat (
  id INT NOT NULL AUTO_INCREMENT,
  kategori_id INT NOT NULL,
  nama VARCHAR(80) NOT NULL,
  urut INT NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  KEY idx_prestasi_tingkat_kategori (kategori_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS aka_prestasi_poin (
  id INT NOT NULL AUTO_INCREMENT,
  tingkat_id INT NOT NULL,
  nama VARCHAR(80) NOT NULL,
  nilai DECIMAL(10,2) NOT NULL DEFAULT 0.00,
  urut INT NOT NULL DEFAULT 0,
  PRIMARY KEY (id),
  KEY idx_prestasi_poin_tingkat (tingkat_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE aka_prestasi_poin;
TRUNCATE TABLE aka_prestasi_tingkat;
TRUNCATE TABLE aka_prestasi_kategori;
SET FOREIGN_KEY_CHECKS = 1;

INSERT INTO aka_prestasi_kategori (id, kode, nama, urut) VALUES
(1, 'A', 'Prestasi Nilai Rapot', 1),
(2, 'B', 'Prestasi Lomba Akademik (OSN)', 2),
(3, 'C', 'Prestasi Lomba Non Akademik', 3),
(4, 'D', 'Kategori Kreativitas dan Keahlian (Karya Siswi)', 4),
(5, 'E', 'Kepemimpinan/Perkaderan (Pengurus Kelas/Pelatihan)', 5),
(6, 'F', 'Keagamaan/Pengabdian Sosial (Mubaligh Hijrah, TDL, Mujanibah, dll)', 6);

INSERT INTO aka_prestasi_tingkat (kategori_id, nama, urut) VALUES
(1, 'Nilai Rapot', 1);

INSERT INTO aka_prestasi_tingkat (kategori_id, nama, urut)
SELECT k.id, t.nama, t.urut
FROM aka_prestasi_kategori k
CROSS JOIN (
  SELECT 'Organtri' AS nama, 1 AS urut UNION ALL
  SELECT 'Madrasah', 2 UNION ALL
  SELECT 'Kelurahan', 3 UNION ALL
  SELECT 'Kecamatan', 4 UNION ALL
  SELECT 'Kabupaten', 5 UNION ALL
  SELECT 'Provinsi', 6 UNION ALL
  SELECT 'Regional', 7 UNION ALL
  SELECT 'Nasional', 8 UNION ALL
  SELECT 'Internasional', 9
) t
WHERE k.kode IN ('B', 'C', 'D', 'E');

INSERT INTO aka_prestasi_tingkat (kategori_id, nama, urut) VALUES
(6, 'Mubaligh Hijrah', 1),
(6, 'Peserta TDL', 2),
(6, 'Peserta Santri Mengabdi', 3),
(6, 'ZIS Wakaf', 4),
(6, 'Nilai Kepribadian', 5),
(6, 'Madrasah', 6);

INSERT INTO aka_prestasi_poin (tingkat_id, nama, nilai, urut)
SELECT t.id, 'Peringkat 1', 0.00, 1 FROM aka_prestasi_tingkat t WHERE t.kategori_id = 1
UNION ALL
SELECT t.id, 'Peringkat 2', 0.00, 2 FROM aka_prestasi_tingkat t WHERE t.kategori_id = 1
UNION ALL
SELECT t.id, 'Peringkat 3', 0.00, 3 FROM aka_prestasi_tingkat t WHERE t.kategori_id = 1;

INSERT INTO aka_prestasi_poin (tingkat_id, nama, nilai, urut)
SELECT t.id, p.nama, 0.00, p.urut
FROM aka_prestasi_tingkat t
CROSS JOIN (
  SELECT 'Juara 1' AS nama, 1 AS urut UNION ALL
  SELECT 'Juara 2', 2 UNION ALL
  SELECT 'Juara 3', 3 UNION ALL
  SELECT 'Harapan', 4 UNION ALL
  SELECT 'Peserta', 5
) p
WHERE t.kategori_id IN (2, 3, 4, 5);

INSERT INTO aka_prestasi_poin (tingkat_id, nama, nilai, urut)
SELECT t.id, 'Nilai', 0.00, 1
FROM aka_prestasi_tingkat t
WHERE t.kategori_id = 6;

ALTER TABLE aka_reward
  ADD COLUMN prestasi_kategori_id INT NULL AFTER jenis_prestasi,
  ADD COLUMN prestasi_tingkat_id INT NULL AFTER prestasi_kategori_id,
  ADD COLUMN prestasi_poin_id INT NULL AFTER prestasi_tingkat_id,
  ADD COLUMN penyelenggara VARCHAR(150) NOT NULL DEFAULT '' AFTER keterangan,
  ADD COLUMN no_sertifikat VARCHAR(80) NOT NULL DEFAULT '' AFTER penyelenggara;
