-- Batasan unit pada aka_prestasi_kategori.
-- Jalankan sekali di Navicat, database yogya_muallimaat, satu ALTER per baris.
-- Abaikan error Duplicate column / Duplicate key / Can't DROP jika sudah pernah dijalankan.
--
-- code01 NULL  = kategori (beserta tingkat & poin) berlaku untuk semua unit
-- code01 terisi = mst_sekolah.CODE01, hanya untuk unit itu
-- Poin beda per unit: buat baris kategori terpisah (kode boleh sama, code01 berbeda).

ALTER TABLE aka_prestasi_kategori ADD COLUMN code01 VARCHAR(20) NULL DEFAULT NULL AFTER urut;

ALTER TABLE aka_prestasi_kategori DROP INDEX uq_prestasi_kategori_kode;

ALTER TABLE aka_prestasi_kategori ADD UNIQUE KEY uq_prestasi_kategori_kode_unit (kode, code01);

ALTER TABLE aka_prestasi_kategori ADD KEY idx_prestasi_kategori_code01 (code01);
