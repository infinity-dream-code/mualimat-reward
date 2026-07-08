-- Renumber id aka_reward → 1, 2, 3, ... (MariaDB/MySQL)
-- JALANKAN SEKALI SAJA. Jangan diulang kalau sudah benar.
-- Database: yogya_muallimaat

SET FOREIGN_KEY_CHECKS = 0;

-- Langkah A: geser ke angka besar dulu (supaya tidak bentrok saat jadi 1,2,3...)
UPDATE `aka_reward` SET `id` = `id` + 2000000;

-- Langkah B: renumber urut dari created_at paling lama
-- PENTING: SET dulu, baru ORDER BY (bukan sebaliknya!)
SET @n := 0;
UPDATE `aka_reward`
SET `id` = (@n := @n + 1)
ORDER BY `created_at` ASC, `id` ASC;

-- Langkah C: pasang AUTO_INCREMENT
ALTER TABLE `aka_reward`
  MODIFY COLUMN `id` INT(11) NOT NULL AUTO_INCREMENT;

SET @next_ai := (SELECT IFNULL(MAX(`id`), 0) + 1 FROM `aka_reward`);
SET @sql := CONCAT('ALTER TABLE `aka_reward` AUTO_INCREMENT = ', @next_ai);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET FOREIGN_KEY_CHECKS = 1;

-- Harusnya: id = 1, 2, 3, 4, 5, 6 (sesuai jumlah baris)
SELECT `id`, `jenis_prestasi`, `created_at`
FROM `aka_reward`
ORDER BY `id` ASC;

DESCRIBE `aka_reward`;
