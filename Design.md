# Design Specification — Portal Prestasi Siswa

Dokumen ini adalah acuan desain **khusus siswa**. Aplikasi dipakai di **ponsel**. Bukan dashboard admin.

---

## 1. Produk

**Portal Prestasi Siswa** — Madrasah Mu'allimaat Muhammadiyah.

Siswa masuk, mengisi data prestasi, mengunggah bukti (PNG/JPG/PDF), lalu mengirim. Verifikasi dilakukan staf di sistem lain, **bukan** di aplikasi ini.

Hanya dua layar:

1. **Masuk**
2. **Kirim prestasi**

Tidak ada: sidebar, dashboard statistik, menu staf, verifikasi, kelola admin, grafik, tabel data institusi.

Kesan yang harus muncul:

* Resmi, tenang, mudah dithumb
* Bukan aplikasi anak-anak, bukan panel admin
* Setiap aksi jelas dalam satu layar
* Notifikasi singkat, animasi tegas, tidak ramai

---

## 2. Prinsip Mobile-First

Desain dimulai dari **lebar 360px**. Desktop memakai ruang lebih lebar (bukan sidebar admin), tanpa mengubah alur siswa.

| Perangkat | Perilaku |
|---|---|
| HP `< 768px` | Satu kolom, lebar penuh. Tombol penuh lebar. Input tinggi ≥ 48px. |
| Tablet `≥ 768px` | Konten maks. `720px`. Nilai dan tahun akademik bersebelahan. Unggah mendukung seret-lepas. |
| Desktop `≥ 1024px` | Konten maks. `1080px`. Login: hero kiri + form kanan. Kirim prestasi: kartu Rincian kiri (sticky) + form kanan. |

Aturan:

* Jangan memaksa dua kolom di HP.
* Jangan sidebar.
* Tombol kirim mudah dijangkau (dekat ibu jari / menempel bawah saat form panjang).
* Area sentuh minimal **44–48px**.
* Hindari hover sebagai satu-satunya petunjuk.

---

## 3. Identitas visual

Hijau institusi, emas sangat terbatas, netral banyak. Terasa seperti portal sekolah, bukan kartu aplikasi. Kop hijau, kertas gading, sudut hampir siku. Tanpa gradien, pill, atau bayangan tebal.

```css
--primary-900: #123D2A;
--primary-800: #185237;
--primary-700: #1F6B45;
--accent-gold: #C79A32;
--success: #2E7D4F;
--warning: #C98A16;
--danger: #B84242;
```

### Light

```css
--bg-page: #F3F6F4;
--bg-surface: #FFFFFF;
--text-primary: #18231D;
--text-secondary: #5F6B64;
--border: #DCE4DE;
```

### Dark

```css
--bg-page: #111A15;
--bg-surface: #17231C;
--text-primary: #F1F5F2;
--text-secondary: #B6C2BA;
--border: #2B3B31;
```

Emas hanya untuk garis tipis di bawah kop. Bukan latar, bukan pill.

Radius **2px**. Tanpa shadow kartu. Tanpa gradient.

---

## 4. Tipografi

* Body & form: **IBM Plex Sans** 400/500/600
* Nama madrasah / judul layar: **Source Serif 4** 600–700

HP:

```text
Nama institusi     22–24px
Judul layar        20px / 700
Label              12–13px / 600
Body / input       16px (cegah zoom iOS)
Petunjuk           12–13px
Tombol             16px / 600
```

Jangan Poppins, Comic Sans, atau font dekoratif.

---

## 5. Light / Dark

Tombol tema di pojok kanan atas (ikon matahari / bulan, SVG, bukan emoji).

* Transisi warna `200ms`
* Simpan di `localStorage` (`mualimat-theme`)
* Default: preferensi sistem
* Layout tidak berubah saat ganti tema

---

## 6. Layar masuk

Fokus HP: **logo → nama sekolah → form**.

```text
[ logo ]
Madrasah Mu'allimaat
Muhammadiyah

Masuk

Username
[                    ]
Password
[                    ]

[        Masuk        ]

Proses masuk bisa memakan waktu.
```

Di HP **jangan** panel kiri hijau berisi manifesto panjang. Itu membuang ruang ibu jari.

Di layar lebar (≥768px) boleh kartu form di tengah dengan header institusi di atas kartu — tetap satu kolom, bukan split admin.

Salinan yang dipakai (singkat):

* Judul: **Masuk**
* Bantuan: *Gunakan username dan password akun prestasi.*
* Catatan: *Jika lambat, tunggu hingga 30 detik.*

Tidak ada tab Siswa / Staf.

---

## 7. Layar kirim prestasi

Header tipis menempel atas:

```text
Logo   Nama siswa          [tema] [keluar]
       Sekolah
```

Isi satu gulir:

```text
Kirim prestasi
Lengkapi data lalu unggah bukti.

Jenis prestasi *
Keterangan *
Nilai (opsional)
Tahun akademik *
Semester *   (1 atau 2)
NISN *       (10 digit)
Bukti PNG/JPG/PDF *   maks. 2 MB

[      Kirim prestasi      ]
```

Identitas siswa ditampilkan sebagai **chip kecil**, bukan form disabled lebar seperti back-office.

Unggah: area ketuk besar, teks “Ketuk untuk pilih file”.

Setelah sukses: toast sukses, form dikosongkan, siswa bisa kirim lagi. Tidak pindah ke dashboard kosong.

---

## 8. Komponen

### Tombol utama

Tinggi 48px, lebar 100%, hijau `--primary-800`, radius 2px, teks putih.

### Input

Tinggi 48px, border 1px, radius 2px, font 16px. Focus: outline hijau, tanpa glow.

### Kartu

Bingkai 1px, tanpa bayangan. Di desktop Rincian kiri, form kanan.

---

## 9. Notifikasi (simple, animasi kuat)

Satu helper global:

```text
notify.success(pesan)
notify.error(pesan)
notify.warning(pesan)
```

Satu baris pesan. **Tanpa judul ganda** (“Berhasil” + kalimat panjang). Ikon kecil + teks.

### Isi

| Jenis | Kapan | Contoh |
|---|---|---|
| success | Login / kirim berhasil | Prestasi berhasil dikirim |
| error | Gagal API / jaringan | Tidak dapat terhubung ke server |
| warning | Form kurang | Lengkapi data yang wajib |

Jangan `alert()`. Jangan tumpuk lebih dari **satu** toast.

### Posisi

* HP: **bawah tengah**, 16px dari tepi, di atas area aman home indicator.
* Desktop: bawah tengah juga (konsisten, bukan pojok admin).

Lebar: `calc(100% - 32px)`, maks. 400px.

### Wujud

```text
┌─────────────────────────────────┐
│ ✓  Prestasi berhasil dikirim  × │
│ ████████████░░░░  progress      │
└─────────────────────────────────┘
```

* Latar: surface
* Aksen: garis kiri 4px (hijau / merah / emas)
* Radius 14px
* Shadow tegas tapi lembut
* Ikon 20px
* Tombol tutup

### Animasi (wajib terasa)

Masuk **280ms** `cubic-bezier(0.22, 1, 0.36, 1)`:

```text
opacity 0 → 1
translateY(20px) → 0
scale(0.96) → 1
```

Keluar **200ms** `ease-in`:

```text
opacity 1 → 0
translateY(8px)
scale(0.98)
```

Progress auto-tutup: success 3s, warning 3.5s, error 4.5s.

Dilarang: bounce berlebih, shake panjang, confetti, gradient bergerak.

---

## 10. Loading

Tombol yang mengeksekusi API menampilkan spinner kecil **di dalam tombol**, teks berubah (“Memproses…” / “Mengirim…”).

Jangan overlay spinner penuh layar kecuali benar-benar blocking.

---

## 11. Empty / error form

Validasi: toast warning, fokus ke field pertama yang salah bila memungkinkan.

File salah format/ukuran: toast warning, jangan diam.

---

## 12. Aksesibilitas

* `lang="id"`
* Label terhubung ke input
* Skip link
* Kontras teks memenuhi kebiasaan baca HP
* `prefers-reduced-motion`: matikan scale/slide, tetap fade singkat

---

## 13. SEO & meta

* Title: Input Prestasi Siswa | Madrasah Mu'allimaat Muhammadiyah
* Description singkat, tanpa menyebut panel staf
* `theme-color` mengikuti tema
* Canonical, OG dasar

---

## 14. Yang tidak boleh ada

* Login staf, approval, kelola pengguna
* Sidebar, breadcrumb dashboard, kartu statistik institusi
* Tabel 7 kolom, grafik tren
* Tab Siswa/Staf
* Toast bertingkat dengan judul + subtitle panjang
* Emoji di UI krom (ikon SVG saja)

---

## 15. Prompt implementasi

> Buat aplikasi mobile-first khusus siswa untuk mengirim prestasi. Hanya layar masuk dan layar form. Hijau institusi #185237, IBM Plex Sans, tombol 48px, tanpa sidebar. Notifikasi satu pesan, muncul dari bawah, animasi scale+fade 280ms, max satu toast. Simpan tema di localStorage.
