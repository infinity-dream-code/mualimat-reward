<!DOCTYPE html>
<html lang="id" class="light">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ $pageTitle }}</title>
    <meta name="description" content="{{ $pageDescription }}">
    <meta name="robots" content="index, follow">
    <meta name="author" content="{{ $siteName }}">
    <meta name="theme-color" content="#185237">
    <link rel="canonical" href="{{ $canonical }}">
    <link rel="icon" href="{{ $logoUrl }}" type="image/svg+xml">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=Source+Serif+4:opsz,wght@8..60,600;8..60,700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="{{ asset('css/portal.css') }}?v={{ filemtime(public_path('css/portal.css')) }}">
    <meta property="og:type" content="website">
    <meta property="og:locale" content="id_ID">
    <meta property="og:title" content="{{ $pageTitle }}">
    <meta property="og:description" content="{{ $pageDescription }}">
    <meta property="og:url" content="{{ $canonical }}">
    <script>
        (function () {
            var saved = localStorage.getItem('mualimat-theme');
            var theme = saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
            document.documentElement.className = theme;
        })();
    </script>
</head>
<body>
    <a class="skip-link" href="#konten-utama">Lewati ke konten</a>

    <header class="topbar">
        <div class="topbar-inner">
            <div class="brand">
                <img src="{{ $logoUrl }}" alt="" width="36" height="36">
                <div>
                    <strong id="barTitle">{{ $siteName }}</strong>
                    <span id="barMeta">Portal prestasi siswa</span>
                </div>
            </div>
            <div class="top-actions">
                <button type="button" class="icon-btn" id="themeBtn" aria-label="Ganti tema"></button>
                <button type="button" class="btn-ghost hidden" id="logoutBtn">Keluar</button>
            </div>
        </div>
    </header>

    <main id="konten-utama" class="wrap">
        <section id="view-login">
            <div class="login-hero">
                <img src="{{ $logoUrl }}" alt="Logo {{ $siteName }}" width="72" height="72">
                <div class="login-hero-copy">
                    <h1>{{ $siteName }}</h1>
                    <p>Kirim prestasi beserta bukti pendukung.</p>
                </div>
            </div>
            <div class="sheet">
                <h2>Masuk</h2>
                <p class="lead">Gunakan username dan password akun siswa.</p>
                <form id="loginForm">
                    <div class="field">
                        <label for="username">Username <span>*</span></label>
                        <input type="text" id="username" name="username" autocomplete="username" required maxlength="50" pattern="[a-zA-Z0-9._@-]+" inputmode="text">
                    </div>
                    <div class="field">
                        <label for="password">Password <span>*</span></label>
                        <input type="password" id="password" name="password" autocomplete="current-password" required maxlength="128">
                    </div>
                    <button type="submit" class="btn btn-primary" id="loginBtn">Masuk</button>
                    <p class="hint">Jika lambat, tunggu hingga 30 detik.</p>
                </form>
            </div>
        </section>

        <section id="view-form" class="hidden is-list">
            <div class="panel-nav" role="tablist" aria-label="Menu siswa">
                <button type="button" id="tabList" class="active" aria-selected="true">Pengajuan</button>
                <button type="button" id="tabForm" aria-selected="false">Kirim</button>
            </div>
            <div class="side-col panel-list">
                <section class="rincian" aria-labelledby="rincianTitle">
                    <h2 id="rincianTitle">Rincian</h2>
                    <dl>
                        <div>
                            <dt>Nama</dt>
                            <dd id="rincianNama">—</dd>
                        </div>
                        <div>
                            <dt>Unit</dt>
                            <dd id="rincianUnit">—</dd>
                        </div>
                        <div>
                            <dt>Kelas</dt>
                            <dd id="rincianKelas">—</dd>
                        </div>
                        <div>
                            <dt>Kelompok</dt>
                            <dd id="rincianKelompok">—</dd>
                        </div>
                        <div>
                            <dt>Skor</dt>
                            <dd id="rincianSkor">0</dd>
                        </div>
                    </dl>
                </section>
                <section class="sheet sheet-list" aria-labelledby="listTitle">
                    <div class="list-head">
                        <h2 id="listTitle">Pengajuan</h2>
                        <label class="sr-only" for="filterStatus">Filter status</label>
                        <select id="filterStatus">
                            <option value="">Semua</option>
                            <option value="pending">Menunggu</option>
                            <option value="approve">Disetujui</option>
                            <option value="canceled">Ditolak</option>
                        </select>
                    </div>
                    <p class="lead" id="listMeta">Skor dihitung dari pengajuan yang sudah disetujui.</p>
                    <div id="pengajuanList"></div>
                </section>
            </div>
            <div class="form-col panel-form">
            <div class="sheet">
                <h2 id="formTitle">Kirim prestasi</h2>
                <p class="lead" id="formLead">Lengkapi data, pilih jenis prestasi, lalu lampirkan tautan bukti.</p>
                <div id="editBanner" class="edit-banner hidden" role="status"></div>
                <form id="prestasiForm" autocomplete="off">
                    <input type="hidden" id="edit_id" value="">
                    <div class="field-row field-row-3">
                        <div class="field">
                            <label for="nisn">NISN</label>
                            <input type="text" id="nisn" name="nisn" maxlength="10" inputmode="numeric" placeholder="10 digit (opsional)" autocomplete="off">
                        </div>
                        <div class="field">
                            <label for="tahun_akademik">Tahun akademik <span>*</span></label>
                            <select id="tahun_akademik" required>
                                <option value="">Pilih tahun</option>
                                @foreach ($tahunAkademik as $thn)
                                    <option value="{{ $thn }}">{{ $thn }}</option>
                                @endforeach
                            </select>
                        </div>
                        <div class="field">
                            <label for="semester">Semester <span>*</span></label>
                            <select id="semester" required>
                                <option value="1" selected>Semester 1</option>
                                <option value="2">Semester 2</option>
                            </select>
                        </div>
                    </div>

                    <div class="field">
                        <label for="prestasi_kategori_id">Kategori prestasi <span>*</span></label>
                        <select id="prestasi_kategori_id" required>
                            <option value="">Pilih kategori prestasi</option>
                        </select>
                    </div>
                    <div class="field">
                        <label for="prestasi_tingkat_id">Jenis prestasi <span>*</span></label>
                        <select id="prestasi_tingkat_id" required disabled>
                            <option value="">Pilih jenis prestasi</option>
                        </select>
                    </div>
                    <div class="field">
                        <label for="prestasi_poin_id">Capaian / poin <span>*</span></label>
                        <select id="prestasi_poin_id" required disabled>
                            <option value="">Pilih capaian</option>
                        </select>
                    </div>
                    <div class="field">
                        <label for="nilai_tampil">Nilai poin</label>
                        <input type="text" id="nilai_tampil" readonly value="—" aria-live="polite">
                        <p class="hint">Nilai diisi admin. Saat ini semua 0.</p>
                    </div>

                    <div class="field">
                        <label for="keterangan">Keterangan / deskripsi <span>*</span><small id="countKet">0/500</small></label>
                        <textarea id="keterangan" required maxlength="500" placeholder="Uraian singkat prestasi"></textarea>
                    </div>
                    <div class="field">
                        <label for="penyelenggara">Penyelenggara <span>*</span></label>
                        <input type="text" id="penyelenggara" required maxlength="150" placeholder="Nama lembaga atau panitia">
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label for="no_sertifikat">No. sertifikat <span>*</span></label>
                            <input type="text" id="no_sertifikat" required maxlength="80" placeholder="Nomor pada sertifikat">
                        </div>
                        <div class="field">
                            <label for="tanggal_pelaksanaan">Tanggal pelaksanaan <span>*</span></label>
                            <input type="date" id="tanggal_pelaksanaan" name="tanggal_pelaksanaan" required min="2000-01-01" max="{{ (int) date('Y') + 1 }}-12-31">
                            <p class="hint">Tanggal lomba atau kegiatan dilaksanakan.</p>
                        </div>
                    </div>
                    <div class="field">
                        <label for="url">Link foto dan video <span>*</span></label>
                        <input type="url" id="url" required maxlength="500" placeholder="https://drive.google.com/...">
                        <p class="hint">Tautan Google Drive yang bisa diakses untuk verifikasi.</p>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary" id="submitBtn">Kirim prestasi</button>
                        <button type="button" class="btn-outline hidden" id="cancelEditBtn">Batal perbaiki</button>
                    </div>
                </form>
            </div>
            </div>
        </section>
    </main>

    <div class="toast-stack" id="toastStack"></div>

    <script>
        window.PORTAL_CONFIG = {
            wsUrl: @json($wsUrl),
            tahunAkademik: @json($tahunAkademik)
        };
    </script>
    <script src="{{ asset('js/portal.js') }}?v={{ filemtime(public_path('js/portal.js')) }}" defer></script>
</body>
</html>
