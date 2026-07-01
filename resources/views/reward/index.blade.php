<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Input Prestasi - Mualimat</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --green-900: #1b5e20;
            --green-700: #2e7d32;
            --green-500: #43a047;
            --green-100: #e8f5e9;
            --gray-50: #f8fafc;
            --gray-200: #e2e8f0;
            --gray-500: #64748b;
            --gray-800: #1e293b;
            --red-500: #ef4444;
            --shadow: 0 10px 40px rgba(27, 94, 32, 0.12);
            --radius: 14px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
            background: linear-gradient(160deg, var(--green-100) 0%, var(--gray-50) 45%, #fff 100%);
            min-height: 100vh;
            color: var(--gray-800);
        }

        .page {
            max-width: 520px;
            margin: 0 auto;
            padding: 2rem 1.25rem 3rem;
        }

        .brand {
            text-align: center;
            margin-bottom: 1.75rem;
        }

        .brand img {
            width: 96px;
            height: 96px;
            object-fit: contain;
            margin-bottom: 0.75rem;
        }

        .brand h1 {
            font-size: 1.35rem;
            font-weight: 700;
            color: var(--green-900);
        }

        .brand p {
            font-size: 0.875rem;
            color: var(--gray-500);
            margin-top: 0.25rem;
        }

        .card {
            background: #fff;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            padding: 1.75rem;
            border: 1px solid rgba(46, 125, 50, 0.08);
        }

        .card h2 {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            color: var(--green-900);
        }

        .form-group {
            margin-bottom: 1rem;
        }

        label {
            display: block;
            font-size: 0.8125rem;
            font-weight: 600;
            color: var(--gray-800);
            margin-bottom: 0.4rem;
        }

        label span {
            color: var(--red-500);
        }

        input[type="text"],
        input[type="password"],
        input[type="number"],
        select,
        textarea {
            width: 100%;
            padding: 0.7rem 0.85rem;
            border: 1.5px solid var(--gray-200);
            border-radius: 10px;
            font: inherit;
            font-size: 0.9375rem;
            transition: border-color 0.15s, box-shadow 0.15s;
            background: #fff;
        }

        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--green-500);
            box-shadow: 0 0 0 3px rgba(67, 160, 71, 0.15);
        }

        textarea { resize: vertical; min-height: 88px; }

        .file-hint {
            font-size: 0.75rem;
            color: var(--gray-500);
            margin-top: 0.35rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 0.8rem 1rem;
            border: none;
            border-radius: 10px;
            font: inherit;
            font-size: 0.9375rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.1s, opacity 0.15s;
        }

        .btn:active { transform: scale(0.98); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }

        .btn-primary {
            background: linear-gradient(135deg, var(--green-700), var(--green-500));
            color: #fff;
            margin-top: 0.5rem;
        }

        .btn-outline {
            background: transparent;
            color: var(--green-700);
            border: 1.5px solid var(--green-500);
            margin-top: 0.75rem;
            width: auto;
            padding: 0.55rem 1rem;
            font-size: 0.8125rem;
        }

        .alert {
            padding: 0.75rem 1rem;
            border-radius: 10px;
            font-size: 0.875rem;
            margin-bottom: 1rem;
            display: none;
        }

        .alert.show { display: block; }
        .alert-error { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
        .alert-success { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }

        .user-bar {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 1rem;
            background: var(--green-100);
            border-radius: 10px;
            padding: 0.85rem 1rem;
            margin-bottom: 1.25rem;
            font-size: 0.8125rem;
        }

        .user-bar strong { display: block; font-size: 0.9375rem; color: var(--green-900); }
        .user-bar span { color: var(--gray-500); }

        .hidden { display: none !important; }

        .spinner {
            width: 18px;
            height: 18px;
            border: 2px solid rgba(255,255,255,0.4);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
            margin-right: 0.5rem;
        }

        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="page">
        <div class="brand">
            <img src="{{ $logoUrl }}" alt="Logo Mualimat">
            <h1>Input Prestasi Siswa</h1>
            <p>Madrasah Mu'allimaat Muhammadiyah</p>
        </div>

        <div id="alert" class="alert" role="alert"></div>

        <!-- Login -->
        <div id="loginSection" class="card">
            <h2>Masuk</h2>
            <form id="loginForm">
                <div class="form-group">
                    <label for="username">Username <span>*</span></label>
                    <input type="text" id="username" name="username" autocomplete="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password <span>*</span></label>
                    <input type="password" id="password" name="password" autocomplete="current-password" required>
                </div>
                <button type="submit" class="btn btn-primary" id="loginBtn">Masuk</button>
            </form>
        </div>

        <!-- Form Prestasi -->
        <div id="prestasiSection" class="card hidden">
            <div class="user-bar">
                <div>
                    <strong id="userName">-</strong>
                    <span id="userInfo">-</span>
                </div>
                <button type="button" class="btn btn-outline" id="logoutBtn">Keluar</button>
            </div>

            <h2>Data Prestasi</h2>
            <form id="prestasiForm">
                <div class="form-group">
                    <label for="jenis_prestasi">Jenis Prestasi <span>*</span></label>
                    <input type="text" id="jenis_prestasi" name="jenis_prestasi" required placeholder="Contoh: Olimpiade Matematika">
                </div>
                <div class="form-group">
                    <label for="keterangan">Keterangan <span>*</span></label>
                    <textarea id="keterangan" name="keterangan" required placeholder="Deskripsi prestasi yang diraih"></textarea>
                </div>
                <div class="form-group">
                    <label for="nilai_penghargaan">Nilai Penghargaan</label>
                    <input type="text" id="nilai_penghargaan" name="nilai_penghargaan" placeholder="Contoh: Juara 1 / Emas">
                </div>
                <div class="form-group">
                    <label for="tahun_akademik">Tahun Akademik <span>*</span></label>
                    <input type="text" id="tahun_akademik" name="tahun_akademik" required placeholder="Contoh: 2025/2026">
                </div>
                <div class="form-group">
                    <label for="file">Upload Bukti (PNG/JPG/PDF) <span>*</span></label>
                    <input type="file" id="file" name="file" accept=".png,.jpg,.jpeg,.pdf,image/png,image/jpeg,application/pdf" required>
                    <p class="file-hint">Maksimal 2 MB. Format: PNG, JPG, atau PDF.</p>
                </div>
                <button type="submit" class="btn btn-primary" id="submitBtn">Kirim Prestasi</button>
            </form>
        </div>
    </div>

    <script>
        const WS_URL = @json($wsUrl);
        const STORAGE_KEY = 'mualimat_reward_session';

        const loginSection = document.getElementById('loginSection');
        const prestasiSection = document.getElementById('prestasiSection');
        const alertEl = document.getElementById('alert');
        const loginForm = document.getElementById('loginForm');
        const prestasiForm = document.getElementById('prestasiForm');
        const loginBtn = document.getElementById('loginBtn');
        const submitBtn = document.getElementById('submitBtn');

        function showAlert(message, type = 'error') {
            alertEl.textContent = message;
            alertEl.className = 'alert show alert-' + type;
        }

        function hideAlert() {
            alertEl.className = 'alert';
        }

        function getSession() {
            try {
                return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || 'null');
            } catch {
                return null;
            }
        }

        function saveSession(data) {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify(data));
        }

        function clearSession() {
            sessionStorage.removeItem(STORAGE_KEY);
        }

        function showPrestasiForm(session) {
            loginSection.classList.add('hidden');
            prestasiSection.classList.remove('hidden');
            document.getElementById('userName').textContent = session.nmcust || '-';
            document.getElementById('userInfo').textContent =
                'No: ' + (session.nocust || '-') + ' | Kelas: ' + (session.kelas || '-');
        }

        function showLoginForm() {
            prestasiSection.classList.add('hidden');
            loginSection.classList.remove('hidden');
            prestasiForm.reset();
        }

        async function callWs(payload, isFormData = false) {
            const options = { method: 'POST' };

            if (isFormData) {
                options.body = payload;
            } else {
                options.headers = { 'Content-Type': 'application/json' };
                options.body = JSON.stringify(payload);
            }

            let res;
            try {
                res = await fetch(WS_URL, options);
            } catch (err) {
                throw new Error('Tidak dapat terhubung ke server API aplikasi (/api/reward). Cek koneksi domain dan cache Laravel.');
            }

            const data = await res.json().catch(() => ({}));

            if (!res.ok || data.status !== 200) {
                throw new Error(data.message || 'Permintaan gagal');
            }

            return data;
        }

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            hideAlert();
            loginBtn.disabled = true;
            loginBtn.innerHTML = '<span class="spinner"></span> Memproses...';

            try {
                const username = document.getElementById('username').value.trim();
                const password = document.getElementById('password').value;

                const response = await callWs({ method: 'login', username, password });
                const data = response?.data;
                if (!data || !data.token) {
                    throw new Error(response?.message || 'Respons login WS tidak lengkap (token tidak ada)');
                }
                const session = {
                    token: data.token,
                    custid: data.custid,
                    nocust: data.nocust,
                    nmcust: data.nmcust,
                    kelas: data.kelas,
                };
                saveSession(session);
                showPrestasiForm(session);
                showAlert('Login berhasil. Silakan isi data prestasi.', 'success');
            } catch (err) {
                showAlert(err.message || 'Login gagal');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = 'Masuk';
            }
        });

        prestasiForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            hideAlert();

            const session = getSession();
            if (!session?.token) {
                showAlert('Sesi habis, silakan login ulang');
                clearSession();
                showLoginForm();
                return;
            }

            const fileInput = document.getElementById('file');
            const file = fileInput.files[0];
            if (!file) {
                showAlert('File wajib diupload');
                return;
            }
            if (file.size > 2 * 1024 * 1024) {
                showAlert('Ukuran file maksimal 2 MB');
                return;
            }

            const allowed = ['image/png', 'image/jpeg', 'application/pdf'];
            if (!allowed.includes(file.type)) {
                showAlert('Format file harus PNG, JPG, atau PDF');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner"></span> Mengirim...';

            try {
                const formData = new FormData();
                formData.append('method', 'submitPrestasi');
                formData.append('token', session.token);
                formData.append('jenis_prestasi', document.getElementById('jenis_prestasi').value.trim());
                formData.append('keterangan', document.getElementById('keterangan').value.trim());
                formData.append('nilai_penghargaan', document.getElementById('nilai_penghargaan').value.trim());
                formData.append('tahun_akademik', document.getElementById('tahun_akademik').value.trim());
                formData.append('file', file);

                const response = await callWs(formData, true);
                if (!response?.data) {
                    throw new Error(response?.message || 'Respons submit WS tidak lengkap');
                }
                prestasiForm.reset();
                showAlert('Prestasi berhasil dikirim dan menunggu persetujuan.', 'success');
            } catch (err) {
                if ((err.message || '').toLowerCase().includes('token')) {
                    clearSession();
                    showLoginForm();
                }
                showAlert(err.message || 'Gagal mengirim prestasi');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Kirim Prestasi';
            }
        });

        document.getElementById('logoutBtn').addEventListener('click', () => {
            clearSession();
            hideAlert();
            showLoginForm();
        });

        const existing = getSession();
        if (existing?.token) {
            showPrestasiForm(existing);
        }
    </script>
</body>
</html>
