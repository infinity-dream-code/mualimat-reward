(() => {
    const cfg = window.PORTAL_CONFIG || {};
    const WS_URL = cfg.wsUrl || '/api/reward';
    const INITIAL_TAHUN = Array.isArray(cfg.tahunAkademik) ? cfg.tahunAkademik : [];
    const KEY_SESSION = 'mualimat_reward_session';
    const KEY_TAHUN = 'mualimat_reward_tahun_akademik';
    const KEY_THEME = 'mualimat-theme';
    const TIMEOUT = 95000;

    const $ = (id) => document.getElementById(id);
    const sun = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
    const moon = '<svg viewBox="0 0 24 24"><path d="M21 14.5A8.5 8.5 0 1 1 9.5 3 7 7 0 0 0 21 14.5Z"/></svg>';
    const ico = {
        success: '<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>',
        error: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m15 9-6 6M9 9l6 6"/></svg>',
        warning: '<svg viewBox="0 0 24 24"><path d="M12 9v4M12 17h.01M10.3 4.2 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z"/></svg>',
    };

    let tahunPromise = null;
    let katalogPromise = null;
    let toastTimer = null;
    let katalog = { kategori: [], tingkat: [], poin: [] };
    let pengajuan = [];
    let pengajuanFilter = '';

    const STATUS_LABEL = {
        pending: 'Menunggu',
        approve: 'Disetujui',
        canceled: 'Ditolak',
    };

    function escapeHtml(v) {
        return String(v ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
    }

    function toast(type, message, duration) {
        const stack = $('toastStack');
        stack.innerHTML = '';
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        el.innerHTML = `${ico[type] || ''}<p>${escapeHtml(message)}</p><button type="button" class="toast-close" aria-label="Tutup">×</button><div class="toast-bar"><i style="animation-duration:${duration}ms"></i></div>`;
        const close = () => {
            el.classList.add('out');
            setTimeout(() => el.remove(), 200);
        };
        el.querySelector('.toast-close').onclick = close;
        stack.appendChild(el);
        clearTimeout(toastTimer);
        toastTimer = setTimeout(close, duration);
    }

    const notify = {
        success(msg) { toast('success', msg, 3000); },
        error(msg) { toast('error', msg, 4500); },
        warning(msg) { toast('warning', msg, 3500); },
    };
    window.notify = notify;

    function applyTheme(theme) {
        document.documentElement.className = theme;
        localStorage.setItem(KEY_THEME, theme);
        $('themeBtn').innerHTML = theme === 'dark' ? sun : moon;
        document.querySelector('meta[name="theme-color"]').setAttribute('content', theme === 'dark' ? '#111A15' : '#185237');
    }
    $('themeBtn').addEventListener('click', () => {
        applyTheme(document.documentElement.classList.contains('dark') ? 'light' : 'dark');
    });
    applyTheme(document.documentElement.classList.contains('dark') ? 'dark' : 'light');

    function session() {
        try { return JSON.parse(sessionStorage.getItem(KEY_SESSION) || 'null'); } catch { return null; }
    }

    async function callWs(payload, isFormData = false) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), TIMEOUT);
        const options = { method: 'POST', signal: controller.signal };
        if (isFormData) options.body = payload;
        else {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify(payload);
        }
        try {
            const res = await fetch(WS_URL, options);
            const text = await res.text();
            let data = {};
            try { data = text ? JSON.parse(text) : {}; } catch { data = { status: 500, message: 'Respons server tidak valid' }; }
            if (!res.ok || data.status !== 200) throw new Error(data.message || 'Permintaan gagal. Silakan coba lagi.');
            return data;
        } catch (err) {
            if (err?.name === 'AbortError') throw new Error('Server terlalu lama merespons. Silakan coba lagi.');
            if (err instanceof Error && err.message && !err.message.startsWith('Failed')) throw err;
            throw new Error('Tidak dapat terhubung ke server. Silakan coba lagi.');
        } finally { clearTimeout(timer); }
    }

    function cachedTahun() {
        if (INITIAL_TAHUN.length) return INITIAL_TAHUN;
        try {
            const p = JSON.parse(sessionStorage.getItem(KEY_TAHUN) || '[]');
            return Array.isArray(p) ? p : [];
        } catch { return []; }
    }

    function fillTahun(list) {
        const sel = $('tahun_akademik');
        sel.innerHTML = '<option value="">Pilih tahun</option>';
        list.forEach((item) => {
            const o = document.createElement('option');
            o.value = item;
            o.textContent = item;
            sel.appendChild(o);
        });
    }

    function loadTahun() {
        const cached = cachedTahun();
        if (cached.length) { fillTahun(cached); return Promise.resolve(); }
        if (tahunPromise) return tahunPromise;
        tahunPromise = callWs({ method: 'getTahunAkademik' })
            .then((res) => {
                const list = res.data?.tahun_akademik || [];
                if (list.length) sessionStorage.setItem(KEY_TAHUN, JSON.stringify(list));
                fillTahun(list);
            })
            .catch((err) => notify.error(err.message))
            .finally(() => { tahunPromise = null; });
        return tahunPromise;
    }

    function showLogin() {
        $('view-login').classList.remove('hidden');
        $('view-form').classList.add('hidden');
        $('logoutBtn').classList.add('hidden');
        $('barTitle').textContent = 'Madrasah Mu\'allimaat Muhammadiyah';
        $('barMeta').textContent = 'Portal prestasi siswa';
    }

    function showForm(user) {
        $('view-login').classList.add('hidden');
        $('view-form').classList.remove('hidden');
        $('logoutBtn').classList.remove('hidden');
        $('barTitle').textContent = user.nmcust || user.nocust || 'Siswa';
        const metaParts = [user.unit, user.kelas, user.kelompok].filter(Boolean);
        $('barMeta').textContent = metaParts.length ? metaParts.join(' · ') : 'Siswa';
        $('rincianUnit').textContent = user.unit || '—';
        const nama = user.nmcust || user.nocust || '—';
        $('rincianNama').textContent = nama;
        $('rincianNama').title = nama;
        $('rincianKelas').textContent = user.kelas || '—';
        const kelompok = user.kelompok || '—';
        $('rincianKelompok').textContent = kelompok;
        $('rincianKelompok').title = kelompok;
        loadTahun();
        katalog = { kategori: [], tingkat: [], poin: [] };
        loadKatalog();
        loadPengajuan();
        setPanel('list');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    $('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = $('username').value.trim();
        const password = $('password').value;
        if (!/^[a-zA-Z0-9._@-]{1,50}$/.test(username) || !password) {
            notify.warning('Lengkapi username dan password.');
            return;
        }
        $('loginBtn').disabled = true;
        $('loginBtn').innerHTML = '<span class="spinner"></span> Memproses…';
        try {
            const res = await callWs({ method: 'login', username, password });
            if (!res.data?.token) throw new Error('Login gagal. Silakan coba lagi.');
            sessionStorage.setItem(KEY_SESSION, JSON.stringify(res.data));
            notify.success('Login berhasil.');
            showForm(res.data);
        } catch (err) {
            notify.error(err.message);
        } finally {
            $('loginBtn').disabled = false;
            $('loginBtn').textContent = 'Masuk';
        }
    });

    function fillSelect(sel, items, placeholder) {
        sel.innerHTML = '';
        const first = document.createElement('option');
        first.value = '';
        first.textContent = placeholder;
        sel.appendChild(first);
        items.forEach((item) => {
            const o = document.createElement('option');
            o.value = String(item.id);
            o.textContent = item.nama;
            if (item.nilai !== undefined && item.nilai !== null) {
                o.dataset.nilai = String(item.nilai);
            }
            sel.appendChild(o);
        });
    }

    function tingkatByKategori(kategoriId) {
        return katalog.tingkat.filter((t) => String(t.kategori_id) === String(kategoriId));
    }

    function poinByTingkat(tingkatId) {
        return katalog.poin.filter((p) => String(p.tingkat_id) === String(tingkatId));
    }

    function resetTingkat() {
        fillSelect($('prestasi_tingkat_id'), [], 'Pilih jenis prestasi');
        $('prestasi_tingkat_id').disabled = true;
        resetPoin();
    }

    function resetPoin() {
        fillSelect($('prestasi_poin_id'), [], 'Pilih capaian');
        $('prestasi_poin_id').disabled = true;
        $('nilai_tampil').value = '—';
    }

    function fillKategori() {
        fillSelect($('prestasi_kategori_id'), katalog.kategori, 'Pilih kategori prestasi');
        resetTingkat();
    }

    function loadKatalog() {
        if (katalog.kategori.length) {
            fillKategori();
            return Promise.resolve();
        }
        if (katalogPromise) return katalogPromise;
        katalogPromise = callWs({ method: 'getPrestasiKatalog', token: session()?.token || '' })
            .then((res) => {
                katalog = {
                    kategori: res.data?.kategori || [],
                    tingkat: res.data?.tingkat || [],
                    poin: res.data?.poin || [],
                };
                fillKategori();
            })
            .catch((err) => notify.error(err.message))
            .finally(() => { katalogPromise = null; });
        return katalogPromise;
    }

    function formatSkor(value) {
        const n = Number(value);
        if (!Number.isFinite(n)) return '0';
        return n.toLocaleString('id-ID', { maximumFractionDigits: 2 });
    }

    function formatTanggal(value) {
        const raw = String(value || '').slice(0, 10);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return '';
        const [y, m, d] = raw.split('-');
        return `${d}/${m}/${y}`;
    }

    function isValidTanggalPelaksanaan(value) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
        const [y, m, d] = value.split('-').map(Number);
        const dt = new Date(y, m - 1, d);
        if (dt.getFullYear() !== y || dt.getMonth() !== m - 1 || dt.getDate() !== d) return false;
        const maxYear = new Date().getFullYear() + 1;
        return y >= 2000 && y <= maxYear;
    }

    function setPanel(name) {
        const formView = $('view-form');
        formView.classList.toggle('is-list', name === 'list');
        formView.classList.toggle('is-form', name === 'form');
        $('tabList').classList.toggle('active', name === 'list');
        $('tabForm').classList.toggle('active', name === 'form');
        $('tabList').setAttribute('aria-selected', name === 'list' ? 'true' : 'false');
        $('tabForm').setAttribute('aria-selected', name === 'form' ? 'true' : 'false');
    }

    function setEditMode(item) {
        const editing = !!item;
        $('edit_id').value = editing ? String(item.id) : '';
        $('formTitle').textContent = editing ? 'Perbaiki prestasi' : 'Kirim prestasi';
        $('formLead').textContent = editing
            ? 'Ubah data atau tautan bukti, lalu kirim ulang. Status akan kembali menunggu persetujuan.'
            : 'Lengkapi data, pilih jenis prestasi, lalu lampirkan tautan bukti.';
        $('submitBtn').textContent = editing ? 'Kirim ulang' : 'Kirim prestasi';
        $('cancelEditBtn').classList.toggle('hidden', !editing);
        const banner = $('editBanner');
        if (editing && item.catatan_admin) {
            banner.classList.remove('hidden');
            banner.innerHTML = `<strong>Catatan admin</strong>${escapeHtml(item.catatan_admin)}`;
        } else {
            banner.classList.add('hidden');
            banner.innerHTML = '';
        }
    }

    function resetFormFields() {
        $('prestasiForm').reset();
        $('edit_id').value = '';
        $('countKet').textContent = '0/500';
        fillTahun(cachedTahun());
        $('semester').value = '1';
        fillKategori();
        setEditMode(null);
    }

    function renderPengajuan() {
        const box = $('pengajuanList');
        const total = formatSkor($('rincianSkor').dataset.total || '0');
        const filtered = pengajuanFilter
            ? pengajuan.filter((item) => item.isapproved === pengajuanFilter)
            : pengajuan;
        const counts = pengajuan.reduce((acc, item) => {
            acc[item.isapproved] = (acc[item.isapproved] || 0) + 1;
            return acc;
        }, {});
        $('listMeta').textContent = pengajuan.length
            ? `${pengajuan.length} pengajuan · ${counts.approve || 0} disetujui · skor ${total}`
            : 'Belum ada pengajuan. Skor dihitung setelah admin menyetujui.';
        if (!filtered.length) {
            box.innerHTML = `<p class="pengajuan-empty">${pengajuan.length ? 'Tidak ada pengajuan pada filter ini.' : 'Belum ada prestasi yang dikirim.'}</p>`;
            return;
        }
        box.innerHTML = filtered.map((item) => {
            const st = item.isapproved || 'pending';
            const tglLaksana = formatTanggal(item.tanggal_pelaksanaan);
            const tgl = formatTanggal(item.updated_at || item.created_at);
            const note = st === 'canceled' && item.catatan_admin
                ? `<p class="pengajuan-note">Catatan: ${escapeHtml(item.catatan_admin)}</p>`
                : '';
            const editBtn = item.can_edit
                ? `<button type="button" data-edit="${item.id}">Perbaiki</button>`
                : '';
            const link = item.url
                ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">Lihat bukti</a>`
                : '';
            return `<article class="pengajuan-item" data-id="${item.id}">
                <h3>${escapeHtml(item.jenis_prestasi || 'Prestasi')}</h3>
                <div class="pengajuan-meta">
                    <span class="st st-${escapeHtml(st)}">${STATUS_LABEL[st] || st}</span>
                    <span>Poin ${escapeHtml(formatSkor(item.nilai_penghargaan))}</span>
                    ${tglLaksana ? `<span>Pelaksanaan ${tglLaksana}</span>` : ''}
                    ${tgl ? `<span>${tgl}</span>` : ''}
                </div>
                ${note}
                <div class="pengajuan-actions">${link}${editBtn}</div>
            </article>`;
        }).join('');
    }

    function loadPengajuan() {
        const user = session();
        if (!user?.token) return Promise.resolve();
        return callWs({ method: 'getPrestasiSaya', token: user.token })
            .then((res) => {
                pengajuan = Array.isArray(res.data?.items) ? res.data.items : [];
                const total = res.data?.total_skor ?? '0';
                $('rincianSkor').textContent = formatSkor(total);
                $('rincianSkor').dataset.total = String(total);
                $('rincianSkor').title = 'Total poin dari pengajuan yang disetujui';
                renderPengajuan();
            })
            .catch((err) => {
                $('pengajuanList').innerHTML = `<p class="pengajuan-empty">${escapeHtml(err.message)}</p>`;
                notify.error(err.message);
            });
    }

    async function startEdit(id) {
        const item = pengajuan.find((row) => String(row.id) === String(id));
        if (!item || !item.can_edit) {
            notify.warning('Pengajuan ini tidak bisa diperbaiki.');
            return;
        }
        await loadKatalog();
        setEditMode(item);
        $('nisn').value = item.nisn || '';
        fillTahun(cachedTahun());
        $('tahun_akademik').value = item.tahun_akademik || '';
        $('semester').value = String(item.semester || '1');
        fillKategori();
        $('prestasi_kategori_id').value = String(item.prestasi_kategori_id || '');
        $('prestasi_kategori_id').dispatchEvent(new Event('change'));
        $('prestasi_tingkat_id').value = String(item.prestasi_tingkat_id || '');
        $('prestasi_tingkat_id').dispatchEvent(new Event('change'));
        $('prestasi_poin_id').value = String(item.prestasi_poin_id || '');
        $('prestasi_poin_id').dispatchEvent(new Event('change'));
        $('keterangan').value = item.keterangan || '';
        $('countKet').textContent = $('keterangan').value.length + '/500';
        $('penyelenggara').value = item.penyelenggara || '';
        $('no_sertifikat').value = item.no_sertifikat || '';
        $('tanggal_pelaksanaan').value = String(item.tanggal_pelaksanaan || '').slice(0, 10);
        $('url').value = item.url || '';
        setPanel('form');
        $('prestasiForm').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    $('tabList').addEventListener('click', () => setPanel('list'));
    $('tabForm').addEventListener('click', () => setPanel('form'));
    $('filterStatus').addEventListener('change', () => {
        pengajuanFilter = $('filterStatus').value;
        renderPengajuan();
    });
    $('pengajuanList').addEventListener('click', (e) => {
        const btn = e.target.closest('[data-edit]');
        if (!btn) return;
        startEdit(btn.getAttribute('data-edit'));
    });
    $('cancelEditBtn').addEventListener('click', () => {
        resetFormFields();
        notify.success('Perbaikan dibatalkan.');
    });

    $('prestasi_kategori_id').addEventListener('change', () => {
        const id = $('prestasi_kategori_id').value;
        if (!id) {
            resetTingkat();
            return;
        }
        const list = tingkatByKategori(id);
        fillSelect($('prestasi_tingkat_id'), list, 'Pilih jenis prestasi');
        $('prestasi_tingkat_id').disabled = list.length === 0;
        resetPoin();
    });

    $('prestasi_tingkat_id').addEventListener('change', () => {
        const id = $('prestasi_tingkat_id').value;
        if (!id) {
            resetPoin();
            return;
        }
        const list = poinByTingkat(id);
        fillSelect($('prestasi_poin_id'), list, 'Pilih capaian');
        $('prestasi_poin_id').disabled = list.length === 0;
        $('nilai_tampil').value = '—';
    });

    $('prestasi_poin_id').addEventListener('change', () => {
        const opt = $('prestasi_poin_id').selectedOptions[0];
        $('nilai_tampil').value = opt && opt.dataset.nilai !== undefined ? opt.dataset.nilai : '—';
    });

    $('keterangan').addEventListener('input', () => {
        $('countKet').textContent = $('keterangan').value.length + '/500';
    });

    $('prestasiForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const user = session();
        if (!user?.token) {
            notify.error('Sesi habis, silakan masuk lagi.');
            logout();
            return;
        }
        const nisn = $('nisn').value.trim();
        const tahun = $('tahun_akademik').value.trim();
        const semester = $('semester').value.trim();
        const kategori = $('prestasi_kategori_id').value.trim();
        const tingkat = $('prestasi_tingkat_id').value.trim();
        const poin = $('prestasi_poin_id').value.trim();
        const ket = $('keterangan').value.trim();
        const penyelenggara = $('penyelenggara').value.trim();
        const sertifikat = $('no_sertifikat').value.trim();
        const tanggal = $('tanggal_pelaksanaan').value.trim();
        const url = $('url').value.trim();
        const driveOk = /^https:\/\/(drive|docs)\.google\.com\//i.test(url)
            || /^https:\/\/drive\.usercontent\.google\.com\//i.test(url);
        if (nisn !== '' && !/^\d{10}$/.test(nisn)) {
            notify.warning('NISN harus 10 digit angka, atau biarkan kosong.');
            return;
        }
        if (!isValidTanggalPelaksanaan(tanggal)) {
            notify.warning('Tanggal pelaksanaan wajib diisi.');
            return;
        }
        if (!/^\d{4}\/\d{4}$/.test(tahun) || !/^[12]$/.test(semester)
            || !kategori || !tingkat || !poin || !ket || !penyelenggara || !sertifikat || !driveOk) {
            notify.warning('Lengkapi data yang wajib. Link bukti harus Google Drive.');
            return;
        }
        const editId = $('edit_id').value.trim();
        $('submitBtn').disabled = true;
        $('submitBtn').innerHTML = editId
            ? '<span class="spinner"></span> Mengirim ulang…'
            : '<span class="spinner"></span> Mengirim…';
        try {
            const payload = {
                method: 'submitPrestasi',
                token: user.token,
                nisn,
                tahun_akademik: tahun,
                semester,
                prestasi_kategori_id: kategori,
                prestasi_tingkat_id: tingkat,
                prestasi_poin_id: poin,
                keterangan: ket,
                penyelenggara,
                no_sertifikat: sertifikat,
                tanggal_pelaksanaan: tanggal,
                url,
            };
            if (editId) payload.id = editId;
            await callWs(payload);
            resetFormFields();
            await loadPengajuan();
            setPanel('list');
            notify.success(editId ? 'Prestasi dikirim ulang dan menunggu persetujuan.' : 'Prestasi berhasil dikirim.');
        } catch (err) {
            notify.error(err.message);
        } finally {
            $('submitBtn').disabled = false;
            $('submitBtn').textContent = $('edit_id').value ? 'Kirim ulang' : 'Kirim prestasi';
        }
    });

    function logout() {
        sessionStorage.removeItem(KEY_SESSION);
        katalog = { kategori: [], tingkat: [], poin: [] };
        pengajuan = [];
        fillKategori();
        resetFormFields();
        showLogin();
        $('loginForm').reset();
        notify.success('Anda sudah keluar.');
    }
    $('logoutBtn').addEventListener('click', logout);

    if (cachedTahun().length) fillTahun(cachedTahun());
    const existing = session();
    if (existing?.token) showForm(existing);
})();
