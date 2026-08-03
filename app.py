import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from uuid import uuid4
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Models
from models import db, User, Sekolah, LaporanPengawasan, Laporan

app = Flask(__name__)
CORS(app)

# =========================================================================
# KONEKSI DATABASE & CONFIG UPLOAD (MENGGUNAKAN SQLITE UNTUK PYTHONANYWHERE FREE)
# =========================================================================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bgn_mbg.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads/bukti_laporan'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'permenchoco58@gmail.com'
app.config['MAIL_PASSWORD'] = 'jkbaadwvmviaawjo'
app.config['MAIL_DEFAULT_SENDER'] = 'permenchoco58@gmail.com'

mail = Mail(app)

# Inisialisasi DB murni dari models.py
db.init_app(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================================================================
# ROUTING TABLE UNTUK KENDALA SPPG
# =========================================================================
ROUTING_TABLE = {
    'Masalah Pasokan Baku / Higienitas Dapur': {
        'dinas': 'Dinas Kesehatan',
        'ranah': 'Penanganan kualitas bahan makanan, sampel uji higienitas, riset medis/keracunan.'
    },
    'Kendala Distribusi (Kendaraan Kecelakaan/Mogok)': {
        'dinas': 'Dinas Pendidikan',
        'ranah': 'Koordinasi keterlambatan pengiriman porsi ke sekolah-sekolah penerima.'
    },
    'Kebakaran / Kebocoran Gas (Darurat Bencana Dapur)': {
        'dinas': 'Dinas Lingkungan Hidup',
        'ranah': 'Penanganan insiden lingkungan, keamanan fasilitas, sanitasi & limbah B3.'
    },
    'Kerusakan Fasilitas / Alat Utama (Genset/Kompor)': {
        'dinas': 'Petugas / Tim Teknis SPPG',
        'ranah': 'Perbaikan fasilitas fisik & koordinasi teknis kompor/genset di lapangan.'
    }
}


# =========================================================================
# ENDPOINTS API AUTHENTICATION & MANAJEMEN PASSWORD
# =========================================================================

@app.route('/')
def home():
    return "Server Backend BGN-MBG Berjalan dengan Lancar di PythonAnywhere!"

@app.route('/api/auth/register', methods=['POST'])
def register_akun():
    try:
        data = request.get_json(silent=True) or {}
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'Petugas Sekolah')

        if not username or not email or not password:
            return jsonify({"status": "error", "message": "Semua data form pendaftaran wajib diisi!"}), 400

        user_email_exist = User.query.filter_by(email=email).first()
        if user_email_exist:
            return jsonify({"status": "error", "message": "Email sudah terdaftar, gunakan email lain!"}), 400

        user_name_exist = User.query.filter_by(username=username).first()
        if user_name_exist:
            return jsonify({"status": "error", "message": "Username sudah digunakan!"}), 400

        hashed_password = generate_password_hash(password)

        user_baru = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            peran=role
        )

        db.session.add(user_baru)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Akun berhasil didaftarkan ke sistem SQLite!"
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500


@app.route('/api/auth/login', methods=['POST'])
def login_petugas():
    try:
        data = request.get_json(silent=True) or {}
        email_atau_username = data.get('email')
        password_input = data.get('password')
        role_input = data.get('role')

        if not email_atau_username or not password_input:
            return jsonify({"status": "error", "message": "Email dan Password wajib diisi!"}), 400

        user = User.query.filter_by(email=email_atau_username, peran=role_input).first()
        if not user:
            user = User.query.filter_by(username=email_atau_username, peran=role_input).first()
        
        if not user:
            return jsonify({
                "status": "error", 
                "message": f"Akun tidak ditemukan atau tidak terdaftar sebagai {role_input}!"
            }), 404

        pwd_hash = user.password_hash
        if pwd_hash.startswith('pbkdf2:sha256') or pwd_hash.startswith('scrypt'):
            is_valid = check_password_hash(pwd_hash, password_input)
        else:
            is_valid = (pwd_hash == password_input)

        if not is_valid:
            return jsonify({"status": "error", "message": "Password yang Anda masukkan salah!"}), 401

        return jsonify({
            "status": "success",
            "message": "Login Berhasil!",
            "data": {
                "id": user.id,
                "user_id": user.id,
                "email": user.email,
                "role": user.peran
            }
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500


@app.route('/api/auth/update-password', methods=['POST'])
def update_password_dalam_aplikasi():
    try:
        data = request.get_json() or {}
        email_atau_username = data.get('email')
        password_lama = data.get('password_lama')
        password_baru = data.get('password_baru')

        if not email_atau_username or not password_lama or not password_baru:
            return jsonify({"status": "error", "message": "Semua field data wajib diisi!"}), 400

        user = User.query.filter((User.email == email_atau_username) | (User.username == email_atau_username)).first()
        
        if not user:
            return jsonify({"status": "error", "message": "Pengguna tidak ditemukan di sistem!"}), 404

        pwd_hash = user.password_hash
        if pwd_hash.startswith('pbkdf2:sha256') or pwd_hash.startswith('scrypt'):
            is_valid = check_password_hash(pwd_hash, password_lama)
        else:
            is_valid = (pwd_hash == password_lama)

        if not is_valid:
            return jsonify({"status": "error", "message": "Password lama yang Anda masukkan salah!"}), 401

        user.password_hash = generate_password_hash(password_baru)
        db.session.commit()

        return jsonify({"status": "success", "message": "Password akun berhasil diperbarui!"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500


# =========================================================================
# ENDPOINTS API LAPORAN KENDALA (PETUGAS LAPANGAN & DINAS PASANGAN)
# =========================================================================

@app.route('/api/petugas/laporan', methods=['POST'])
def kirim_laporan():
    try:
        user_id = request.form.get('user_id', '1')
        instansi_asal = request.form.get('instansi_asal', request.form.get('nama_puskesmas', 'Instansi Tanpa Nama')) 
        lokasi_instansi = request.form.get('lokasi_instansi', request.form.get('alamat_lokasi', 'Lokasi Kosong'))    
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        tanggal_str = request.form.get('tanggal_laporan')
        jenis_laporan = request.form.get('jenis_laporan', request.form.get('jenis_masalah', 'Laporan Umum'))
        deskripsi = request.form.get('deskripsi', '-')
        
        sppg_terduga = request.form.get('sppg_terduga', request.form.get('nama_sppg', None))
        tingkat_keparahan = request.form.get('tingkat_keparahan', request.form.get('level_keracunan', None))
        
        unique_filename = "default_bukti.jpg"
        
        if 'foto_bukti' in request.files:
            file = request.files['foto_bukti']
            if file and file.filename != '':
                ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
                unique_filename = f"{uuid4().hex}.{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)

        if tanggal_str and '-' in tanggal_str:
            try:
                tanggal_obj = datetime.strptime(tanggal_str, '%Y-%m-%d').date()
            except ValueError:
                tanggal_obj = datetime.now().date()
        else:
            tanggal_obj = datetime.now().date()

        try:
            lat_val = float(latitude) if latitude else -6.200000
            lng_val = float(longitude) if longitude else 106.816666
        except ValueError:
            lat_val, lng_val = -6.200000, 106.816666

        baru_laporan = Laporan(
            user_id=int(user_id) if str(user_id).isdigit() else 1,
            instansi_asal=instansi_asal,      
            lokasi_instansi=lokasi_instansi,  
            latitude=lat_val,
            longitude=lng_val,
            tanggal_laporan=tanggal_obj,
            jenis_laporan=jenis_laporan,
            deskripsi=deskripsi,
            foto_bukti=unique_filename,
            status='Menunggu Validasi',
            sppg_terduga=sppg_terduga,
            tingkat_keparahan=tingkat_keparahan
        )
        
        db.session.add(baru_laporan)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": "Laporan berhasil disimpan!",
            "data": baru_laporan.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Gagal menyimpan ke DB: {str(e)}"}), 500


@app.route('/api/petugas/riwayat/<int:user_id>', methods=['GET'])
def ambil_riwayat(user_id):
    try:
        if not user_id or user_id == 0:
            return jsonify({"status": "error", "message": "ID Pengguna tidak valid!"}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User tidak ditemukan di database"}), 404
            
        role_lower = user.peran.lower() if user.peran else ''
        
        if 'dinas kesehatan' in role_lower or 'dinkes' in role_lower:
            laporan_list = Laporan.query.join(User, Laporan.user_id == User.id, isouter=True).filter(
                (User.peran.ilike('%puskesmas%')) | 
                (Laporan.jenis_laporan.ilike('%Pasokan%')) | 
                (Laporan.jenis_laporan.ilike('%Higienitas%'))
            ).order_by(Laporan.tanggal_laporan.desc()).all()

        elif 'dinas pendidikan' in role_lower or 'disdik' in role_lower:
            laporan_list = Laporan.query.join(User, Laporan.user_id == User.id, isouter=True).filter(
                (User.peran.ilike('%sekolah%')) | 
                (Laporan.jenis_laporan.ilike('%Distribusi%'))
            ).order_by(Laporan.tanggal_laporan.desc()).all()

        elif 'dinas lingkungan hidup' in role_lower or 'dlh' in role_lower:
            laporan_list = Laporan.query.join(User, Laporan.user_id == User.id, isouter=True).filter(
                (User.peran.ilike('%limbah%')) | 
                (Laporan.jenis_laporan.ilike('%Kebakaran%')) | 
                (Laporan.jenis_laporan.ilike('%Gas%'))
            ).order_by(Laporan.tanggal_laporan.desc()).all()

        elif role_lower in ['bgn', 'mbg', 'admin']:
            laporan_list = Laporan.query.order_by(Laporan.tanggal_laporan.desc()).all()

        else:
            laporan_list = Laporan.query.filter_by(user_id=user_id).order_by(Laporan.tanggal_laporan.desc()).all()

        return jsonify({
            "status": "success",
            "data": [l.to_dict() for l in laporan_list]
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500


@app.route('/api/petugas/ringkasan/<int:user_id>', methods=['GET'])
def ambil_ringkasan(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User tidak ditemukan"}), 404

        role_lower = user.peran.lower() if user.peran else ''

        if 'dinas lingkungan hidup' in role_lower or 'dlh' in role_lower:
            base_query = Laporan.query.join(User, Laporan.user_id == User.id, isouter=True).filter(
                (User.peran.ilike('%limbah%')) | (Laporan.jenis_laporan.ilike('%Kebakaran%')) | (Laporan.jenis_laporan.ilike('%Gas%'))
            )
        elif 'dinas pendidikan' in role_lower or 'disdik' in role_lower:
            base_query = Laporan.query.join(User, Laporan.user_id == User.id, isouter=True).filter(
                (User.peran.ilike('%sekolah%')) | (Laporan.jenis_laporan.ilike('%Distribusi%'))
            )
        elif 'dinas kesehatan' in role_lower or 'dinkes' in role_lower:
            base_query = Laporan.query.join(User, Laporan.user_id == User.id, isouter=True).filter(
                (User.peran.ilike('%puskesmas%')) | (Laporan.jenis_laporan.ilike('%Pasokan%')) | (Laporan.jenis_laporan.ilike('%Higienitas%'))
            )
        elif role_lower in ['bgn', 'mbg', 'admin']:
            base_query = Laporan.query
        else:
            base_query = Laporan.query.filter(Laporan.user_id == user_id)

        total = base_query.count()
        menunggu = base_query.filter((Laporan.status == 'Menunggu Validasi') | (Laporan.status == 'Menunggu') | (Laporan.status == 'Menunggu Respon')).count()
        selesai = base_query.filter((Laporan.status == 'Valid') | (Laporan.status == 'Selesai') | (Laporan.status == 'Selesai Ditangani')).count()
        tidak_valid = base_query.filter((Laporan.status == 'Tidak Valid') | (Laporan.status == 'Ditolak')).count()
        
        return jsonify({
            "status": "success",
            "ringkasan": {
                "total_laporan": total,
                "menunggu": menunggu,
                "valid": selesai,
                "tidak_valid": tidak_valid
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# =========================================================================
# ENDPOINTS KHUSUS ROLE SPPG (INPUT FORM KENDALA DAPUR & DASHBOARD)
# =========================================================================

@app.route('/api/sppg/laporan', methods=['POST'])
def kirim_laporan_sppg():
    try:
        user_id_raw = request.form.get('user_id', '1')
        pelapor = request.form.get('pelapor', 'SPPG Dapur')
        jenis_kendala = request.form.get('jenis_kendala', 'Kendala Dapur SPPG')
        tingkat_urgensi = request.form.get('tingkat_urgensi', 'Sedang')
        dampak_distribusi = request.form.get('dampak_distribusi', 'Pengiriman Terlambat')
        tanggal_kejadian = request.form.get('tanggal_kejadian', str(datetime.now().date()))
        deskripsi = request.form.get('deskripsi', '-')

        try:
            user_id = int(user_id_raw)
        except (ValueError, TypeError):
            user_id = 1

        pemetaan = ROUTING_TABLE.get(jenis_kendala, {
            'dinas': 'BGN Pusat',
            'ranah': 'Penanganan umum internal SPPG'
        })
        dinas_tujuan = pemetaan['dinas']
        ranah_tujuan = pemetaan['ranah']

        unique_filename = "default_bukti.jpg"
        if 'foto_bukti' in request.files:
            file = request.files['foto_bukti']
            if file and file.filename != '':
                ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
                unique_filename = f"{uuid4().hex}.{ext}"
                
                target_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
                if not os.path.exists(target_dir):
                    os.makedirs(target_dir, exist_ok=True)
                    
                file_path = os.path.join(target_dir, unique_filename)
                file.save(file_path)

        if '-' in str(tanggal_kejadian):
            try:
                tanggal_obj = datetime.strptime(str(tanggal_kejadian), '%Y-%m-%d').date()
            except ValueError:
                tanggal_obj = datetime.now().date()
        else:
            tanggal_obj = datetime.now().date()

        deskripsi_lengkap = (
            f"[{dampak_distribusi}] {deskripsi}\n\n"
            f"📍 Penanggung Jawab: {dinas_tujuan}\n"
            f"ℹ️ Ranah: {ranah_tujuan}"
        )

        baru_laporan = Laporan(
            user_id=user_id,
            instansi_asal=pelapor,
            lokasi_instansi="Dapur SPPG",
            latitude=-6.200000,
            longitude=106.816666,
            tanggal_laporan=tanggal_obj,
            jenis_laporan=jenis_kendala,
            deskripsi=deskripsi_lengkap,
            foto_bukti=unique_filename,
            status='Menunggu Validasi',
            sppg_terduga=pelapor,
            tingkat_keparahan=tingkat_urgensi
        )

        db.session.add(baru_laporan)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": f"Laporan Kendala SPPG Berhasil Dikirim ke {dinas_tujuan}!",
            "data": baru_laporan.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server Error SPPG: {str(e)}"}), 500


@app.route('/api/sppg/laporan-terbaru/<int:user_id>', methods=['GET'])
def get_laporan_terbaru_sppg(user_id):
    try:
        laporan_terbaru = Laporan.query.filter_by(user_id=user_id).order_by(Laporan.tanggal_laporan.desc()).limit(3).all()
        return jsonify({
            "status": "success",
            "data": [l.to_dict() for l in laporan_terbaru]
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Server Error SPPG Terbaru: {str(e)}"}), 500


@app.route('/api/sppg/ringkasan/<int:user_id>', methods=['GET'])
def get_ringkasan_sppg(user_id):
    try:
        total = Laporan.query.filter_by(user_id=user_id).count()
        menunggu = Laporan.query.filter_by(user_id=user_id).filter(
            (Laporan.status == 'Menunggu Respon') | (Laporan.status == 'Menunggu Validasi')
        ).count()
        selesai = Laporan.query.filter_by(user_id=user_id).filter(
            (Laporan.status == 'Selesai Ditangani') | (Laporan.status == 'Valid') | (Laporan.status == 'Selesai')
        ).count()
        
        return jsonify({
            "status": "success",
            "ringkasan": {
                "total_laporan": total,
                "menunggu_respon": menunggu,
                "selesai_ditangani": selesai
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# =========================================================================
# ENDPOINTS DINAS VALIDATOR & BGN MONITORING PUSAT
# =========================================================================

@app.route('/api/dinas/validasi/<int:laporan_id>', methods=['PUT'])
def validasi_laporan(laporan_id):
    try:
        data = request.get_json() or {}
        status_baru = data.get('status')
        
        laporan = Laporan.query.get(laporan_id)
        if not laporan:
            return jsonify({"status": "error", "message": "Data laporan tidak ditemukan!"}), 404
            
        laporan.status = status_baru
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": f"Laporan berhasil diperbarui menjadi: {status_baru}",
            "data": laporan.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500


@app.route('/api/bgn/ringkasan', methods=['GET'])
def get_ringkasan_bgn():
    try:
        total = Laporan.query.count()
        menunggu = Laporan.query.filter((Laporan.status == 'Menunggu Validasi') | (Laporan.status == 'Menunggu') | (Laporan.status == 'Menunggu Respon')).count()
        valid = Laporan.query.filter((Laporan.status == 'Valid') | (Laporan.status == 'Selesai') | (Laporan.status == 'Selesai Ditangani')).count()
        tidak_valid = Laporan.query.filter((Laporan.status == 'Tidak Valid') | (Laporan.status == 'Ditolak')).count()
        
        return jsonify({
            "status": "success",
            "ringkasan": {
                "total_laporan": total,
                "menunggu": menunggu,
                "valid": valid,
                "tidak_valid": tidak_valid
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/bgn/semua_laporan', methods=['GET'])
def get_semua_laporan_bgn():
    try:
        laporan_list = Laporan.query.order_by(Laporan.tanggal_laporan.desc()).all()
        return jsonify({
            "status": "success",
            "total_data": len(laporan_list),
            "data": [l.to_dict() for l in laporan_list]
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/dinas/laporan-terbaru/<int:user_id>', methods=['GET'])
def get_laporan_terbaru_dinas(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User Dinas tidak ditemukan!"}), 404

        role_lower = user.peran.lower() if user.peran else ''

        if 'dinas lingkungan hidup' in role_lower or 'dlh' in role_lower:
            query_filter = (User.peran.ilike('%limbah%')) | (Laporan.jenis_laporan.ilike('%Kebakaran%')) | (Laporan.jenis_laporan.ilike('%Gas%'))
        elif 'dinas pendidikan' in role_lower or 'disdik' in role_lower:
            query_filter = (User.peran.ilike('%sekolah%')) | (Laporan.jenis_laporan.ilike('%Distribusi%'))
        elif 'dinas kesehatan' in role_lower or 'dinkes' in role_lower:
            query_filter = (User.peran.ilike('%puskesmas%')) | (Laporan.jenis_laporan.ilike('%Pasokan%')) | (Laporan.jenis_laporan.ilike('%Higienitas%'))
        else:
            query_filter = (Laporan.user_id == user_id)

        laporan_terbaru = Laporan.query.join(User, Laporan.user_id == User.id, isouter=True)\
            .filter(query_filter)\
            .order_by(Laporan.tanggal_laporan.desc())\
            .limit(5).all()

        return jsonify({
            "status": "success",
            "data": [l.to_dict() for l in laporan_terbaru]
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": f"Server Error Dinas Terbaru: {str(e)}"}), 500


# =========================================================================
# ENDPOINTS EDIT PROFIL PETUGAS & USER MANAGEMENT
# =========================================================================

@app.route('/api/petugas/profil/<int:user_id>', methods=['GET'])
def ambil_profil_petugas(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User tidak ditemukan!"}), 404
        
        return jsonify({
            "status": "success",
            "data": {
                "nama_petugas": user.username or "Petugas Lapangan",
                "email": user.email,
                "nama_sekolah": getattr(user, 'instansi_asal', getattr(user, 'nama_sekolah', "Instansi Unit Kerja")),
                "npsn": getattr(user, 'npsn', "12345678"),
                "alamat_sekolah": getattr(user, 'lokasi_instansi', getattr(user, 'alamat_sekolah', "Alamat Kantor Operasional"))
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/petugas/update/<int:user_id>', methods=['PUT'])
def update_profil_petugas(user_id):
    try:
        data = request.get_json() or {}
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User tidak ditemukan!"}), 404
        
        if 'nama_petugas' in data: user.username = data['nama_petugas']
        if 'email' in data: user.email = data['email']
        
        if 'nama_sekolah' in data:
            if hasattr(user, 'instansi_asal'):
                user.instansi_asal = data['nama_sekolah']
            elif hasattr(user, 'nama_sekolah'):
                user.nama_sekolah = data['nama_sekolah']
                
        if 'npsn' in data and hasattr(user, 'npsn'): 
            user.npsn = data['npsn']
            
        if 'alamat_sekolah' in data:
            if hasattr(user, 'lokasi_instansi'):
                user.lokasi_instansi = data['alamat_sekolah']
            elif hasattr(user, 'alamat_sekolah'):
                user.alamat_sekolah = data['alamat_sekolah']
            
        db.session.commit()
        return jsonify({"status": "success", "message": "Profil berhasil diperbarui!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/users/profile/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"status": "error", "message": "User tidak ditemukan"}), 404
    
    return jsonify({
        "status": "success",
        "user": {
            "nama": user.username,
            "email": getattr(user, 'email', ''),
            "instansi": getattr(user, 'instansi', ''),
            "kode_instansi": getattr(user, 'kode_instansi', ''),
            "alamat": getattr(user, 'alamat', '')
        }
    }), 200


@app.route('/api/users/change-password/<int:user_id>', methods=['PUT'])
def change_password(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User tidak ditemukan"}), 404
        
        data = request.get_json() or {}
        password_lama = data.get('password_lama')
        password_baru = data.get('password_baru')
        
        if not password_lama or not password_baru:
            return jsonify({"status": "error", "message": "Password lama dan baru wajib diisi!"}), 400

        pwd_di_db = user.password_hash

        is_valid = False
        if pwd_di_db.startswith('scrypt:') or pwd_di_db.startswith('pbkdf2:'):
            is_valid = check_password_hash(pwd_di_db, password_lama)
        else:
            is_valid = (pwd_di_db == password_lama)

        if not is_valid:
            return jsonify({"status": "error", "message": "Password lama yang Anda masukkan salah!"}), 400
        
        user.password_hash = generate_password_hash(password_baru)
        db.session.commit()
        
        return jsonify({"status": "success", "message": "Password berhasil diganti!"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


# =========================================================================
# ENDPOINTS UNTUK SERTIFIKAT SLHS (SPPG)
# =========================================================================

@app.route('/api/users/upload-slhs/<int:user_id>', methods=['POST'])
def upload_slhs(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User tidak ditemukan!"}), 404

        if 'file_slhs' not in request.files:
            return jsonify({"status": "error", "message": "Tidak ada file yang diunggah!"}), 400

        file = request.files['file_slhs']
        if file.filename == '':
            return jsonify({"status": "error", "message": "Nama file kosong!"}), 400

        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
            unique_filename = f"slhs_{user_id}_{uuid4().hex[:8]}.{ext}"
            
            target_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
            if not os.path.exists(target_dir):
                os.makedirs(target_dir, exist_ok=True)

            file_path = os.path.join(target_dir, unique_filename)
            file.save(file_path)

            if hasattr(user, 'sertifikat_slhs'):
                user.sertifikat_slhs = unique_filename
            else:
                setattr(user, 'sertifikat_slhs', unique_filename)

            db.session.commit()

            return jsonify({
                "status": "success",
                "message": "Sertifikat SLHS berhasil diunggah!",
                "file_url": f"/static/uploads/bukti_laporan/{unique_filename}",
                "file_name": unique_filename
            }), 200
        else:
            return jsonify({"status": "error", "message": "Format file tidak didukung! (Gunakan PDF, JPG, PNG)"}), 400

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server Error Upload SLHS: {str(e)}"}), 500


@app.route('/api/users/get-slhs/<int:user_id>', methods=['GET'])
def get_slhs(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User tidak ditemukan!"}), 404

        filename = getattr(user, 'sertifikat_slhs', None)
        if filename:
            file_url = f"https://ratra.pythonanywhere.com/static/uploads/bukti_laporan/{filename}"
            return jsonify({
                "status": "success",
                "is_uploaded": True,
                "file_url": file_url,
                "file_name": filename
            }), 200
        else:
            return jsonify({
                "status": "success",
                "is_uploaded": False,
                "file_url": None
            }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
