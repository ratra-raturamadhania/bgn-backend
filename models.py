from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

# =========================================================================
# 1. TABEL USER
# =========================================================================
class User(db.Model):
    __tablename__ = 'users' 
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    peran = db.Column(db.String(50), default='Petugas Sekolah') 
    
    nama_sekolah = db.Column(db.String(150), nullable=True, default='SDN 01 Menteng')
    npsn = db.Column(db.String(20), nullable=True, default='20101234')
    alamat_sekolah = db.Column(db.Text, nullable=True, default='Jl. Menteng Raya No. 10, Jakarta Pusat')
    foto = db.Column(db.String(255), nullable=True) 
    
    # TAMBAHAN BARU: Kolom untuk menyimpan nama file Sertifikat SLHS SPPG
    sertifikat_slhs = db.Column(db.String(255), nullable=True)
    
    otp_code = db.Column(db.String(6), nullable=True)
    otp_expired_at = db.Column(db.DateTime, nullable=True)

    laporan_pengawasan = db.relationship('LaporanPengawasan', backref='petugas', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'peran': self.peran,
            'nama_sekolah': self.nama_sekolah,
            'npsn': self.npsn,
            'alamat_sekolah': self.alamat_sekolah,
            'foto': self.foto,
            'sertifikat_slhs': self.sertifikat_slhs  # <--- Ditambahkan ke response dict
        }

# =========================================================================
# 2. TABEL DATA SEKOLAH
# =========================================================================
class Sekolah(db.Model):
    __tablename__ = 'sekolah'
    
    id = db.Column(db.Integer, primary_key=True)
    nama_sekolah = db.Column(db.String(100), nullable=False, unique=True)
    alamat = db.Column(db.String(200), nullable=False)
    jumlah_siswa = db.Column(db.Integer, nullable=False)
    
    laporan = db.relationship('LaporanPengawasan', backref='sekolah_terkait', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'nama_sekolah': self.nama_sekolah,
            'alamat': self.alamat,
            'jumlah_siswa': self.jumlah_siswa
        }

# =========================================================================
# 3. TABEL LAPORAN PENGAWASAN
# =========================================================================
class LaporanPengawasan(db.Model):
    __tablename__ = 'laporan_pengawasan'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sekolah_id = db.Column(db.Integer, db.ForeignKey('sekolah.id'), nullable=False)
    
    tanggal_laporan = db.Column(db.String(50), default=datetime.now().strftime('%Y-%m-%d'))
    porsi_diterima = db.Column(db.Integer, nullable=False)
    porsi_terdistribusi = db.Column(db.Integer, nullable=False)
    status_higienis = db.Column(db.String(50), nullable=False) 
    status_ketepatan_waktu = db.Column(db.String(50), nullable=False) 
    catatan_kondisi = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'oleh_petugas': self.petugas.username if self.petugas else "Anonim",
            'nama_sekolah': self.sekolah_terkait.nama_sekolah if self.sekolah_terkait else "Tanpa Sekolah",
            'tanggal': self.tanggal_laporan,
            'porsi': f"{self.porsi_terdistribusi}/{self.porsi_diterima} Porsi",
            'higienis': self.status_higienis,
            'waktu': self.status_ketepatan_waktu,
            'catatan': self.catatan_kondisi
        }

# =========================================================================
# 4. TABEL LAPORAN KENDALA
# =========================================================================
class Laporan(db.Model):
    __tablename__ = 'laporan'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    instansi_asal = db.Column(db.String(150), nullable=False)
    
    sppg_terduga = db.Column(db.String(255), nullable=True)
    tingkat_keparahan = db.Column(db.String(100), nullable=True)
    
    lokasi_instansi = db.Column(db.String(255), nullable=False, default='Lokasi Kosong')
    latitude = db.Column(db.Numeric(10, 8), nullable=True, default=-6.200000)
    longitude = db.Column(db.Numeric(11, 8), nullable=True, default=106.816666)
    tanggal_laporan = db.Column(db.Date, nullable=False)
    jenis_laporan = db.Column(db.String(100), nullable=False)
    deskripsi = db.Column(db.Text, nullable=False)
    foto_bukti = db.Column(db.String(255), nullable=False)
    
    status = db.Column(
        db.Enum(
            'Menunggu Validasi', 'Valid', 'Tidak Valid', 
            'Menunggu Respon', 'Selesai Ditangani', 'Selesai', 'Ditolak',
            name='status_laporan_enum'
        ), 
        default='Menunggu Validasi'
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "instansi_asal": self.instansi_asal,
            "sppg_terduga": self.sppg_terduga if self.sppg_terduga else "-",
            "tingkat_keparahan": self.tingkat_keparahan if self.tingkat_keparahan else "-",
            "lokasi_instansi": self.lokasi_instansi,
            "latitude": float(self.latitude) if self.latitude else 0.0,
            "longitude": float(self.longitude) if self.longitude else 0.0,
            "tanggal_laporan": self.tanggal_laporan.strftime('%Y-%m-%d') if self.tanggal_laporan else '-',
            "jenis_laporan": self.jenis_laporan,
            "deskripsi": self.deskripsi,
            "foto_bukti": f"/static/uploads/bukti_laporan/{self.foto_bukti}",
            "status": self.status.value if hasattr(self.status, 'value') else str(self.status),
            "created_at": self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else '-'
        }