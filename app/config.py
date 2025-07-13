import os
from datetime import timedelta
from dotenv import load_dotenv

# ✅ Load environment variables from .env
load_dotenv()

# ✅ Ensure required environment variables exist
required_vars = [
    'SECRET_KEY',
    'DATABASE_URL',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_BUCKET_NAME',
    'RSA_PRIVATE_KEY',
    'RSA_PUBLIC_KEY',
    'MAIL_USERNAME',
    'MAIL_PASSWORD',
]

for var in required_vars:
    if not os.environ.get(var):
        raise EnvironmentError(f"❌ Missing required environment variable: '{var}'")

if 'AWS_REGION' not in os.environ:
    print("⚠️  AWS_REGION not set. Defaulting to 'us-east-1'")


class Config:
    # ================================
    # 🔐 Flask Core & Session Settings
    # ================================
    SECRET_KEY = os.environ['SECRET_KEY']
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=10)
    SESSION_PERMANENT = True
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

    # ================================
    # 🗄️ Database
    # ================================
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ================================
    # 🔒 OTP & Lockout Config
    # ================================
    OTP_ISSUER_NAME = "Digital Time Capsule"
    MAX_OTP_ATTEMPTS = 3
    OTP_LOCKOUT_TIME = int(os.getenv("OTP_LOCKOUT_TIME", 3600))     # in seconds
    OTP_VALID_WINDOW = int(os.getenv("OTP_VALID_WINDOW", 1))        # ±30s per window

    # ================================
    # 🔑 RSA Keys
    # ================================
    RSA_PRIVATE_KEY = os.environ['RSA_PRIVATE_KEY'].replace('\\n', '\n')
    RSA_PUBLIC_KEY = os.environ['RSA_PUBLIC_KEY'].replace('\\n', '\n')

    # ================================
    # 📬 Email (SMTP)
    # ================================
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ['MAIL_USERNAME']
    MAIL_PASSWORD = os.environ['MAIL_PASSWORD']
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@digitaltimecapsule.com')

    # ================================
    # ☁️ AWS S3
    # ================================
    AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
    AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
    AWS_BUCKET_NAME = os.environ['AWS_BUCKET_NAME']
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

    # ================================
    # 📁 App Storage
    # ================================
    TEMP_FOLDER = 'app/temp'

    # ================================
    # 📦 File Upload: Extensions
    # ================================
    ALLOWED_EXTENSIONS = {
        # Text and Documents
        'txt', 'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx',
        'csv', 'json', 'xml', 'md', 'rtf', 'odt', 'ods', 'odp',

        # Images
        'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp', 'tiff',
        'ico', 'heic', 'psd', 'raw', 'ai',

        # Videos
        'mp4', 'mov', 'avi', 'mkv', 'flv', 'wmv', 'webm', 'm4v',

        # Audio
        'mp3', 'wav', 'flac', 'aac', 'ogg', 'wma', 'm4a', 'aiff',

        # Archives
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso',

        # Code / Programming
        'py', 'java', 'cpp', 'c', 'cs', 'go', 'js', 'ts', 'html',
        'css', 'scss', 'php', 'rb', 'sh', 'bat', 'swift', 'kt',
        'rs', 'sql', 'pl', 'jsonc', 'yaml', 'yml',

        # Executables
        'exe', 'msi', 'apk', 'deb', 'rpm', 'bin', 'dmg', 'jar',
        'app', 'com', 'cmd',

        # Data / DB
        'db', 'sqlite', 'db3', 'accdb', 'mdb', 'bak', 'sql',
        'parquet', 'hdf5', 'pkl', 'sav',

        # Design / 3D
        'psd', 'xd', 'fig', 'sketch', 'blend', 'fbx', 'obj',
        'stl', 'dwg', 'dxf',

        # Containers
        'vdi', 'vmdk', 'vhd', 'ova', 'ovf', 'dockerfile',

        # Other
        'log', 'cfg', 'ini', 'tmp', 'crt', 'pem', 'cer',
        'pub', 'key'
    }


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key'
    TEMP_FOLDER = 'app/static/test_temp'
