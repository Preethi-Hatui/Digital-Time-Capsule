# app/utils/validators.py

import re
from datetime import datetime
from typing import Tuple, Union
from werkzeug.datastructures import FileStorage


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validates an email address using regex.

    Args:
        email (str): Email address to validate.

    Returns:
        tuple: (is_valid, message)
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email or not re.fullmatch(pattern, email):
        return False, "Invalid email format"
    return True, "Email is valid"


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validates a password for minimum complexity.

    Args:
        password (str): The password to validate.

    Returns:
        tuple: (is_valid, message)
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"


def validate_unlock_time(unlock_time_str: str) -> Tuple[bool, Union[str, datetime]]:
    """
    Validates and parses a future unlock datetime string.

    Args:
        unlock_time_str (str): Expected in '%Y-%m-%d %H:%M' format.

    Returns:
        tuple: (is_valid, parsed_datetime_or_error_message)
    """
    try:
        unlock_time = datetime.strptime(unlock_time_str, '%Y-%m-%d %H:%M')
        if unlock_time <= datetime.utcnow():
            return False, "Unlock time must be in the future"
        return True, unlock_time
    except ValueError:
        return False, "Invalid date/time format. Expected: YYYY-MM-DD HH:MM"


def validate_file(file: FileStorage) -> Tuple[bool, str]:
    """
    Validates uploaded file: presence, size, extension.

    Args:
        file (werkzeug.datastructures.FileStorage): Uploaded file.

    Returns:
        tuple: (is_valid, message)
    """
    if not file or not file.filename:
        return False, "No file selected"

    max_size = 50 * 1024 * 1024  # 50 MB
    if hasattr(file, 'content_length') and file.content_length:
        if file.content_length > max_size:
            return False, "File size exceeds 50MB limit"

    allowed_extensions = {
        # Text, Documents
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

        # Programming
        'py', 'java', 'cpp', 'c', 'cs', 'go', 'js', 'ts', 'html',
        'css', 'scss', 'php', 'rb', 'sh', 'bat', 'swift', 'kt',
        'rs', 'sql', 'pl', 'jsonc', 'yaml', 'yml',

        # Executables
        'exe', 'msi', 'apk', 'deb', 'rpm', 'bin', 'dmg', 'jar',
        'app', 'com', 'cmd',

        # Databases
        'db', 'sqlite', 'db3', 'accdb', 'mdb', 'bak',
        'parquet', 'hdf5', 'pkl', 'sav',

        # Design & 3D
        'xd', 'fig', 'sketch', 'blend', 'fbx', 'obj',
        'stl', 'dwg', 'dxf',

        # Virtualization
        'vdi', 'vmdk', 'vhd', 'ova', 'ovf', 'dockerfile',

        # Others
        'log', 'cfg', 'ini', 'tmp', 'crt', 'pem', 'cer',
        'pub', 'key'
    }

    if '.' not in file.filename:
        return False, "Invalid file extension"

    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in allowed_extensions:
        return False, f"File type .{ext} is not supported"

    return True, "File is valid"
