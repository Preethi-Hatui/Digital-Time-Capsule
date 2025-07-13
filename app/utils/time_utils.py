# app/utils/time_utils.py

from datetime import datetime, timedelta


def format_datetime(value: datetime, format: str = 'medium') -> str:
    """
    Format a datetime object into a human-readable string.

    Args:
        value (datetime): The datetime object to format.
        format (str): Format style ('full', 'medium', 'date', 'time').

    Returns:
        str: Formatted datetime string or original input string if invalid.
    """
    if not isinstance(value, datetime):
        return str(value)  # Gracefully fallback if not a datetime

    format_map = {
        'full': "%Y-%m-%d %H:%M:%S",
        'medium': "%Y-%m-%d %H:%M",
        'date': "%Y-%m-%d",
        'time': "%H:%M:%S"
    }

    format_str = format_map.get(format.lower(), format_map['medium'])
    return value.strftime(format_str)


def time_ago(value: datetime) -> str:
    """
    Returns a human-friendly relative time string (e.g., '2 days ago').

    Args:
        value (datetime): Past datetime value.

    Returns:
        str: Relative time description.
    """
    if not isinstance(value, datetime):
        return str(value)

    now = datetime.utcnow()
    diff = now - value

    if diff.total_seconds() < 0:
        return "in the future"

    seconds = int(diff.total_seconds())
    minutes = seconds // 60
    hours = minutes // 60
    days = diff.days
    weeks = days // 7
    months = days // 30
    years = days // 365

    if years > 0:
        return f"{years} year{'s' if years != 1 else ''} ago"
    elif months > 0:
        return f"{months} month{'s' if months != 1 else ''} ago"
    elif weeks > 0:
        return f"{weeks} week{'s' if weeks != 1 else ''} ago"
    elif days > 0:
        return f"{days} day{'s' if days != 1 else ''} ago"
    elif hours > 0:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif minutes > 0:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    return "just now"
