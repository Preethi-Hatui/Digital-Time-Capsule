import logging
from logging.config import fileConfig
from flask import current_app
from alembic import context

# Load Alembic config
config = context.config

# Set up Python logging from Alembic .ini file
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

# ==============================
# Engine Access for Flask-SQLAlchemy
# ==============================
def get_engine():
    try:
        # Flask-SQLAlchemy < 3
        return current_app.extensions['migrate'].db.get_engine()
    except TypeError:
        # Flask-SQLAlchemy ≥ 3
        return current_app.extensions['migrate'].db.engine
    except Exception as e:
        logger.error(f"❌ Failed to get DB engine: {e}")
        raise

def get_engine_url():
    try:
        return get_engine().url.render_as_string(hide_password=False).replace('%', '%%')
    except Exception:
        return str(get_engine().url).replace('%', '%%')

# Set the sqlalchemy.url config option for Alembic
config.set_main_option('sqlalchemy.url', get_engine_url())

# ==============================
# Metadata Setup
# ==============================
target_db = current_app.extensions['migrate'].db

def get_metadata():
    if hasattr(target_db, 'metadatas'):
        return target_db.metadatas[None]
    return target_db.metadata

# ==============================
# Migration Routines
# ==============================
def run_migrations_offline():
    """Run migrations in offline mode (no DB connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=get_metadata(),
        literal_binds=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """Run migrations in online mode (DB connected)."""

    def process_revision_directives(context, revision, directives):
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info("✅ No schema changes detected.")

    connectable = get_engine()

    with connectable.connect() as connection:
        # FIXED: Avoid duplicate `compare_type` argument
        configure_args = current_app.extensions['migrate'].configure_args.copy()
        configure_args.update(
            connection=connection,
            target_metadata=get_metadata(),
            compare_type=True,
            process_revision_directives=process_revision_directives,
        )

        context.configure(**configure_args)

        with context.begin_transaction():
            context.run_migrations()

# ==============================
# Execute
# ==============================
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
