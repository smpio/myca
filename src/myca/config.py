import os

app_root = os.path.dirname(os.path.dirname(__file__))

secret_key = os.environ.get('SECRET_KEY', '-')
database_uri = os.environ.get('DATABASE_URI', 'postgres://postgres@postgres/postgres')
reverse_proxy_count = int(os.environ.get('REVERSE_PROXY_COUNT', 0))
plugins_dir = os.environ.get('PLUGINS_DIR')
