# migrations/env.py
"""
Alembic environment script
--------------------------
Nhiệm vụ file này:
1) Xác định metadata của ORM (SQLModel.metadata) để Alembic biết so sánh Model <-> DB.
2) Đọc DATABASE_URL (và SSL CA nếu cần) để kết nối tới DB.
3) Chạy migration ở 2 chế độ:
   - Offline: xuất SQL (không mở kết nối DB)
   - Online : kết nối DB và apply migration
4) Bật so sánh kiểu cột / DEFAULT để autogenerate chính xác.
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlmodel import SQLModel

# -------------------------------------------------------------------
# 0) Nạp cấu hình alembic.ini (để Alembic biết logger / config mặc định)
# -------------------------------------------------------------------
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# -------------------------------------------------------------------
# 1) Đảm bảo có thể import module dự án để metadata chứa đầy đủ bảng
#    - Thêm project root vào sys.path
#    - Import "app" (hoặc models) để register các model với SQLModel.metadata
#    Lưu ý: nếu import app.py có side-effect, cân nhắc tách models vào models.py
# -------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Thử import app hoặc models để các class (License, Device, ...) được load
try:
    import app  # noqa: F401  # nếu models ở app.py, import app là đủ
except Exception as e:
    print("[alembic/env.py] Warning: cannot import app to load models:", e)

# -------------------------------------------------------------------
# 2) Chỉ ra metadata để Alembic autogenerate dựa vào đó
#    Với SQLModel, metadata nằm ở SQLModel.metadata
# -------------------------------------------------------------------
target_metadata = SQLModel.metadata

# -------------------------------------------------------------------
# 3) Hàm lấy DATABASE_URL
#    - Ưu tiên đọc từ biến môi trường DATABASE_URL
#    - Nếu không có thì rơi về sqlalchemy.url trong alembic.ini
# -------------------------------------------------------------------
def get_url() -> str:
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    return config.get_main_option("sqlalchemy.url")

# -------------------------------------------------------------------
# 4) Kết nối thêm cho MySQL/Aiven (SSL CA)
#    - Nếu bạn dùng Aiven MySQL, đặt env MYSQL_CA = đường dẫn tới ca.pem
#    - SQLite không cần connect_args
# -------------------------------------------------------------------
def get_connect_args(url: str):
    ca = os.getenv("MYSQL_CA")  # ví dụ: C:\certs\aiven-ca.pem hoặc /etc/ssl/aiven/ca.pem
    if url and url.startswith(("mysql+pymysql://", "mysql+aiomysql://")) and ca:
        return {"ssl": {"ca": ca}}
    return {}

# -------------------------------------------------------------------
# 5) Tùy chọn loại trừ đối tượng khi autogenerate
#    - Ở đây bỏ qua bảng alembic_version
# -------------------------------------------------------------------
def include_object(obj, name, type_, reflected, compare_to):
    if type_ == "table" and name == "alembic_version":
        return False
    return True

# -------------------------------------------------------------------
# 6) OFFLINE mode: xuất SQL, không mở kết nối DB
# -------------------------------------------------------------------
def run_migrations_offline():
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,               # render giá trị literal vào SQL
        compare_type=True,                # so sánh thay đổi kiểu cột
        compare_server_default=True,      # so sánh DEFAULT trên server
        include_object=include_object,
        render_as_batch=url.startswith("sqlite"),  # giúp ALTER phức tạp trên SQLite
    )
    with context.begin_transaction():
        context.run_migrations()

# -------------------------------------------------------------------
# 7) ONLINE mode: mở kết nối và apply migration
# -------------------------------------------------------------------
def run_migrations_online():
    url = get_url()
    connect_args = get_connect_args(url)

    # Tạo engine thủ công để chèn connect_args (ví dụ SSL CA cho Aiven)
    engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)

    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=include_object,
            render_as_batch=url.startswith("sqlite"),
        )
        with context.begin_transaction():
            context.run_migrations()

# -------------------------------------------------------------------
# 8) Nhánh điều khiển offline/online
# -------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
