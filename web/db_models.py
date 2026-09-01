# wiperx/web/db_models.py
"""
SQLAlchemy ORM Models
-----------------------
Persistent-storage mirrors of the dataclasses in web/models.py. Kept
deliberately separate from the app-facing User/RemoteMachine classes so
Flask-Login's UserMixin and the rest of the app never depend on SQLAlchemy
directly - web/models.py's store proxies are the only place that converts
between the two.
"""

from sqlalchemy import Column, Integer, String
from web.db import Base


class UserORM(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)
    display_name = Column(String, default="")
    # "local" (bcrypt password below is authoritative) or "ldap" (created/
    # updated just-in-time on a successful LDAP bind - see web/ldap_auth.py).
    auth_source = Column(String, default="local", nullable=False)


class MachineORM(Base):
    __tablename__ = "machines"

    machine_id = Column(String, primary_key=True)
    hostname = Column(String, nullable=False)
    os_type = Column(String, default="unknown")
    connection_type = Column(String, default="ssh")
    ssh_username = Column(String, default="")
    ssh_key_path = Column(String, default="")
    ssh_port = Column(Integer, default=22)
    winrm_username = Column(String, default="")
    winrm_port = Column(Integer, default=5986)
    description = Column(String, default="")
    last_scan = Column(String, nullable=True)
    status = Column(String, default="unknown")
