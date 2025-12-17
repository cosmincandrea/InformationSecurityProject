import os


class Config:

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    #ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

    BACKUP_DIR = os.environ.get("BACKUP_DIR", "backups")
