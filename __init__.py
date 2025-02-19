import secrets
import sqlite3
from typing import Optional, Tuple, List

import pyotp
from werkzeug.security import check_password_hash, generate_password_hash

def criar_banco(filename: str = 'usuarios.db')-> sqlite3.Connection:
    """
        Cria o banco de dados, descartando os dodos se houver algum
    """
    conn = sqlite3.connect(filename)
    # Enable foreign key support
    conn.execute("PRAGMA foreign_keys = ON;")

    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS usuarios;")
    cursor.execute("""CREATE TABLE usuarios
                    (
                        id          INTEGER NOT NULL
                                    CONSTRAINT usuarios_pk PRIMARY KEY
                                    AUTOINCREMENT,
                        email       TEXT    NOT NULL,
                        senha_hash  text    NOT NULL,
                        use_otp     BOOLEAN NOT NULL DEFAULT 0,
                        otp_secret  TEXT
                    );""")
    cursor.execute("CREATE UNIQUE INDEX usuarios_email_uindex ON usuarios(email);")
    cursor.execute("DROP TABLE IF EXISTS backupkeys;")
    cursor.execute("""CREATE TABLE backupkeys
                    (
                        id          INTEGER NOT NULL
                                    CONSTRAINT backupkeys_pk PRIMARY KEY
                                    AUTOINCREMENT,
                        user_id     INTEGER NOT NULL
                                    CONSTRAINT backupkeys_usuarios_id_fk
                                    REFERENCES usuarios(id) ON DELETE CASCADE,
                        backup_code TEXT NOT NULL,
                        used        BOOLEAN NOT NULL DEFAULT 0
                    );""")
    cursor.execute("CREATE INDEX backupkeys_user_id_index ON backupkeys(user_id);")
    conn.commit()

    return conn

def criar_usuario(conn: sqlite3.Connection,
                  email: str = None,
                  senha: str = None,
                  use_otp:bool = False) -> Optional[Tuple[Optional[str], Optional[str], Optional[List[str]]]]:
    """
        Cria um novo usuário na base de dados.

        - O email é armazenado em letras minúsculas para garantir consistência.
        - A senha é armazenada como um hash usando `generate_password_hash()`.
        - Gera um segredo OTP usando `pyotp.random_base32()`.
        - Gera 5 códigos de backup de 6 caracteres cada, armazenando-os na tabela `backupkeys`
          em formato hash.
        - Retorna o segredo OTP e os códigos de backup em texto plano para o usuário.

        Arguments:
            conn (sqlite3.Connection): Conexão com o banco de dados SQLite.
            email (str): Email do usuário.
            senha (str): Senha em texto plano.
            use_otp (bool): O usuário vai utilizar 2FA (default: False)

        Returns:
            None se o usuário já existir; Tuple[str, str, List[str]] contendo segredo OTP, URI
            para configuração do autenticador e lista de códigos de backup em texto plano se
            usuário tiver configurado 2FA.
    """

    if email is None or senha is None:
        return None

    if email.strip() == "" or senha.strip() == "":
        return None

    cursor = conn.cursor()

    cursor.execute("SELECT id "
                   "FROM usuarios "
                   "WHERE email = ?", (email.lower(),))

    if cursor.fetchone():
        return None

    senha_hash = generate_password_hash(senha)
    otp_secret = pyotp.random_base32() if use_otp else ""

    cursor.execute("INSERT INTO usuarios "
                   "(email, senha_hash, otp_secret, use_otp) "
                   "VALUES (?, ?, ?, ?)", (email.lower(), senha_hash, otp_secret, use_otp))

    conn.commit()

    if not use_otp:
        return None, None, None

    backup_codes = gerar_codigos_reserva(conn, email, senha, 5)
    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=email.lower(), issuer_name="OTP")

    return otp_secret, otp_uri, backup_codes



def login(conn: sqlite3.Connection,
          email: str,
          senha: str,
          otp: str = None) -> bool:
    """
    Verifica as credenciais do usuário para autenticação.

    - O email é convertido para letras minúsculas antes da busca no banco de dados.
    - A senha é validada usando `check_password_hash()`.
    - O código OTP é validado usando `totp.verify()`.
    - Caso o OTP falhe, verifica se o código fornecido corresponde a um código de backup não
      utilizado.
    - Se um código de backup for usado, ele é marcado como "usado" (`used = True`).

    Args:
        conn (sqlite3.Connection): Conexão com o banco de dados SQLite.
        email (str): Email do usuário.
        senha (str): Senha em texto plano.
        otp (str): Código OTP ou código de backup.

    Returns:
         bool: `True` se a autenticação for bem-sucedida, `False` caso contrário.
    """

    cursor = conn.cursor()

    #retrieve user data
    cursor.execute("SELECT id, senha_hash, otp_secret, use_otp "
                "FROM usuarios "
                "WHERE email = ?", (email.lower(),))

    user=cursor.fetchone()

    if not user:
        return False # user not found

    user_id, senha_hash, otp_secret, use_otp = user

    #check password
    if not check_password_hash(senha_hash, senha):
        return False

    # there is no OTP to check
    if not use_otp:
        return True

    # Verify OTP
    totp = pyotp.TOTP(otp_secret)
    if totp.verify(otp):
        return True

    # if otp fails, check backup codes
    cursor.execute("SELECT id, backup_code "
                "FROM backupkeys "
                "WHERE user_id = ? AND used = 0",
                (user_id,))
    backup_codes = cursor.fetchall()

    if not backup_codes:
        return False

    for backup_code in backup_codes:
        backup_code_id, hashed_code  = backup_code
        if check_password_hash(hashed_code , otp):
            cursor.execute("UPDATE backupkeys "
                        "SET used = 1 "
                        "WHERE id = ?",
                        (backup_code_id,))
            conn.commit()
            return True

    return False # if all checks fail

def gerar_codigos_reserva(conn:sqlite3.Connection,
                          email:str,
                          senha:str,
                          quantidade: int =5)-> Optional[List[str]]:
    """
    Gera novos códigos de backup para um usuário autenticado.

    - O email é convertido para letras minúsculas antes da busca no banco de dados.
    - A senha é validada usando `check_password_hash()`.
    - Se a senha estiver correta, novos códigos de backup são gerados e armazenados no banco
      de dados.
    - Os códigos são armazenados na tabela `backupkeys` com `used = False` e retornados em
      texto plano.

    Args:
        conn (sqlite3.Connection): Conexão com o banco de dados SQLite.
        email (str): Email do usuário.
        senha (str): Senha em texto plano.
        quantidade (int): Número de códigos de backup que devem ser gerados (default: 5)

    Returns:
        Optional[List[str]]: Lista dos novos códigos de backup em texto plano, ou `None` se a
                             senha for inválida.
    """

    cursor = conn.cursor()

    #retrieve user data
    cursor.execute("SELECT id, senha_hash, use_otp "
                "FROM usuarios "
                "WHERE email = ?", (email.lower(),))

    user = cursor.fetchone()

    if not user:
        return None #user not found

    user_id, senha_hash, use_otp = user

    #verify password
    if not check_password_hash(senha_hash,senha):
        return None # invalid password

    if not use_otp:
        return None

    #generate new backup codes
    new_codes = ["".join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(6) )
        for _ in range(quantidade)]

    for code in new_codes:
        hashed_code = generate_password_hash(code)
        cursor.execute("INSERT INTO backupkeys (user_id, backup_code, used) "
                       "VALUES (?, ?, False)", (user_id, hashed_code))

    conn.commit()
    return new_codes # Return plaintext codes to the user

















