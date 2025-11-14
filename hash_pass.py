# hash_pass.py
import bcrypt

# La contraseña que queremos hashear
password = "clave123"

# La convertimos a bytes
password_bytes = password.encode('utf-8')

# Generamos la "sal"
salt = bcrypt.gensalt()

# Generamos el hash
hash_bytes = bcrypt.hashpw(password_bytes, salt)

# Convertimos el hash (que está en bytes) a un string para guardarlo en la BD
hash_string = hash_bytes.decode('utf-8')

print("Tu contraseña en texto plano es:", password)
print("El HASH seguro (copia esto) es:", hash_string)