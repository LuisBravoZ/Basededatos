import subprocess
from flask import Flask, render_template, request, redirect, url_for
import cx_Oracle
import tkinter as tk
from tkinter import filedialog, messagebox
import datetime
import threading
import os

app = Flask(__name__)
# Ruta del directorio DATA_PUMP_DIR en tu sistema Oracle
DATA_PUMP_DIR = '/path/to/data_pump_dir'

# Función para obtener la lista de usuarios
def obtener_usuarios():
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM all_users WHERE username NOT IN ('SYS', 'SYSTEM')")
        usuarios = [row[0] for row in cursor.fetchall()]
        return usuarios
    except cx_Oracle.DatabaseError as e:
        print("Error al obtener usuarios:", e)
        return []

# Función para obtener la lista de roles
def obtener_roles():
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM dba_roles")
        roles = [row[0] for row in cursor.fetchall()]
        return roles
    except cx_Oracle.DatabaseError as e:
        print("Error al obtener roles:", e)
        return []

# Función para obtener los roles de un usuario
def obtener_roles_usuario(nombre_usuario):
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT granted_role
            FROM dba_role_privs
            WHERE grantee = :nombre_usuario
        """, nombre_usuario=nombre_usuario)
        roles = [row[0] for row in cursor.fetchall()]
        return roles
    except cx_Oracle.DatabaseError as e:
        print("Error al obtener roles del usuario:", e)
        return []
    finally:
        cursor.close()
        conn.close()
        
# Función para realizar el respaldo
def realizar_respaldo():
    root = tk.Tk()
    root.withdraw()  # Ocultar la ventana principal de Tkinter

    # Abrir la ventana de diálogo para guardar el archivo
    ruta_archivo = filedialog.asksaveasfilename(defaultextension=".dmp",
                                                filetypes=[("Archivos de respaldo", "*.dmp")],
                                                title="Guardar respaldo como")

    if ruta_archivo:
        # Obtener solo el nombre del archivo, sin la ruta
        nombre_archivo = os.path.basename(ruta_archivo)
        # Ruta completa en el directorio de Data Pump
        data_pump_path = os.path.join(DATA_PUMP_DIR, nombre_archivo)
        # Comando para realizar el respaldo
        backup_command = f'expdp system/tierra24@localhost:1521/XEPDB1 DIRECTORY=DATA_PUMP_DIR DUMPFILE={nombre_archivo}'

        try:
            # Ejecutar el comando de respaldo desde la línea de comandos
            subprocess.run(backup_command, shell=True, check=True, capture_output=True, text=True)
            # Mover el archivo generado al destino seleccionado
            if os.path.exists(data_pump_path):
                os.rename(data_pump_path, ruta_archivo)
                messagebox.showinfo("Respaldo completado", f"Respaldo guardado en:\n{ruta_archivo}")
            else:
                messagebox.showerror("Error al realizar el respaldo", "No se encontró el archivo generado.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error al realizar el respaldo", f"{e}\nOutput: {e.output}\nError: {e.stderr}")
    else:
        messagebox.showwarning("Operación cancelada", "No se realizó el respaldo porque la operación fue cancelada.")

    root.destroy()
# Función para realizar la restauración
def realizar_restauracion():
    root = tk.Tk()
    root.withdraw()  # Ocultar la ventana principal de Tkinter

    # Abrir la ventana de diálogo para seleccionar el archivo de respaldo
    ruta_archivo = filedialog.askopenfilename(defaultextension=".dmp",
                                              filetypes=[("Archivos de respaldo", "*.dmp")],
                                              title="Seleccionar archivo de respaldo")

    if ruta_archivo:
        # Obtener solo el nombre del archivo, sin la ruta
        nombre_archivo = os.path.basename(ruta_archivo)
        # Comando para realizar la restauración
        restore_command = f'impdp system/tierra24@localhost:1521/XEPDB1 DIRECTORY=DATA_PUMP_DIR DUMPFILE={nombre_archivo}'

        try:
            # Copiar el archivo al directorio de Data Pump si no está allí
            data_pump_path = os.path.join(DATA_PUMP_DIR, nombre_archivo)
            if not os.path.exists(data_pump_path):
                os.rename(ruta_archivo, data_pump_path)

            # Ejecutar el comando de restauración desde la línea de comandos
            subprocess.run(restore_command, shell=True, check=True, capture_output=True, text=True)
            messagebox.showinfo("Restauración completada", f"La base de datos ha sido restaurada desde:\n{ruta_archivo}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error al realizar la restauración", f"{e}\nOutput: {e.output}\nError: {e.stderr}")
    else:
        messagebox.showwarning("Operación cancelada", "No se realizó la restauración porque la operación fue cancelada.")

    root.destroy()

def get_entities():
    # Conexión a la base de datos
    conn = cx_Oracle.connect(
        user='system',
        password='tierra24',
        dsn='localhost:1521/XEPDB1',
        encoding='UTF-8'
    )
    cursor = conn.cursor()

    # Consulta para obtener las últimas 18 entidades creadas por el usuario "system"
    query = """
            SELECT table_name 
            FROM all_tables 
            WHERE owner = 'SYSTEM' 
            
            """
    cursor.execute(query)

    # Recuperar las entidades y almacenarlas en una lista
    entities = [row[0] for row in cursor]

    # Cerrar cursor y conexión
    cursor.close()
    conn.close()

    return entities

@app.route('/get_entities')
def send_entities():
    entities = get_entities()
    html_content = "<ul>"
    for entity in entities:
        html_content += f"<li>{entity}</li>"
    html_content += "</ul>"
    return html_content


@app.route('/')
def menu():
    return render_template('index.html')

@app.route('/respaldo', methods=['POST'])
def respaldo():
    # Ejecutar la función de respaldo en un hilo separado
    threading.Thread(target=realizar_respaldo).start()
    return redirect(url_for('respaldo_restaurar', message='Proceso de respaldo iniciado.'))

@app.route('/restauracion', methods=['POST'])
def restauracion():
    # Ejecutar la función de restauración en un hilo separado
    threading.Thread(target=realizar_restauracion).start()
    return redirect(url_for('respaldo_restaurar', message='Proceso de restauración iniciado.'))

@app.route('/respaldo_restaurar')
def respaldo_restaurar():
    message = request.args.get('message', '')
    return render_template('respaldo_restaurar.html', message=message)


@app.route('/test')
def test():
    return render_template('test.html')

@app.route('/administrar_usuarios', methods=['GET', 'POST'])
def administrar_usuarios():
    usuarios = obtener_usuarios()
    roles = obtener_roles()
    roles_usuario = []
    usuario_seleccionado = None
    if request.method == 'POST':
        usuario_seleccionado = request.form['nombre_usuario']
        roles_usuario = obtener_roles_usuario(usuario_seleccionado)
    return render_template('administrar_usuarios.html', usuarios=usuarios, roles=roles, roles_usuario=roles_usuario, usuario_seleccionado=usuario_seleccionado)

@app.route('/agregar_usuario', methods=['POST'])
def agregar_usuario():
    nombre = request.form['nombre']
    contraseña = request.form['contraseña']
    
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("CREATE USER {} IDENTIFIED BY {}".format(nombre, contraseña))
        conn.commit()
        print("Usuario agregado correctamente")
    except cx_Oracle.DatabaseError as e:
        print("Error al agregar usuario:", e)
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('administrar_usuarios'))

@app.route('/eliminar_usuario', methods=['POST'])
def eliminar_usuario():
    nombre = request.form['nombre_eliminar']
    
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("DROP USER {}".format(nombre))
        conn.commit()
        print("Usuario eliminado correctamente")
    except cx_Oracle.DatabaseError as e:
        print("Error al eliminar usuario:", e)
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('administrar_usuarios'))

@app.route('/modificar_usuario', methods=['POST'])
def modificar_usuario():
    nombre = request.form['nombre_modificar']
    nueva_contraseña = request.form['nueva_contraseña']
    
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("ALTER USER {} IDENTIFIED BY {}".format(nombre, nueva_contraseña))
        conn.commit()
        print("Usuario modificado correctamente")
    except cx_Oracle.DatabaseError as e:
        print("Error al modificar usuario:", e)
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('administrar_usuarios'))

@app.route('/crear_rol', methods=['POST'])
def crear_rol():
    nombre_rol = request.form['nombre_rol']
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("CREATE ROLE {}".format(nombre_rol))
        conn.commit()
        print("Rol creado correctamente")
    except cx_Oracle.DatabaseError as e:
        print("Error al crear rol:", e)
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('administrar_usuarios'))

@app.route('/asignar_rol', methods=['POST'])
def asignar_rol():
    nombre_usuario = request.form['nombre_usuario']
    nombre_rol = request.form['nombre_rol']
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("GRANT {} TO {}".format(nombre_rol, nombre_usuario))
        conn.commit()
        print("Rol asignado correctamente")
    except cx_Oracle.DatabaseError as e:
        print("Error al asignar rol:", e)
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('administrar_usuarios'))

@app.route('/ver_roles_usuario', methods=['GET', 'POST'])
def ver_roles_usuario():
    usuarios = obtener_usuarios()
    roles_usuario = []
    usuario_seleccionado = None
    if request.method == 'POST':
        usuario_seleccionado = request.form['nombre_usuario']
        roles_usuario = obtener_roles_usuario(usuario_seleccionado)
    return render_template('ver_roles_usuario.html', usuarios=usuarios, roles_usuario=roles_usuario, usuario_seleccionado=usuario_seleccionado)

if __name__ == '__main__':
    app.run(debug=True)