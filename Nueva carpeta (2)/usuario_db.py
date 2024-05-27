import json
from logging import root 
import cx_Oracle
import subprocess
from flask import Flask, json, jsonify, render_template, request, redirect, send_file, url_for
import cx_Oracle
import tkinter as tk
from tkinter import filedialog, messagebox
import datetime
import threading
import os
from tabulate import tabulate
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)

##primer punto roles, usuarios, etc...

@app.route('/agregar_entidad', methods=['GET', 'POST'])
def agregar_entidad():
    if request.method == 'POST':
        nombre_entidad = request.form['nombre_entidad']
        atributos_nombres = request.form.getlist('atributo_nombre')
        atributos_tipos = request.form.getlist('atributo_tipo')
        
        # Construir la cadena de SQL para crear la tabla con los atributos especificados
        sql_create_table = f"CREATE TABLE {nombre_entidad} (id NUMBER PRIMARY KEY, "
        for nombre, tipo in zip(atributos_nombres, atributos_tipos):
            sql_create_table += f"{nombre} {tipo}, "
        sql_create_table = sql_create_table.rstrip(', ') + ")"
        
        print(f"SQL para crear tabla: {sql_create_table}")  # Agregar para depuración
        
        try:
            conn = cx_Oracle.connect(
                user='system',
                password='tierra24',
                dsn='localhost:1521/XEPDB1',
                encoding='UTF-8'
            )
            cursor = conn.cursor()
            # Ejecutar la consulta SQL para crear la tabla con los atributos especificados
            cursor.execute(sql_create_table)
            conn.commit()
            print(f"Entidad '{nombre_entidad}' agregada correctamente con los atributos: {atributos_nombres}")
        except cx_Oracle.DatabaseError as e:
            error, = e.args
            print("Error al agregar entidad:", error.message)
        finally:
            cursor.close()
            conn.close()
        return redirect(url_for('test'))  # Redirige al menú principal después de agregar la entidad
    else:
        return render_template('agregar_entidad.html')  # Renderiza el formulario para agregar entidad

def obtener_atributos_entidad(nombre_entidad):
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT column_name, data_type
            FROM all_tab_columns
            WHERE table_name = :nombre_entidad
        """, nombre_entidad=nombre_entidad.upper())
        atributos = cursor.fetchall()
        if not atributos:
            # Si no se encuentran atributos, devuelve una lista vacía
            return []
        else:
            # Si se encuentran atributos, procesa los resultados y devuelve una lista de tuplas
            return atributos
    except cx_Oracle.DatabaseError as e:
        print("Error al obtener atributos de la entidad:", e)
        return []  # Manejar el error devolviendo una lista vacía
    finally:
        cursor.close()
        conn.close()

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
        
def get_entities():
    try:
        # Conexión a la base de datos
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()

        # Consulta para obtener todas las tablas del usuario "system"
        query = """
                SELECT object_name
                FROM user_objects
                WHERE object_type = 'TABLE'
                """
        cursor.execute(query)

        # Recuperar las entidades y almacenarlas en una lista
        entities = [row[0] for row in cursor]

        # Cerrar cursor y conexión
        cursor.close()
        conn.close()

        return entities
    except Exception as e:
        print("Error:", e)
        return []

entities = get_entities()
print(entities)

@app.route('/get_entities')
def send_entities():
    entities = get_entities()
    html_content = "<ul>"
    for entity in entities:
        html_content += f"<li>{entity} <button onclick=\"viewAttributes('{entity}')\">Ver Atributos</button></li>"
    html_content += "</ul>"
    html_content += """
    <script>
        function viewAttributes(entityName) {
            window.location.href = '/ver_atributos/' + entityName;
        }
    </script>
    """
    return html_content

@app.route('/ver_atributos/<nombre_entidad>')
def ver_atributos(nombre_entidad):
    atributos = obtener_atributos_entidad(nombre_entidad)
    return render_template('ver_atributos.html', nombre_entidad=nombre_entidad, atributos=atributos)

@app.route('/')
def menu():
    return render_template('index.html')

@app.route('/test')
def test():
    return render_template('test.html')


#para agregarusuario,etc.. roles, etc..
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

#para generer el pdf y que no de problemas con el listado
# de las entidades y atrivutos por entidad
@app.route('/get_entities_pdf', methods=['GET'])
def get_entities_pdf():
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT table_name FROM all_tables WHERE owner = 'SYSTEM'")
        entities = cursor.fetchall()
        cursor.close()
        conn.close()

        entities_list = [{'name': entity[0]} for entity in entities]
        return jsonify(entities_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ver_atributos_pdf/<nombre_entidad>', methods=['GET'])
def ver_atributos_pdf(nombre_entidad):
    try:
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT column_name
            FROM all_tab_columns
            WHERE table_name = :nombre_entidad
        """, nombre_entidad=nombre_entidad.upper())
        attributes = cursor.fetchall()
        cursor.close()
        conn.close()

        attributes_list = [{'name': attr[0]} for attr in attributes]
        return jsonify(attributes_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#para restaurar
#DESDE AQUI COMPLICADO
@app.route('/generar.html')
def generar_pdf():
    return render_template('generar.html')

@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    try:
        entities_json = request.form.get('entities')
        attributes_json = request.form.get('attributes')
        entities = json.loads(entities_json)
        attributes = json.loads(attributes_json)

        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )
        cursor = conn.cursor()

        pdf_file = "reporte.pdf"
        c = canvas.Canvas(pdf_file, pagesize=letter)
        y = 750

        for entity in entities:
            query = f"SELECT {', '.join(attributes)} FROM {entity}"
            cursor.execute(query)
            resultados = cursor.fetchall()
            print(f"Resultados para la entidad {entity}: {resultados}")

            c.drawString(50, y, f"Entidad: {entity}")
            y -= 20

            for row in resultados:
                x = 50
                for item in row:
                    c.drawString(x, y, str(item))
                    x += 100
                y -= 20
            y -= 20

        c.save()
        cursor.close()
        conn.close()

        return send_file(pdf_file, as_attachment=True)
    except Exception as e:
        error_message = f"Error al generar el PDF: {str(e)}"
        print(error_message)
        return error_message, 500

def obtener_ruta_directorio():
    try:
        # Establece la conexión con la base de datos Oracle
        conn = cx_Oracle.connect(
            user='system',
            password='tierra24',
            dsn='localhost:1521/XEPDB1',
            encoding='UTF-8'
        )

        # Crea un cursor para ejecutar la consulta
        cursor = conn.cursor()

        # Ejecuta la consulta para obtener la ruta del directorio
        cursor.execute("SELECT directory_path FROM all_directories WHERE directory_name = 'DATA_PUMP_DIR'")

        # Recupera la ruta del directorio
        ruta_directorio = cursor.fetchone()[0]
        return ruta_directorio

    except cx_Oracle.DatabaseError as e:
        print("Error al obtener la ruta del directorio:", e)
        return None

    finally:
        # Cierra el cursor y la conexión si están inicializados
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
            
tns_alias = 'localhost/XEPDB1'

def realizar_respaldo():
    root = tk.Tk()
    root.withdraw()

    try:
        # Nombre del archivo de respaldo
        backup_filename = f'backup_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.dmp'

        # Obtener la ruta del directorio
        ruta_directorio = obtener_ruta_directorio()
        if ruta_directorio is None:
            messagebox.showerror("Error", "No se pudo obtener la ruta del directorio.")
            return

        # Comando para realizar el respaldo
        backup_command = f'expdp system/tierra24@{tns_alias} DIRECTORY=DATA_PUMP_DIR DUMPFILE="{backup_filename}" LOGFILE=backup.log FULL=YES'

        # Ejecutar el comando de respaldo desde la línea de comandos
        subprocess.run(backup_command, shell=True, check=True, capture_output=True, text=True)

        # Definir la ruta completa del archivo de respaldo
        ruta_archivo = os.path.join(ruta_directorio, backup_filename)

        # Obtener solo el nombre del archivo
        nombre_archivo = os.path.basename(ruta_archivo)

        # Abrir la ventana de diálogo para seleccionar el nombre del archivo
        ruta_destino = filedialog.asksaveasfilename(defaultextension=".dmp",
                                                    filetypes=[("Archivos de respaldo", "*.dmp")],
                                                    title="Guardar respaldo como",
                                                    initialfile=nombre_archivo)

        if ruta_destino:
            # Mover el archivo generado al destino seleccionado
            os.rename(ruta_archivo, ruta_destino)
            messagebox.showinfo("Respaldo completado", f"Respaldo guardado en:\n{ruta_destino}")
        else:
            messagebox.showwarning("Operación cancelada", "No se realizó el respaldo porque la operación fue cancelada.")

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error al realizar el respaldo", f"{e}\nOutput: {e.output}\nError: {e.stderr}")

    root.destroy()

@app.route('/respaldo', methods=['POST'])
def respaldo():
    threading.Thread(target=realizar_respaldo).start()
    return redirect(url_for('respaldo_restaurar', message='Proceso de respaldo iniciado.'))

def realizar_restauracion():
    root = tk.Tk()
    root.withdraw()  # Ocultar la ventana principal de Tkinter

    try:
        # Obtener la ruta del directorio
        restore_directory = obtener_ruta_directorio()

        if restore_directory:
            # Abrir la ventana de diálogo para seleccionar el archivo de respaldo
            ruta_archivo = filedialog.askopenfilename(
                defaultextension=".dmp",
                filetypes=[("Archivos de respaldo", "*.dmp")],
                title="Seleccionar archivo de respaldo"
            )

            if ruta_archivo:
                # Obtener solo el nombre del archivo, sin la ruta
                nombre_archivo = os.path.basename(ruta_archivo)
                # Comando para realizar la restauración
                restore_command = f"impdp system/tierra24@{tns_alias} DIRECTORY=DATA_PUMP_DIR DUMPFILE={nombre_archivo} LOGFILE=restore.log FULL=YES"

                # Copiar el archivo seleccionado al directorio de Oracle
                destino_archivo = os.path.join(restore_directory, nombre_archivo)
                os.rename(ruta_archivo, destino_archivo)

                # Ejecutar el comando de restauración desde la línea de comandos
                subprocess.run(restore_command, shell=True, check=True, capture_output=True, text=True)
                messagebox.showinfo("Restauración completada", f"La base de datos ha sido restaurada desde:\n{ruta_archivo}")
            else:
                messagebox.showwarning("Operación cancelada", "No se realizó la restauración porque la operación fue cancelada.")
        else:
            messagebox.showerror("Error al realizar la restauración", "No se pudo obtener la ruta del directorio de restauración.")

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error al realizar la restauración", f"{e}\nOutput: {e.output}\nError: {e.stderr}")

    root.destroy()

@app.route('/restauracion', methods=['POST'])
def restauracion():
    threading.Thread(target=realizar_restauracion).start()
    return redirect(url_for('respaldo_restaurar', message='Proceso de restauración iniciado.'))

@app.route('/respaldo_restaurar')
def respaldo_restaurar():
    message = request.args.get('message', '')
    return render_template('respaldo_restaurar.html', message=message)



########CRUDS

@app.route('/crud')
def crud():
    return render_template('crud.html')

def get_columns(cursor, table_name):
    cursor.execute(f"""
        SELECT column_name, data_type
        FROM user_tab_columns
        WHERE table_name = '{table_name}'
    """)
    return cursor.fetchall()

def generate_procedures(cursor, table_name, columns):
    primary_key = columns[0][0]  # Suponemos que la primera columna es la clave primaria
    col_names = [col[0] for col in columns]
    col_names_str = ", ".join(col_names)
    col_params = ", ".join([f"p_{col[0]} {col[1]}" for col in columns])
    col_params_without_pk = ", ".join([f"p_{col[0]} {col[1]}" for col in columns[1:]])
    col_assignments = ", ".join([f"{col[0]} = p_{col[0]}" for col in columns[1:]])
    col_values = ", ".join([f"p_{col[0]}" for col in columns])

    procedures = f"""
    CREATE OR REPLACE PROCEDURE insert_{table_name} (
        {col_params}
    ) AS
    BEGIN
        INSERT INTO {table_name} ({col_names_str})
        VALUES ({col_values});
    END insert_{table_name};
    /

    CREATE OR REPLACE PROCEDURE select_{table_name} (
        p_result OUT SYS_REFCURSOR
    ) AS
    BEGIN
        OPEN p_result FOR SELECT * FROM {table_name};
    END select_{table_name};
    /

    CREATE OR REPLACE PROCEDURE update_{table_name} (
        p_{primary_key} {columns[0][1]},
        {col_params_without_pk}
    ) AS
    BEGIN
        UPDATE {table_name}
        SET {col_assignments}
        WHERE {primary_key} = p_{primary_key};
    END update_{table_name};
    /

    CREATE OR REPLACE PROCEDURE delete_{table_name} (
        p_{primary_key} {columns[0][1]}
    ) AS
    BEGIN
        DELETE FROM {table_name}
        WHERE {primary_key} = p_{primary_key};
    END delete_{table_name};
    /
    """
    return procedures

@app.route('/generate_crud')
def generate_crud():
    connection = cx_Oracle.connect('system', 'tierra24', 'localhost/XEPDB1')
    cursor = connection.cursor()

    cursor.execute("""
        SELECT table_name
        FROM user_tables
    """)
    tables = cursor.fetchall()

    with open("procedures.sql", "w") as f:
        for table in tables:
            table_name = table[0]
            columns = get_columns(cursor, table_name)
            procedures = generate_procedures(cursor, table_name, columns)
            
            # Escribir en el archivo
            f.write(f"-- Procedimientos para la tabla {table_name}\n")
            f.write(procedures)
            f.write("\n")
            
            # Ejecutar en la base de datos
            for procedure in procedures.split('/'):
                if procedure.strip():
                    cursor.execute(procedure.strip())

    connection.commit()
    cursor.close()
    connection.close()

    return send_file("procedures.sql", as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)