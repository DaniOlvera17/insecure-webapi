import json
import random
import hashlib
import secrets
import hmac
import re
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



def loadDatabaseSettings(pathjs):
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson
	
"""
function loadDatabaseSettings(pathjs):
	string = file_get_contents(pathjs);
	json_a = json_decode(string, true);
	return json_a;

"""
def getToken():
	# Token aleatorio criptograficamente seguro (no predecible)
	return secrets.token_hex(32)

def hashPassword(password):
	# PBKDF2-HMAC-SHA256 con sal aleatoria por usuario
	salt = secrets.token_hex(16)
	dk = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 200000).hex()
	return f"pbkdf2_sha256$200000${salt}${dk}"

def verifyPassword(password, almacenado):
	# Compara en tiempo constante contra el hash guardado
	try:
		algo, iteraciones, salt, dk = almacenado.split('$')
		calc = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(iteraciones)).hex()
		return hmac.compare_digest(calc, dk)
	except Exception:
		return False

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def campoVacio(*valores):
	# Devuelve True si algun valor no es texto o esta vacio
	for v in valores:
		if not isinstance(v, str) or v.strip() == "":
			return True
	return False

"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""
@post('/Registro')
def Registro():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	####/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	if not R:
		return {"R":-1}
	# Validar que los campos no esten vacios
	if campoVacio(request.json["uname"], request.json["email"], request.json["password"]):
		return {"R":-1}
	# Validar formato de correo
	if not EMAIL_RE.match(request.json["email"]):
		return {"R":-1}
	# Exigir una longitud minima de contrasena
	if len(request.json["password"]) < 8:
		return {"R":-1}
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Usuario values(null,%s,%s,%s)', (request.json["uname"], request.json["email"], hashPassword(request.json["password"])));
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
		return {"R":-2}
	return {"R":0,"D":R}




"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'uname' in request.json  and 'password' in request.json
	if not R:
		return {"R":-1}
	# Validar que los campos no esten vacios
	if campoVacio(request.json["uname"], request.json["password"]):
		return {"R":-1}
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('Select id, password from Usuario where uname = %s', (request.json["uname"],));
			filas = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}

	# Verificar la contrasena en Python contra el hash PBKDF2 almacenado
	if filas and verifyPassword(request.json["password"], filas[0][1]):
		R = [(filas[0][0],)]
	else:
		R = False
	
	
	if not R:
		db.close()
		return {"R":-3}
	
	T = getToken();
	# Los tokens de sesion no se escriben en archivos de texto plano.
	try:
		with db.cursor() as cursor:
			cursor.execute('Delete from AccesoToken where id_Usuario = %s', (R[0][0],));
			cursor.execute('insert into AccesoToken values(%s,%s,now())', (R[0][0], T));
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 * 
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",
 * 		"ext": "PNG"
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	if not R:
		return {"R":-1}
	# Validar que los campos no esten vacios
	if campoVacio(request.json["name"], request.json["data"], request.json["ext"], request.json["token"]):
		return {"R":-1}
	
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	# Validar si el usuario esta en la base de datos
	TKN = request.json['token'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (TKN,));
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	# Si el token no existe, R viene vacio: evitar el error y rechazar
	if not R:
		db.close()
		return {"R":-2}
	id_Usuario = R[0][0];
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(base64.b64decode(request.json['data'].encode()))
	
	############################
	############################
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Imagen values(null,%s,"img/",%s)', (request.json["name"], id_Usuario));
			cursor.execute('select max(id) as idImagen from Imagen where id_Usuario = %s', (id_Usuario,));
			R = cursor.fetchall()
			idImagen = R[0][0];
			cursor.execute('update Imagen set ruta = %s where id = %s', ('img/'+str(idImagen)+'.'+str(request.json['ext']), idImagen));
			db.commit()
			# Mover archivo a su nueva locacion
			shutil.move('tmp/'+str(id_Usuario),'img/'+str(idImagen)+'.'+str(request.json['ext']))
			return {"R":0,"D":idImagen}
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	
"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Descargar')
def Descargar():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	# Validar que el token exista y obtener el usuario dueno
	id_Usuario = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (TKN,));
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	if not R:
		db.close()
		return {"R":-2}
	id_Usuario = R[0][0]

	# Buscar la imagen SOLO si pertenece a este usuario (evita IDOR)
	try:
		with db.cursor() as cursor:
			cursor.execute('Select name,ruta from Imagen where id = %s and id_Usuario = %s', (idImagen, id_Usuario));
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	db.close()
	if not R:
		return {"R":-3}

	# Servir solo el nombre del archivo desde la carpeta img (evita acceso a otros archivos)
	nombre_archivo = Path(R[0][1]).name
	return static_file(nombre_archivo, Path("img").resolve())

if __name__ == '__main__':
    run(host='localhost', port=8082, debug=False)
