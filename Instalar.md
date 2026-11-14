# Como instalar la WebAPI

## Archivos minimos
Esta api asume que ya tienes instalando FatfreeFramework con composer
en la carpeta /var/www/html/wapp

En dicha carpeta debes copiar los siguentes archivos

- index.php
- db.json
- htaccess.txt

1. Renombra htaccess.txt a .htaccess
2. Copia db.json.example a db.json y edita db.json con los datos de tu Base de Datos (db.json no se versiona: contiene credenciales)

## Cargar la base de datos

1. En cualquier otra carpeta del servidor sube el archivo db.sql
2. En la consola de SQL  seleccion tu base de datos
3. Carga tu base de datos desde el script 
4. Agrega elementos basicos de seguridad.
