---
title: MySQL Injection UNION attack
date: 2023-04-09
categories: [Vulnerabilities, Web]
tags: [mysql, vulnerabilities, code_injection, web]
comments: false
---

Cuando una aplicacion en vulnerable a ataques de inyeccion de SQL y los resultados de las consultas son recogidos por las repuestas de la aplicacion, el operador UNION puede ser unado para devolvernos informacion sobre otras tablas de la base de datos. Esto resulta en un ataque de inyeccion SQL basado en el operador UNION.
El operador UNION nos facilita la ejecucion de una o varias sentencias SELECT, y asi añadir resultados al de la sentencia original.
Por ejemplo:
```
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
Esta consulta sql devolvera un solo resultado de dos columnas, conteniendo este los valores de las columnas "a" y "b" de "table1" y "c" y "d" de "table2".
Para que una sentencia "UNION" funcione, se deben reunir dos requisitos:
- El resultado de las consultas debe contener el mismo numero de columnas.
- Los tipos de datos de cada columna deben ser compatibles.

Para llevar a cavo un ataque de inyeccion SQL mediante el operador UNION, nos tendremos que asegurar que cumplimos estos dos requeisitos. Esto generalmente nos requerira comprobar los siguiente:
- Cuantas columnas contiene la respuesta de la consulta original.
- Que columnas de la respuesta original tienen el tipo de datos requerido para retornar los datos de la consulta inyectada.

## Determinando el numero de columnas
Cuando queremos realizar un ataque UNION de inyección SQL, tenemos dos métodos efectivos para determinar cuántas columnas contiene la respuesta de la consulta original.

El primero se basa en inyectar operadores "ORDER BY", y secuencialmente de forma manual ir aumentando el valor de operador hasta que la respuesta sea un error.
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```
Esta serie de inyeccion modificar la consulta original para ordenar los resultados por diferentes columnas en el conjunto resultados. Con este operador, al estar utilizando el identificador de conlumnas no es necesario saber el nombre de las columnas involucradas en la consulta. El error retornado por el indice que ya no existe seria:
```
The ORDER BY position number 3 is out of range of the number of items in the select list.
```

El segundo consiste en enviar un conjunto de sentencias "UNION SELECT" que especifican el numero de valores nulos. 
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
Si el numero de "NULL" no coincide con el numero de columnas, la respuesta seria un error como el siguiente:
```
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```
Los errores retornados podrias ser como los anteriores o errores personalizados por el sitio web.

## Determinar columnas con un tipo de datos util
El motivo de realizar una inyeccion SQL basada en el parametro UNION es poder recuperar datos de una tabla diferente a la de la tabla original.
Una vez determinada la cantidad de columnas requeridas, podemos sondear cada columna para comprobar si puede contener datos enviando una serie de sentencias "UNION SELECT" que colocan un valor de cadena en cada columna. Por ejemplo en una consulta que contiene cuatro columnas:
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
Si el tipo de datos de una columna no es compatible con los datos de la inyeccion provocara un error en la base de datos, como:
```
Conversion failed when converting the varchar value 'a' to data type int.
```
Si no se produce el error y la respuesta contiene algun contenido adicional, la columna correspondiente es adecuada para recuperar datos de la inyeccion.

## Recuperando datos
Ya habiendo determinado el numero de columnas y la/s columna/s que tienen un tipo de dato compatible con la inyeccion, estaremos el condiciones de recuperar datos interesantes.
Suponiendo que:
- La consalta original devuelve dos columnas, las cuales pueden contener "STRING".
- La inyeccion se realiza dentro un operador "WHERE" de la consulta original.
- La base de datos contiene una tabla "users" con las columnas "username" y "password".

Con estos prerequisitos, podemos recuperar el contenido de la tabla "users" enviando lo siguiente:
```
' UNION SELECT username, password FROM users--
```

## Obtener multiples datos dentro de una sola columna
Si la consulta original solo nos devuelve una solo columna, y sabiendo lo que ya sabemos, si la inyeccion contiene mas de una columna solo podriamos retornar una de ellas. Pero podemos recuperar multiples datos dentro de una sola columna concatenando los valores de varias en una sola, idealmente incluyendo un separados para dividir los datos. Por ejemplo, en Oracle podriamos introducir lo siguiente:
```
' UNION SELECT username || '~' || password FROM users--
```
Esta inyeccion utiliza "||", que es un operador de concatenacion de cadenas en Oracle. La consulta concatena los valores de los campos "username" y "password", separados por el caracter "~".
Hay que tener en cuanta que cada base de datos utiliza una sintaxis diferentes para la concatenacion de valores. Por ejemplo:
```
Oracle: 'foo'||'bar'
PostgreSQL'foo'||'bar'
Microsoft: 'foo'+'bar'
MySQL: CONCAT('foo','bar')
       'foo' 'bar' [Espacio sin coma entre las dos columnas a concatenar]
```
