---
title: Blind SQL Injection
date: 2023-04-09 01:00:00
categories: [Vulnerabilities, Web]
tags: [sql, vulnerabilities, code_injection, web]
comments: false
---

La inyeccion SQL ciega surge cuando una aplicacion es vulnerable a inyecciones SQL, pero sus respuestas HTTP no contienen los resultados de la consulta SQL no los detalles de ningun error de la base de datos.

Cuando las aplicacion web son solo vulnerables a ataques de inyeccion SQL de tipo ciego, los ataques UNION no son efectivos ya que dependen de poder ver los resultados de la consulta inyectada.

## Explotacion de inyeccion SQL ciega mediante condicionales
Considerando una aplicacion que utiliza cookies de segumiento para recopilar analisis sobre el uso. Las solicitudes a la aplicacion incluirian un encabezado cono el siguiente:
```
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```
Cuando se procesa "TrackingId", la aplicacion determina si se trata de un usuario conocido mediante la siguiente consulta:
```
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
Esta consulta es vulnerable a la inyeccion SQL, pero los resultados no se devuelven al usuario. Pero la aplicacion se comporta de una manera diferente dependiendo del dato devuelto. Cuando el "TrickingId" es conocido se devuelve un mensaje "Bienvenido de nuevo".
Este comportamiento es suficiente para poder explotar la vulnerabilidad de inyeccion SQL ciega y recuperar informacion activando diferentes respuestas condicionales, dependiendo de una condicion inyectada, Para ver como funciona esto, suponemos que se envian dos solicitudes que contienen los siguientes "TrackingId":
```
…xyz' AND '1'='1
…xyz' AND '1'='2
```
El primero de estos valores hara que la consulta devuelva resultados, porque "AND '1'='1'1" es verdadera, por lo que se mostrara el mensaje "Bienvenido de nuevo". Mientras que el segundo valores hara que la consulta no devuelva ningun resultado, porque la condicion inyectada es falsa, por lo que no se mostrara el mensaje "Bienvenido de nuevo". Esto nos permite determinar la respuesta a cualquier condicion inyectada unica, por lo tanto, extraer datos bit a bit.
Por ejemplo, suponiendo que existe una tabla "Users" con las consultas "Username" y "Password", y un usuario llamado "Administrator". Podemos determinar la contraseña de este usuario enviando una serie de sentenias para comprobar la contraseña caracter a caracter. La sentencia seria algo como lo siguiente:
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```
Esto devuelve el mensaje "Bienvenido de nuevo", lo que indica que la condicion inyectada es verdadera, y por lo tanto el primer caracter es mayor a "m".
A continuacion, enviaremos lo siguiente:
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```
Esto no devolvera el mensaje "Bienvenido de nuevo", lo que nos indicara que la condicion es falsa. Con esto sabremos que el segundo caracter no es "t".
Finalmente enviaremos los siguiente:
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```
Con esto determinaremos que el primer caracter es una "s".
Con esto y cambiando el determinador de numero de caracter podremos determinar uno a uno los caracteres de la contraseña.

## Explotacion de inyeccion SQL ciega mediante errores
Conociendo lo anterior, suponemos que la aplicacion realiza la misma consulta, pero no se comporta de manera diferente dependiendo de la respuesta de la consulta. La tecnica anterior no funcionaria en este acso porque inyectar diferentes condicionales booleanas no hace ninguna diferencia en las respuestas de la aplicacion.
En esta situacion, a menudo en posible indicir errores en los condicionales de las consultas SQL. Esto implica modificar la consilta para que cause un error en la base de datos si la condicion es verdadera, pero no si la condicion es falsa. A menudo, un error controlado que arroja la base de datos causara alguna diferencia en la respuesta de la aplicacion, como un mensaje de error.
Para ver como funciona esto, suponemos que se envian dos solicitudes que contienen los siguientes "TrackingId":
```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
Estas entradas usan el operador "CASE" para comprobar una condicion y devolver una expresion diferente dependiendo si la expresion es verdadera. Con la primera, la expresion "CASE" se evalua como "a", lo que no provoca ningun error. Con la segundam se evalua como "1/0", lo que provoca un error de division por cero. Suponiendo que el error cause alguna diferencia en la respuesta HTTP de la aplicacion, podemos usar esta diferencia para inferir si la condicion inyectada es verdadera.
Usando esta tecnica, podemos recuperar datos de la manera descrita, probando un caracter a la vez:
```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

## Explotacion de inyeccion SQL ciega mediante retrasos de tiempo
Con el ejemplo anterior, suponiendo que ahora detecta los errores de la base de datos y los maneja correctamente. Activar un error de base de datos cuando se ejecutan las consultas ya no causa ninguna diferencia en la respuesta, por lo que la tecnica anterior ya no es efectiva.
A menudo es posible explotar esta vulnerabilidad utilizando retrasos de tiempo condicionalmente, dependiendo de una condicion inyectada. Debido a que la aplicacion generalmente procesa las consultas SQL de forma sincrona, retrasar la ejecucion de una consulta tambien retrasa la respuesta HTTP. Esto permite inferir la veracidad de la condicion inyectada en funcion del tiempo transcurrido antes de que se reciba la respuesta HTTP.
Las tecnicas para desencadenar unretraso de tiempo son especificas del tipo de base de datos utilizado por la aplicacion. En Microsoft SQL Server, una entrada como la siguiente se puede usar para comprobar la condicion y desencadenar un retraso dependiendo de si la expresiones verdadera:
```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```
La primera de estas entradas no activara un retraso, porque 1 no es igual a 2. La segundo entrada activara un retraso de 10 segundos, porque 1 es igual a 1.
Usando esta tecnica podemos recuperar datos de la manera ya descrita, probando de forma sistematica un caracter cada vez:
```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```
