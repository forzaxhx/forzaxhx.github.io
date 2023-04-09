---
title: Blind SQL Injection
date: 2023-04-09 01:00:00
categories: [Vulnerabilities, Web]
tags: [sql, vulnerabilities, code_injection, web]
comments: false
---

La inyección SQL ciega surge cuando una aplicación es vulnerable a inyecciones SQL, pero sus respuestas HTTP no contienen los resultados de la consulta SQL ni los detalles de ningún error de la base de datos.

Cuando las aplicación web son solo vulnerables a ataques de inyección SQL de tipo ciego, los ataques UNION no son efectivos ya que dependen de poder ver los resultados de la consulta inyectada.

## Explotación de inyección SQL ciega mediante condicionales
Considerando una aplicación que utiliza cookies de seguimiento para recopilar análisis sobre el uso. Las solicitudes a la aplicación incluye un encabezado como el siguiente:
```
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```
Cuando se procesa "TrackingId", la aplicación determina si se trata de un usuario conocido mediante la siguiente consulta:
```
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
Esta consulta es vulnerable a la inyección SQL, pero los resultados no se devuelven al usuario. Pero la aplicación se comporta de una manera diferente dependiendo del dato devuelto. Cuando el "TrickingId" es conocido se devuelve un mensaje "Bienvenido de nuevo".
Este comportamiento es suficiente para poder explotar la vulnerabilidad de inyección SQL ciega y recuperar información activando diferentes respuestas condicionales, dependiendo de una condición inyectada, Para ver como funciona esto, suponemos que se envían dos solicitudes que contienen los siguientes "TrackingId":
```
…xyz' AND '1'='1
…xyz' AND '1'='2
```
El primero de estos valores hará que la consulta devuelve resultados, porque "AND '1'='1'1" es verdadera, por lo que se mostrará el mensaje "Bienvenido de nuevo". Mientras que el segundo valor hará que la consulta no devuelva ningún resultado, porque la condición inyectada es falsa, por lo que no se mostrará el mensaje "Bienvenido de nuevo". Esto nos permite determinar la respuesta a cualquier condición inyectada única, por lo tanto, extraer datos bit a bit.
Por ejemplo, suponiendo que existe una tabla "Users" con las consultas "Username" y "Password", y un usuario llamado "Administrator". Podemos determinar la contraseña de este usuario enviando una serie de sentencias para comprobar la contraseña carácter a carácter. La sentencia sería algo como lo siguiente:
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```
Esto devuelve el mensaje "Bienvenido de nuevo", lo que indica que la condición inyectada es verdadera, y por lo tanto el primer carácter es mayor a "m".
A continuación, enviaremos lo siguiente:
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```
Esto no devolverá el mensaje "Bienvenido de nuevo", lo que nos indicará que la condición es falsa. Con esto sabremos que el segundo carácter no es "t".
Finalmente enviaremos los siguiente:
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```
Con esto determinaremos que el primer carácter es una "s".
Con esto y cambiando el determinador de número de carácter podremos determinar uno a uno los caracteres de la contraseña.

## Explotación de inyección SQL ciega mediante errores
Conociendo lo anterior, suponemos que la aplicación realiza la misma consulta, pero no se comporta de manera diferente dependiendo de la respuesta de la consulta. La técnica anterior no funciona en este caso porque inyectar diferentes condiciones booleanas no hace ninguna diferencia en las respuestas de la aplicación.
En esta situación, a menudo es posible inducir errores en los condicionales de las consultas SQL. Esto implica modificar la consulta para que cause un error en la base de datos si la condición es verdadera, pero no si la condición es falsa. A menudo, un error controlado que arroja la base de datos causará alguna diferencia en la respuesta de la aplicación, como un mensaje de error.
Para ver como funciona esto, suponemos que se envían dos solicitudes que contienen los siguientes "TrackingId":
```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
Estas entradas usan el operador "CASE" para comprobar una condición y devuelve una expresión diferente dependiendo si la expresión es verdadera. Con la primera, la expresión "CASE" se evalúa como "a", lo que no provoca ningún error. Con la segunda se evalúa como "1/0", lo que provoca un error de división por cero. Suponiendo que el error cause alguna diferencia en la respuesta HTTP de la aplicación, podemos usar esta diferencia para inferir si la condición inyectada es verdadera.
Usando esta técnica, podemos recuperar datos de la manera descrita, probando un carácter a la vez:
```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

## Explotación de inyección SQL ciega mediante retrasos de tiempo
Con el ejemplo anterior, suponiendo que ahora detecta los errores de la base de datos y los maneja correctamente. Activar un error de base de datos cuando se ejecutan las consultas ya no causa ninguna diferencia en la respuesta, por lo que la técnica anterior ya no es efectiva.
A menudo es posible explotar esta vulnerabilidad utilizando retrasos de tiempo condicionalmente, dependiendo de una condición inyectada. Debido a que la aplicación generalmente procesa las consultas SQL de forma síncrona, retrasar la ejecución de una consulta también retrasa la respuesta HTTP. Esto permite inferir la veracidad de la condición inyectada en función del tiempo transcurrido antes de que se reciba la respuesta HTTP.
Las técnicas para desencadenar un retraso de tiempo son específicas del tipo de base de datos utilizado por la aplicación. En Microsoft SQL Server, una entrada como la siguiente se puede usar para comprobar la condición y desencadenar un retraso dependiendo de si la expresiones verdadera:
```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```
La primera de estas entradas no activará un retraso, porque 1 no es igual a 2. La segunda entrada activará un retraso de 10 segundos, porque 1 es igual a 1.
Usando esta técnica podemos recuperar datos de la manera ya descrita, probando de forma sistemática un carácter cada vez:
```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```
