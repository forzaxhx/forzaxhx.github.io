---
title: MySQL Injection UNION attack
date: 2023-04-09
categories: [Vulnerabilities, Web]
tags: [mysql, vulnerabilities, code_injection, web]
comments: false
pin: true
---

Cuando una aplicacion en vulnerable a ataques de inyeccion de SQL y los resultados de las consultas son recogidos por las repuestas de la aplicacion, el operador UNION puede ser unado para devolvernos informacion sobre otras tablas de la base de datos. Esto resulta en un ataque de inyeccion SQL basado en el operador UNION.
El operador UNION nos facilita la ejecucion de una o varias sentencias SELECT, y asi añadir resultados al de la sentencia original.
Por ejemplo:
```
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
