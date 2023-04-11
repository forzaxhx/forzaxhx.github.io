---
title: Reflected XSS
date: 2023-04-09 01:00:00
categories: [Vulnerabilities, Web]
tags: [xss, vulnerabilities, code_injection, web]
comments: false
---

Este tipo de vulnerabilidad XSS es la mas simple y comun de encontrar en aplicaciones web. Esta esta presente cuando una aplicacion recibe datos mediante una solicitud HTTP y los inserta dentro de la respuesta inmedita no segura.

Ejemplo de XSS Reflejada:
```
https://insecure-website.com/status?message=All+is+well.
<p>Status: All is well.</p>
```
La aplicacion web no realiza ningun procesamiento ni saneamiento en los datos de la peticion HTTP, por lo tanto podemos construir facilmente un ataque como el siguiente:
```
https://insecure-website.com/status?message=<script>/*+Codigo+Malicioso+here...+*/</script>
<p>Status: <script>/* Codigo Malicioso... */</script></p>
```
Si un usuario visita la url construida, la inyeccion que hemos construido se ejecuta en el navegador del usuario, todo esto en la sesion del ese usuario con la aplicacion web. En ese momento, el codigo malicioso podra hacer cualquier tipo de accion y obtener cualquier dato al que el usuario victima tenga acceso.

