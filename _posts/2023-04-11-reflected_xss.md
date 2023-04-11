---
title: Reflected XSS
date: 2023-04-11
categories: [Vulnerabilities, Web]
tags: [xss, vulnerabilities, code_injection, web]
comments: false
---

Este tipo de vulnerabilidad XSS es la más simple y común de encontrar en aplicaciones web. Esta está presente cuando una aplicación recibe datos mediante una solicitud HTTP y los inserta dentro de la respuesta inmediata no segura.

Ejemplo de XSS Reflejada:
```
https://insecure-website.com/status?message=All+is+well.
<p>Status: All is well.</p>
```
La aplicación web no realiza ningún procesamiento ni saneamiento en los datos de la petición HTTP, por lo tanto podemos construir fácilmente un ataque como el siguiente:
```
https://insecure-website.com/status?message=<script>/*+Codigo+Malicioso+here...+*/</script>
<p>Status: <script>/* Codigo Malicioso... */</script></p>
```
Si un usuario visita la url construida, la inyección que hemos construido se ejecuta en el navegador del usuario, todo esto en la sesión de ese usuario con la aplicación web. En ese momento, el código malicioso podrá hacer cualquier tipo de acción y obtener cualquier dato al que el usuario víctima tenga acceso.
