---
title: Stored XSS
date: 2023-04-09 01:00:00
categories: [Vulnerabilities, Web]
tags: [xss, vulnerabilities, code_injection, web]
comments: false
---

Este tipo de XSS, también conocida como XSS Persistente o de segundo orden, aplica cuando una aplicación recibe datos de una fuente que no es de confianza e incluye esos datos en sus posteriores respuesta HTTP de forma no segura.

Los datos pueden enviarse a la aplicación a través de solicitudes HTTP como: comentarios de blogs, apodos de usuarios en chats o detalles de producto en pedidos de clientes. En otros casos, los datos pueden llegar de otras fuentes no confiables como: aplicaciones de correo web que muestran mensajes recibidos a través de SMTP, aplicaciones de marketing que muestran publicaciones en redes sociales o una aplicación de monitorización de red que muestra paquetes de datos del tráfico de la red.

Un ejemplo de XSS Almacenada podría ser un tablero de mensajes que permite a los usuarios enviar mensajes a otros usuarios:
```
<p>Hello, this is my message!</p>
```
La aplicación no realiza ningún saneamiento ni procesamiento del mensaje, esto los podemos aprovechar fácilmente de la siguiente manera:
```
<p><script>/* Codigo Malicioso... */</script></p>
```
