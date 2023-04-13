---
title: Bypassing Referer-based CSRF defenses
date: 2023-04-13
categories: [Vulnerabilities, Web]
tags: [csrf, vulnerabilities, code_injection, web]
comments: false
---

Además de las defensas que emplean tokens CSRF, algunas aplicaciones utilizan el encabezado HTTP "Referer" para intentar defenderse de los ataques CSRF, normalmente al verificar que la solicitud se originó en el propio dominio de la aplicación. Este enfoque es generalmente menos eficaz y, a menudo, está sujeto a desviaciones.

**Encabezado Referer**
Este encabezado es de solicitud opcional que contiene la URL de la página web vinculada al recurso que se solicita. Por lo general, los navegadores lo agregan automáticamente cuando un usuario activa una solicitud HTTP, incluso al hacer clic en un enlace o enviar un formulario. Existen varios métodos que permiten que la página de enlace retenga o modifique el valor del encabezado "Referer". Esto se hace a menudo por razones de privacidad.

## La validación de Referer depende de que el encabezado esté presente
Algunas aplicaciones validan el encabezado "Referer" cuando está presente en las solicitudes, pero omiten la validación si se omite el encabezado.

En esta situación, podemos crear un exploit CSRF de una manera que haga que el navegador del usuario de la víctima suelte el encabezado "Referer" en la solicitud resultante. Hay varias formas de lograr esto, pero la más fácil es usar una etiqueta "META" dentro de la página HTML que alberga el ataque CSRF:
```
<meta name="referrer" content="never">
```

## La validación de Referir se puede eludir
Algunas aplicaciones validan el encabezado "Referer" de una manera ingenua que se puede omitir. Por ejemplo, si la aplicación valida que el dominio en el "Referer" comienza con el valor esperado, entonces podemos colocar esto como un subdominio de su propio dominio:
```
http://vulnerable-website.com.attacker-website.com/csrf-attack
```
Del mismo modo, si la aplicación simplemente valida que "Referer" contiene su propio nombre de dominio, el atacante puede colocar el valor requerido en otra parte de la URL:
```
http://attacker-website.com/csrf-attack?vulnerable-website.com
```

