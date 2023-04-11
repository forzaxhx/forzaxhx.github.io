---
title: CSP Evasion
date: 2023-04-11
categories: [Vulnerabilities, Web]
tags: [xss, vulnerabilities, code_injection, web]
comments: false
---

Política de seguridad de contenido o CSP es un mecanismo de seguridad del navegador que tiene como objetivo mitigar los ataques XSS y otros ataques. Su función es restringir los recursos que una página puede cargar y restringir si una página puede ser enmarcada por otras páginas.

Para habilitar CSP, una respuesta debe incluir un encabezado de respuesta HTTP llamado "Content-Security-Policy" con un valor que contenga la política. La política en sí consta de una o más directivas, separadas por punto y coma.

## Omisión de CSP con inyeccion de políticas
Es posible encontrar que un sitio web refleje la entrada en la política real, muy probablemente en una directiva "report-uri". Si el sitio refleja un parámetro que podamos controlar, podemos inyectar un punto y coma para agregar nuestras propias directivas. Generalmente, esta directiva "report-uri" es la última de la lista y será la última en interpretarse. Esto significa que esta deberá sobreescribir las directivas existentes para aprovechar esta vulnerabilidad y eludir la política.

Por lo general, no es posible sobreescribir las directivas "report-uri" existentes. Sin embargo, Chrome introdujo recientemente la directiva "script-src-elm", que le permite controlar los elementos "script", pero no eventos. De forma fundamental, esta nueva directiva nos permite sobrescribir las directivas "script-src" existentes. Con este conocimiento, deberíamos ser capaces de evadir en algunos casos las CSP.
