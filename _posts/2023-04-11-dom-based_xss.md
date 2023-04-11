---
title: DOM-based XSS
date: 2023-04-11
categories: [Vulnerabilities, Web]
tags: [xss, vulnerabilities, code_injection, web]
comments: false
---

Este tipo de XSS aplica cuando una aplicación web contiene JS del lado del cliente que procesa los datos de una fuente que no es de confianza de una manera no segura, normalmente reescribiendo los datos nuevamente en el DOM.

Por ejemplo, una aplicación usa JS para leer el valor de un campo introducido por el usuario y escribir ese valor en un elemento dentro del HTML:
```
var search = document.getElementById('search').value;
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;
```
Si podemos controlar el valor del campo de entrada, podremos construir fácilmente una inyeccion maliciosa que haga que se ejecute el propio script:
```
You searched for: <img src=1 onerror='/* Codigo Malicioso... */'>
```
En un caso típico, el campo de entrada se completaría con parte de la solicitud HTTP, como parámetro de cadena de consulta de URL, lo que nos permite realizar un ataque utilizando una URL maliciosa, como lo haríamos en el caso de explotar una XSS reflejada.
