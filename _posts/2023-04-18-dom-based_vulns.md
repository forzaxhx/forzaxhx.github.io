---
title: DOM-Based Vulnerabilities
date: 2023-04-18
categories: [Vulnerabilities, Web]
tags: [dom, vulnerabilities, code_injection, web]
comments: false
---

El DOM o modelo de objeto de documento es la representación jerárquica de un navegador web de los elementos de la página. Los sitios web pueden usar JS para manipular los objetos y nodos del DOM, así como sus propiedades. La manipulación del DOM no es perjudicial como tal. De hecho, es un elemento base de funcionamiento de los sitios web. Pero el JS que maneja los datos de manera insegura puede permitir varios ataques. Este tipo de vulnerabilidades surgen cuando un sitio web contiene JS que toma un valor controlable por el usuario final, conocido como fuente, y lo pasa a una acción peligrosa, conocida como sumidero.

## Vulnerabilidades Taint-Flow
Muchas de estas vulnerabilidades se sirven de problemas con la forma en que el código del lado del cliente manipula los datos.

## Que es el Taint-Flow
Para explotar o mitigar estas vulnerabilidades, es importante que primero nos familiaricemos con los siguientes 2 conceptos:
- Fuente: Propiedad de JS que acepta datos que están potencialmente controlados por un atacante. Un ejemplo de una fuente es la propiedad "location.search" porque lee la entrada de la cadena de consulta, que es relativamente fácil de controlar para un atacante. Esto incluye la URL de referencia (expuesta por la cadena "document.referrer"), las cookies del usuarios (expuestas por la cadena "document.cookie") y los mensajes web
- Sumidero: Funcion de JS potencialmente peligrosa o un objeto del DOM que puede causar efectos no deseados si se pasan datos controlados por un atacante. Por ejemplo, la función "eval()" es un sumidero porque procesa el argumento que se le pasa como JS. Un ejemplo de un sumidero HTML es "document.body.innerHTML" porque potencialmente permite que un atacante inyecte HTML malicioso y ejecute JS arbitrario.

Las vulnerabilidades basadas en DOM surgen cuando un sitio web pasa datos de una fuente a un sumidero, que luego maneja los datos de manera insegura en el contexto de la sesión del cliente.

La fuente más común es la URL, a la que normalmente se accede con el objeto "location". Podemos construir un enlace para enviar a una víctima a una página vulnerable con un payload de consulta y fragmentar partes de la URL. Teniendo en cuenta el siguiente código:
```
goto = location.hash.slice(1)
if (goto.startsWith('https:')) {
  location = goto;
}
```
Esto es vulnerable a una redirección abierta basada en DOM porque la fuente "location.hash" se maneja de forma insegura. Si la URL contiene un fragmento HASH que comienza con "https:", este código extrae el valor de la propiedad "location.hash" y lo establece como propiedad "location" de "window". Podríamos aprovechar esta vulnerabilidad construyendo la siguiente URL:
```
https://www.innocent-website.com/example#https://www.evil-user.net
```
Cuando una víctima visita esta URL, JS establece el valor de la propiedad "location" en "https://www.evil-user.net", lo que automáticamente redirige a la víctima al sitio malicioso. Este comportamiento podría explicarse fácilmente para construir un ataque de phising.

## Fuentes comunes
```
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

## Sumideros comunes
| DOM-based vulnerability 						          | Sink 						          |
|-----------------------------------------------|:--------------------------|
| DOM XSS										                    | document.write() 			    |
| Redirección abierta 							            | windows.location 			    |
| Manipulación de cookies						            | document.cookie 			    |
| Inyección de JS 								              | eval() 					          |
| Manipulación de dominios de documentos 		    | document.domain 			    |
| Envenenamiento de WebSocket-URL 				      | WebSocket() 				      |
| Manipulación de enlaces 						          | element.src 				      |
| Manipulación de mensajes web 					        | postMessage()				      |
| Manipulación de encabezado de solicitud AJAX 	| setRequestHeader() 		    |
| Manipulación de rutas de archivos locales 	  | FileReader.ReadAsText()   |
| Inyeccion SQL del lado del cliente 			      | ExecuteSql() 				      |
| Manipulación de almacenamiento HTML5 			    | sessionStorage.setItem()  |
| Inyección XPath del lado del cliente 			    | document.evaluate() 		  |
| Inyeccion JSON del lado del cliente 			    | JSON.parse() 				      |
| Manipulación de datos DOM 					          | element.setAttribute() 	  |
| Negación de servicio 							            | RegExp() 					        |

## DOM Clobbering
La destrucción de DOM es una técnica avanzada en la que se inyecta HTML en la página para manipular el DOM y, en última instancia, cambiar el comportamiento de JS en el sitio web. La forma más común de DOM Clobbering utiliza un elemento de anclaje para sobrescribir una variable global, que luego es utilizada por la aplicación web de una manera no segura, como generar una URL de secuencia de comandos dinámica.
