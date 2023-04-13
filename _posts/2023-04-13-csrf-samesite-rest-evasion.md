---
title: SameSite cookies restrictions evasion
date: 2023-04-13
categories: [Vulnerabilities, Web]
tags: [csrf, vulnerabilities, code_injection, web]
comments: false
---

SameSite es un mecanismo de seguridad del navegador que determina cuándo las cookies de un sitio web se incluyen en las solicitudes que se originan en otros sitios web. Las restricciones de cookies de Same Site brindan protección parcial contra una variedad de ataques entre sitios, incluidos CARD, filtraciones entre sitios y algunas vulnerabilidades de CORS.

## ¿Que es un sitio en el contexto de las cookies SameSite?
Un sitio se define como el dominio de nivel superior(TLD) generalmente algo como ".com" o ".net", más un nivel adicional del nombre de dominio. Esto a menudo se denomina TDL+1.

Al determinar si una solicitud es del mismo sitio o no, también se tiene en cuenta el esquema de URL. Esto significa que la mayoría de los navegadores tratan un enlace desde "http://app.example.com" como si fuera un sitio cruzado.

## ¿Cuál es la diferencia entre un sitio y un origen?
La diferencia radica en su enlace; un sitio abarca varios nombres de dominio, mientras que un origen solo incluye uno. Aunque están estrechamente relacionados, es importante no usar los términos indistintamente, ya que combinarlos puede tener serias implicaciones de seguridad.

Se considera que dos URL tienen el mismo origen si comparten exactamente el mismo esquema, nombre de dominio y puerto. Aunque tenga en cuenta que el puerto a menudo se deduce del esquema.

## ¿Cómo funciona SameSite?
Antes de que se introdujera este mecanismo, los navegadores enviaban cookies en cada solicitud al dominio que las emitía, incluso si la solicitud fue activada por un sitio web de un tercero no relacionado. SameSite funciona al permitir que los navegadores y los propietarios de sitios web limiten qué solicitudes entre sitios, si las hay, deben incluir cookies especificas. Esto puede ayudar a reducir la exposición de los usuarios a los ataques CSRF, que inducen al navegador de la víctima a emitir una solicitud que desencadena una acción dañina en el sitio web vulnerable. Como estas solicitudes generalmente requieren una cookie asociada con la sesión autenticada de la víctima, el ataque fallará si el navegador no la incluye.

Todos los principales navegadores actualmente admiten los siguientes niveles de restricciones SameSite:
- Strict
- Lax
- None

Los desarrolladores pueden configurar manualmente un nivel de restricción para cada cookie que establecen, dándoles más control sobre cuando se utilizan las cookies. Para hacer esto, solo tienen que incluir el atributo SameSite en el encabezado Set-Cookie de la respuesta, junto con su valor preferido:
```
Set-Cookie: session=0F8tgdOhi9ynR1M9wa3ODa; SameSite=Strict
```
Aunque esto ofrece cierta protección contra ataques CSRF, ninguna de estas restricciones proporciona inmunidad garantizada, como demostraremos utilizando laboratorios interactivos deliberadamente vulnerables más adelante en esta sección.

## Estricto
Si una cookie se establece con el atributo SameSite=Strict, los navegadores no la enviaran en ninguna solicitud entre sitios. En términos simples, esto significa que si el sitio de destino de la solicitud no coincide con el sitio que se muestra actualmente en la barra de direcciones del navegador, no incluirá la cookie.

## Lax
Estas restricciones SameSite significan que los navegadores enviaran la cookie en solicitudes entre sitios, pero solo si se cumplen las dos condiciones siguientes:
- La solicitud utiliza el método GET.
- La solicitud resultó de una navegación de nivel superior por parte del usuario, como hacer clic en un enlace.

Esto significa que la cookie no se incluye en las solicitudes entre sitios POST, por ejemplo. Dado que las solicitudes POST generalmente se utilizan para realizar acciones que modifican datos o estados es mucho más probable que sean el objetivo de ataques CSRF.

Asimismo, la cookie no se incluye en solicitudes en segundo plano, como las iniciadas en scripts, iframes o referencia a imágenes y otros recursos.

## None
Si una cookie se configura con el atributo SameSite=None, esto deshabilita las restricciones de SameSite por completo, independientemente del navegador. Como resultado, los navegadores enviaran esta cookie en todas las solicitudes al sitio que la emitió, incluso aquellas que fueron activadas por sitios de terceros completamente relacionados.

Con la excepción de Chrome, este es el comportamiento predeterminado que utilizan los principales navegadores si SameSite no proporciona ningún atributo al configurar la cookie.

Existen razones legítimas para deshabilitar SameSite, como cuando la cookie está destinada a ser utilizada desde un contexto de terceros y no otorga al portador acceso a ningún dato o funcionalidad confidencial. Las cookies de seguimiento son un ejemplo típico.

Si encuentra un conjunto de cookies con SameSite=None o sin restricciones explícitas, vale la pena investigar si es de alguna utilidad. Cuando Chorme adoptó por primera vez el comportamiento "Lax-by-default", esto tuvo el efecto secundario de romper muchas de las funciones web existentes. Como solución rápida, algunos sitios web optaron por deshabilitar simplemente las restricciones de SameSite en todas las cookies, incluidas las potencialmente confidenciales.

Al configurar una cookie con SameSite=None, el sitio web también debe incluir el atributo Secure, lo que garantiza que la cookie solo se envía en mensajes cifrados a través de HTTPS. De lo contrario, los navegadores rechazan la cookie y no se configura.
```
Set-Cookie: trackingId=0F8tgdOhi9ynR1M9wa3ODa; SameSite=None; Secure
```    

## Omitir las restricciones de SameSite Lax mediante solicitudes GET
En la práctica, los servidores no siempre son quisquillosos con respecto a si reciben GET o POST, incluso aquellos que esperan el envío de un formulario. Si también usan restricciones Lax para sus cookies de sesión, ya sea explícitamente o debido a la configuración predeterminada del navegador, aún puede realizar un ataque CSRF al obtener una solicitud GET del navegador de la víctima.

Siempre que la solicitud implique una navegación de nivel superior, el navegador seguirá incluyendo la cookie de sesión de la víctima. El siguiente es uno de los enfoques más simples para lanzar un ataque de este tipo:
```
<script>
    document.location = 'https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000';
</script>
``` 
Incluso si no se permite una solicitud GET ordinaria, algunos marcos proporcionan formas de anular el método especificado en la línea de solicitud. Por ejemplo, Symfony admite el parámetro "_method" en formularios, que tiene prioridad sobre el método normal a efectos de enrutamiento.
```
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
    <input type="hidden" name="_method" value="GET">
    <input type="hidden" name="recipient" value="hacker">
    <input type="hidden" name="amount" value="1000000">
</form>
```
Otros marcos admiten una variedad de parámetros similares.

## Omitir la restricciones de SameSite usando dispositivos en el sitio
Si una cookie se establece con el atributo SameSite=Strict, los navegadores no la incluyen en ninguna solicitud entre sitios. Es posible que pueda sortear esta limitación si puede encontrar un gadget que genere una solicitud que genere una solicitud secundaria dentro del mismo sitio.

Un posible gadget es una redirección del lado del cliente que construye dinámicamente el objetivo de la redirección utilizando una entrada controlable por el atacante, como parámetros de URL. Para ver algunos ejemplos, consulte nuestros materiales sobre la redirección abierta basada en DOM.

En lo que respecta a los navegadores, estos redireccionamientos del lado del cliente no son realmente redireccionamiento en absoluto; la solicitud resultante se trata simplemente como una solicitud normal e independiente. Lo que es más importante, esta es una solicitud del mismo sitio y, como tal, incluirá todas las cookies relacionadas con el sitio, independientemente de las restricciones vigentes.

Tengamos en cuenta que el ataque equivalente no es posible con redireccionamientos del lado del servidor. En este caso, los navegadores reconocen que la solicitud para seguir la redirección resultó inicialmente de una solicitud entre sitios, por lo que aún aplican las restricciones de cookies apropiadas.

## Eludir las restricciones de SameSite a través de dominios hermanos vulnerables
Ya sea que esté probando el sitio web de otra persona o tratando de proteger el suyo propio, es esencial tener en cuenta que una solicitud aún puede ser del mismo sitio, incluso si se emite de origen cruzado.

Nos aseguramos de auditar minuciosamente toda la superficie de ataque disponible, incluso los dominios hermanos. En particular, las vulnerabilidades que le permiten obtener una solicitud secundaria arbitraria, como XSS, pueden comprometer completamente las defensas basadas en el sitio, exponiendo todos los dominios del sitio a ataques entre sitios.

Además del CSRF clásico, no olvidemos que si el sitio web de destino es compatible con WebSockets, esta funcionalidad podría ser vulnerable al secuestro de WebSocket entre sitios(CSWSH), que es esencialmente sólo un ataque CSRF dirigido a un protocolo de enlace WebSocket.

## Omitir las restricciones de SameSite Lax con cookies recién emitidas
Las cookies con restricciones "Lax" de SameSite normalmente no se envían en ninguna solicitud POST entre sitios, pero hay algunas excepciones.

Como se mencionó anteriormente, si un sitio web no incluye un atributo SameSite al configurar una cookie, Chrome aplica restricciones "Lax" automáticamente de forma predeterminada. Sin embargo, para evitar romper los mecanismos de inicio de sesión único(SSO), en realidad no aplica las restricciones durante los primeros 120 segundos de las solicitudes POST de nivel superior. Como resultado, existe una ventana de dos minutos en la que los usuarios pueden ser susceptibles a ataques entre sitios.

Es algo poco práctico intentar cronometrar el ataque para que caiga dentro de esta breve ventana. Por otro lado, si podemos encontrar un dispositivo en el sitio que le permite obligar a la víctima a recibir una nueva cookie de sesión, puede actualizar su cookie de forma preventiva antes de continuar con el ataque principal. Por ejemplo, completar un flujo de inicio de sesión basado en "OAuth" puede dar como resultado una nueva sesión cada vez que el servicio "OAuth" no necesariamente sabe si el usuario todavía está conectado al sitio de destino.

Para activar la actualización de la cookie sin que la víctima tenga que volver a iniciar sesión manualmente, debe utilizar una navegación de nivel superior, lo que garantiza que se incluyan las cookies asociadas con su sesión actual de "OAuth". Esto plantea un desafío adicional porque luego debe redirigir al usuario a su sitio para que pueda lanzar el ataque CSRF.

Alternativamente, podemos activar la actualización de cookies desde una nueva pestaña para que el navegador no abandone la página antes de que pueda realizar el ataque final. Un inconveniente menor con este enfoque es que los navegadores bloquean las pestañas emergentes a menos que se abran mediante una interacción manual. Por ejemplo, el navegador bloqueara la siguiente ventana emergente de forma predeterminada:
```
window.open('https://vulnerable-website.com/login/sso');
```  
Para evitar esto podemos envolver la declaración en un controlador "onclick" de eventos de la siguiente manera:
```
window.onclick = () => {
    window.open('https://vulnerable-website.com/login/sso');
}
```
De esta manera. El método "window.open()" solo se invoca cuando el usuario hace clic en algún lugar de la página.

