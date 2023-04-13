---
title: CSRF-token evasion
date: 2023-04-13
categories: [Vulnerabilities, Web]
tags: [csrf, vulnerabilities, code_injection, web]
comments: false
---

Un token CSRF es un valor único, secreto e impredecible que genera la aplicación del lado del servidor y se comparte con el cliente. Al emitir una solicitud para realizar una acción confidencial, como enviar un formulario, el cliente debe incluir el token CSRF correcto. De lo contrario, el servidor se negara a realizar la acción solicitada.

Una forma común de compartir token CSRF con el cliente es incluirlos como un parámetro oculto en un formulario HTML, por ejemplo:
```
<form name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="example@normal-website.com">
    <input required type="hidden" name="csrf" value="50FaWgdOhi9M9wyna8taR1k3ODOR8d6u">
    <button class='button' type='submit'> Update email </button>
</form>
```
EL envío de este formulario da como resultado la siguiente solicitud:
```
POST /my-account/change-email HTTP/1.1
Host: normal-website.com
Content-Length: 70
Content-Type: application/x-www-form-urlencoded

csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=example@normal-website.com
```

Cuando se implementan correctamente, los tokens CSRF ayudan a proteger contra los ataques CSRF al dificultar que construyamos una solicitud válida en nombre de la víctima. Como no tenemos forma de predecir el valor correcto del token CSRF, no podrá incluirlo en la solicitud maliciosa.

## Defectos comunes en la validación del token CSRF
Las vulnerabilidades CSRF generalmente surgen debido a una valoración defectuosa de los tokens CSRF. En esta sección, cubriremos algunos de los problemas más comunes que nos permiten eludir estas defensas.

## Validación del token CSRF depende del modelo de solicitud 
Algunas aplicaciones validan correctamente el token cuando la solicitud utiliza el método POST, pero emiten la validación cuando se utiliza el método GET.

En esta situación, podemos cambiar el método GET para eludir la validación y lanzar un ataque CSRF:
```
GET /email/change?email=pwned@evil-user.net HTTP/1.1
Host: vulnerable-website.com
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm
```

## La validación del token CSRF depende de la presencia del token
Algunas aplicaciones validan correctamente el token cuando está presente, pero omiten la validación si se omite el token.

En esta situación, podemos eliminar todo el parámetro que contiene el token para eludir la validación y lanzar un ataque CSRF:
```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

email=pwned@evil-user.net
```

## El token CSRF no está vinculado a la sesión del usuario
Algunas aplicaciones no validan que el token pertenezca a la misma sesión que el usuario que realiza la solicitud. En su lugar, la aplicación mantiene un grupo global de tokens que he emitido y acepta cualquier token que aparezca en este grupo.

En esta situación, podemos iniciar sesión en la aplicación con su propia cuenta, obtener un token válido y luego enviar ese token al usuario víctima en su ataque CSRF.

## El token CSRF está vinculado a una cookie que no es de sesion
En una variación de la vulnerabilidad anterior, algunas aplicaciones vinculan el token CSRF a una cookie, pero no a la misma cookie que se usa para rastrear sesiones. Esto puede ocurrir fácilmente cuando una aplicación emplea dos marcos diferentes, uno para el manejo de sesiones y otro para la protección CSRF, que no están integrados entre sí:
```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv

csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```
Esta situación es más difícil de explotar, pero sigue siendo vulnerable. Si el sitio web contiene algún comportamiento que permite que establezcamos una cookie en el navegador de la víctima, entonces es posible un ataque. Podemos iniciar sesión en la aplicación, obtener un token válido y  una cookie asociada, aprovechar el comportamiento de configuración de cookies para colocar su cookie en el navegador de la víctima y enviar su token a la víctima en su ataque CSRF.

## El token CSRF simplemente se duplica en una cookie
En otra variación de la vulnerabilidad anterior, algunas aplicaciones no mantienen ningún registro del lado del servidor de los token que se han emitido, sino que duplican cada token dentro de una cookie y un parámetro de solicitud. Cuando se valida la solicitud posterior, la aplicación simplemente verifica que el token enviado en el parámetro de solicitud coincida con el valor enviado en la cookie. Esto a veces se denomina defensa de "doble envio" contra CSRF, y se recomienda porque es simplemente de implementar y evita la necesidad de cualquier estado del lado del servidor:
```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com
```

En esta situación, podemos volver a realizar un ataque CSRF si el sitio web contiene alguna funcionalidad de configuración de cookies. Aquí, no necesitamos obtener un token válido propio. Simplemente inventar un token, aprovechan el comportamiento de configuración de cookies para colocar su cookie en el navegador de la víctima y alimentan su token a la víctima en su ataque CSRF
