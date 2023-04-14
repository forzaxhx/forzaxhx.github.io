---
title: Clickjacking
date: 2023-04-14
categories: [Vulnerabilities, Web]
tags: [clickjacking, vulnerabilities, code_injection, web]
comments: false
---

El clickjacking es un ataque basado en la interfaz en el que se engaña a un usuario para que haga clic en contenido procesable en un sitio web oculto al hacer clic en otro contenido en un sitio web señuelo. 

Por ejemplo: Un usuario web accede a un sitio web señuelo, como un sitio web al que acceden debido a que se les proporciona un enlace por correo, y hace clic en un botón para ganar un premio. Sin saberlo, un atacante los engañó para que presionaran un botón oculto alternativo y esto resultó en el pago de una cuenta en otro sitio. Este es un ejemplo de un ataque de clickjacking. La técnica depende de la incorporación de una o varias páginas web visibles y procesables que contengan un botón o enlace oculto, por ejemplo, dentro de un iframe. El iframe se superpone sobre el contenido de la página web de señuelo del usuario. Este ataque se diferencia de un ataque de CSRF en que se requiere que el usuario realice una acción, como hacer clic en un botón, mientras que un ataque CSRF depende de la falsificación de una solicitud completa sin el conocimiento o la entrada del usuario.

La protección contra este tipo de ataques a menudo se proporciona mediante el uso de un token CSRF: un token específico de sesión, un token de un solo uso o ambos. El token CSRF no mitiga los ataques de clickjacking, ya que se establece una sesión de destino con contenido cargado desde un sitio web auténtico y con todas las solicitudes que se realizan en el dominio. Los tokens CSRF se colocan en las solicitudes y se pasan al servidor como parte de una sesión de comportamiento normal. La diferencia en el comportamiento con una sesión normal de usuario es que el proceso ocurre dentro de un iframe oculto.

## Como contruir un ataque de clickjacking básico
Los ataques de clickjacking usan CSS para crear y manipular capas. Incorporamos el sitio web objetivo como una capa de iframe superpuesta en el sitio web señuelo. Un ejemplo sería el siguiente:
```
<head>
	<style>
		#target_website {
			position:relative;
			width:128px;
			height:128px;
			opacity:0.00001;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:300px;
			height:400px;
			z-index:1;
			}
	</style>
</head>
...
<body>
	<div id="decoy_website">
	...decoy web content here...
	</div>
	<iframe id="target_website" src="https://vulnerable-website.com">
	</iframe>
</body>
```

El iframe del sitio web de destino se coloca dentro del navegador para que haya una superposición precisa de la acción de destino con el sitio web señuelo utilizando los valores de posición de ancho y alto adecuados. Los valores de posición absoluta y relativa se utilizan para garantizar que el sitio web destino se superponga con precisión al señuelo, independientemente del tamaño de la pantalla y la plataforma. El índice z determina el orden de apilamiento de las capas de iframe y sitio web. El valor de opacidad se define como 0,0 para que el contenido del iframe sea transparente para el usuario. La protección para el clickjacking del navegador podrá aplicar una detección de transparencia de iframe basada en umbrales. Seleccionamos valores de opacidad para que se logre el efecto deseado sin desencadenar comportamientos de protección.

## Clickbandit
Aunque se pueden crear manualmente pruebas de concepto de clickjacking como se describió anteriormente, esto puede ser tedioso y llevar mucho tiempo y práctica. Cuando estamos probando el clickjacking en la vida real, es recomendable que utilicemos la herramienta Click Bandit de Burp Suite. Esto permite usar el navegador para realizar las acciones deseadas en la página enmarcable, luego creamos un archivo HTML que contiene una superposición de clickjacking adecuada. Podemos usar esto para general una PoC interactiva en cuestión de segundos, sin tener que escribir una sola línea de HTML o CSS.

## Clickjacking con entrada de formulario prellenado
Algunos sitios web que requieren que se completen y envíen formularios permiten el llenado previo de las entradas del formulario mediante parámetros GET antes del envío. Otros sitios web pueden requerir texto antes de enviar el formulario. Como los valores GET forman parte de la URLs , la URL de destino se puede modificar para incorporar los valores que elijamos y el botón transparente "enviar" se superpone en el sitio señuelo como en el ejemplo básico de clickjacking.

## Guiones de ruptura de marcos
Este tipo de ataques son posibles siempre que los sitios web puedan ser enmarcados. Por lo tanto, las técnicas preventivas se basan en restringir la capacidad de encuadre de los sitios web. Una protección común del lado del cliente promulgada a través del navegador web es usar secuencias de comandos de ruptura de marcos. Estos se pueden implementar a través de complementos o extensiones de JS del navegador propietario, como NoScript. Los scripts a menudo se diseñan para que realicen algunos todos los siguientes comportamiento:
- Verificar y hacer cumplir que la ventana de la aplicación actual sea la ventana principal superior.
- Hacer visibles todos los marcos.
- Evitar hacer click en marcos invisibles.
- Interceptar y señalar posibles ataques de clickjacking al usuario.

Las técnicas de destrucción de marcos a menudo son específicas por navegador y la plataforma y, debido a la flexibilidad de HTML, podemos generalmente eludir estas comprobaciones. Como los destructores de marcos son JS, la configuración de seguridad del navegador puede impedir su funcionamiento o, de hecho, es posible que el navegador ni siquiera sea compatible con JS. Una solución efectiva contra los destructores de marcos es utilizar un atributo iframe "Sandbox" de HTML5. Cuando esto se establece con los valores "allow-forms" y o se omite el valor, el script de destrucción de marcos se puede neutralizar ya que el iframe no puede verificar si el o no la ventana superior: "allow-scripts allow-top-navigation".
```
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```  
Tanto los valores "allow-forms" como los "allow-scripts" permiten las acciones específicas dentro del iframe pero la navegación del nivel superior está deshabilitada. Esto inhibe los comportamientos de ruptura de marcos al tiempo que permite la funcionalidad dentro del sitio objetivo.

## Combinación de clickjacking con DOM-Based XSS
La verdadera potencia del clickjacking se revela cuando se utiliza como portador de otro ataque, como podría ser el DOM XSS. La implementación de este ataque combinado es relativamente sencilla, suponiendo que hayamos identificado primero el exploit XSS. El exploit CSS luego se combina con la URL de destino del iframe para que el usuario haga click en el botón o enlace y, en consecuencia, ejecute el ataque DOM XSS.

## Clickjacking de varios pasos
La manipulación de las entradas a un sitio web de destino puede requerir múltiples acciones. Por ejemplo, un atacante podría querer engañar a un usuario para que compre algo en un sitio web minorista, por lo que los artículos deben agregarse a una cesta de la compra antes de realizar el pedido. Estas acciones pueden ser implementadas por el atacante usando múltiples divisiones o iframes. Dichos ataques requieren una precisión y cuidado considerables desde nuestra perspectiva para que sean efectivos y sigilosos.

