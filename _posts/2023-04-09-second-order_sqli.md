---
title: Stored SQL Injection
date: 2023-04-09 01:00:00
categories: [Vulnerabilities, Web]
tags: [mysql, vulnerabilities, code_injection, web]
comments: false
---

La inyeccion SQL de primer orden surge cuando la aplicacion toma la entrada del usuario mediante una solicitud HTTP, y el procesamiento de la solicitud incorpora la entrada en una consulta SQL de manera insegura.
En la inyeccion SQL de segundo orden o Inyeccion SQL Almacenada, la aplicacion toma la entrada del usuario de una solicitud HTTP y la almacena para un uso futuro. Esto generalmente se hace colocando la entra en una base de datos, pero no surge ninguna vulnerabilidad en el punto donde se almacenan los datos. Mas tarde, al manejar una solicitudad HTTP diferentes, la aplicacion recupera los datos almacenados y los incorpora a la consulta SQL de forma no segura.

![img-description](/assets/img/samples/storedsqli.png)

La inyeccion SQL almacenada a menudo surge cuando los desarrolladores son conscientes de las conerabilidades de inyeccion SQL, manejando de manera segura la ubicacion inicial de la entrada en la base de datos. Cuando los datos se procesan posteriormente, se consideran seguros, ya que previamente se colocaron en la base de datos de forma segura. En este punto, los datos se manejan de forma insegura, por que desarrollador determiana que los datos son confiables.
