---
title: Stored SQL Injection
date: 2023-04-09
categories: [Vulnerabilities, Web]
tags: [sql, vulnerabilities, code_injection, web]
comments: false
---

La inyección SQL de primer orden surge cuando la aplicación toma la entrada del usuario mediante una solicitud HTTP, y el procesamiento de la solicitud incorpora la entrada en una consulta SQL de manera insegura.
En la inyección SQL de segundo orden o Inyección SQL Almacenada, la aplicación toma la entrada del usuario de una solicitud HTTP y la almacena para un uso futuro. Esto generalmente se hace colocando la entrada en una base de datos, pero no surge ninguna vulnerabilidad en el punto donde se almacenan los datos. Más tarde, al manejar una solicitud HTTP diferente, la aplicación recupera los datos almacenados y los incorpora a la consulta SQL de forma no segura.

![img-description](/assets/img/samples/storedsqli.png)

La inyección SQL almacenada a menudo surge cuando los desarrolladores son conscientes de las contabilidades de inyección SQL, manejando de manera segura la ubicación inicial de la entrada en la base de datos. Cuando los datos se procesan posteriormente, se consideran seguros, ya que previamente se colocaron en la base de datos de forma segura. En este punto, los datos se manejan de forma insegura, porque desarrollador determina que los datos son confiables.
