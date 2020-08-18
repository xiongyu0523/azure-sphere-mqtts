# azure-sphere-mqtts
This sample project shows how to port a 3rd party mqtt library on Azure Sphere and use wolfSSL api to secure the connection. The [MQTT-C](https://github.com/LiamBindle/MQTT-C) is a lightweight MQTT library written by portable C. By adding wolfSSL support in mqtt_pal.c portable layer, we can easily run it on sphere platform.

