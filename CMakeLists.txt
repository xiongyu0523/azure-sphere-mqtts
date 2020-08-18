#  Copyright (c) Microsoft Corporation. All rights reserved.
#  Licensed under the MIT License.

cmake_minimum_required (VERSION 3.10)

project (azure-sphere-mqtts C)

azsphere_configure_tools(TOOLS_REVISION "20.07")
azsphere_configure_api(TARGET_API_SET "6")

# include
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/MQTT-C/include)

# macro
add_compile_definitions(MQTT_USE_WOLFSSL)

# Create executable
add_executable (${PROJECT_NAME} main.c eventloop_timer_utilities.c MQTT-C/src/mqtt.c MQTT-C/src/mqtt_pal.c)
target_link_libraries (${PROJECT_NAME} applibs pthread gcc_s c wolfssl)

azsphere_target_add_image_package(${PROJECT_NAME} RESOURCE_FILES "certs/mosquitto.org.crt" "certs/client.crt" "certs/client.key")
