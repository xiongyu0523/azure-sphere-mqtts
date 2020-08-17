#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <applibs/log.h>
#include <applibs/networking.h>
#include <applibs/storage.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <mqtt.h>

#define MQTT_SERVER "broker.emqx.io"
#if defined(CLIENT_AUTENTICATION)
#define MQTT_PORT   "8884"
#else
#define MQTT_PORT   "8883"
#endif
#define PUB_TOPIC  "azsphere/deviceid/time"
#define SUB_TOPIC  "azsphere/deviceid/led"

static const char networkInterface[] = "wlan0";

/**
 * A simple program to that publishes the current time whenever ENTER is pressed.
 */
void publish_callback(void** unused, struct mqtt_response_publish* published)
{
    /* note that published->topic_name is NOT null-terminated (here we'll change it to a c-string) */
    char* topic_name = (char*)malloc(published->topic_name_size + 1);
    memcpy(topic_name, published->topic_name, published->topic_name_size);
    topic_name[published->topic_name_size] = '\0';

    Log_Debug("Received publish on topic ('%s'): %s\n", topic_name, (const char*)published->application_message);

    free(topic_name);
}

/**
 * A simple program to that publishes the current time whenever ENTER is pressed.
 */
void* client_refresher(void* client)
{
    struct timespec ts = { 0, 1000 * 1000 * 100 };

    while (1) {
        mqtt_sync((struct mqtt_client*)client);

        while ((-1 == nanosleep(&ts, &ts)) && (EINTR == errno));
    }

    return NULL;
}

static bool IsNetworkInterfaceConnectedToInternet(void)
{
    Networking_InterfaceConnectionStatus status;
    if (Networking_GetInterfaceConnectionStatus(networkInterface, &status) != 0) {
        if (errno != EAGAIN) {
            Log_Debug("ERROR: Networking_GetInterfaceConnectionStatus: %d (%s)\n", errno, strerror(errno));
            return false;
        }
        Log_Debug("WARNING: Not doing download because the networking stack isn't ready yet.\n");
        return false;
    }

    if ((status & Networking_InterfaceConnectionStatus_ConnectedToInternet) == 0) {
        Log_Debug("WARNING: no internet connectivity.\n");
        return false;
    }

    return true;
}

static bool wait_for_async_connection(int sockfd, int timeout)
{
    struct pollfd pfd;

    pfd.fd = sockfd;
    pfd.events = POLLOUT;

    int ret = poll(&pfd, 1, timeout);
    if (ret == 0) {
        Log_Debug("ERROR: Connection timeout\n");
        return false;
    } else if (ret < 0) {
        Log_Debug("ERROR: poll fail, reason = %d (%s)\n", errno, strerror(errno));
        return false;
    }

    int retVal = -1;
    socklen_t retValLen = sizeof(retVal);

    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &retVal, &retValLen) < 0) {
        Log_Debug("ERROR: getsockopt fail, reason = %d (%s)\n", errno, strerror(errno));
        return false;
    }

    if (retVal != 0) {
        Log_Debug("ERROR: SO_ERROR is %d\n", retVal);
        return false;
    }

    return true;
}


/**
 * A simple program to that publishes the current time whenever ENTER is pressed.
 */
int main(int argc, const char* argv[])
{
    int ret_status = -1;

    bool isInternetConnected = false;
    do {
        isInternetConnected = IsNetworkInterfaceConnectedToInternet();
    } while (isInternetConnected == false);

    /*
        Phase I: Open and connect a non blocking TCP socket to server
    */
    int sockfd;
    int rt;

    /* connect to server */
    struct sockaddr_storage addr;
    socklen_t sockaddr_len = sizeof(struct sockaddr_in);

    struct addrinfo hints;
    struct addrinfo* answer = NULL;

    memset(&addr, 0, sizeof(addr));
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(MQTT_SERVER, MQTT_PORT, &hints, &answer) < 0 || answer == NULL) {
        Log_Debug("no addr info for responder\n");
        return -1;
    }

    sockaddr_len = answer->ai_addrlen;
    memcpy(&addr, answer->ai_addr, sockaddr_len);
    freeaddrinfo(answer);

    sockfd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        Log_Debug("bad socket fd, out of fds?\n");
        return -1;
    }

    rt = connect(sockfd, (const struct sockaddr*)&addr, sockaddr_len);
    if ((rt != 0) && (errno != EINPROGRESS)) {
        Log_Debug("Responder tcp connect failed\n");
        close(sockfd);
        return -1;
    }

    if (!wait_for_async_connection(sockfd, 500)) {
        close(sockfd);
        return -1;
    }
    /*
        Phase II: Init WOLFSSL and setup TLS connection
    */

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int ret, err;
    char* ca_path = NULL;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create and initialize WOLFSSL_CTX */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx == NULL) {
        Log_Debug("ERROR: failed to create WOLFSSL_CTX\n");
        goto cleanupLabel;
    }

    /* Load root CA certificates full path */
    ca_path = Storage_GetAbsolutePathInImagePackage("certs/AAACertificateServiceRootCA.pem");
    if (ca_path == NULL) {
        Log_Debug("ERROR: the certificate path could not be resolved\n");
        goto cleanupLabel;
    }

    ret = wolfSSL_CTX_load_verify_locations(ctx, ca_path, NULL);
    if (ret != WOLFSSL_SUCCESS) {
        Log_Debug("ERROR: failed to load root certificate\n");
        goto cleanupLabel;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        Log_Debug("ERROR: failed to create WOLFSSL object\n");
        goto cleanupLabel;
    }

    /* Attach wolfSSL to the socket */
    if (wolfSSL_set_fd(ssl, sockfd) != WOLFSSL_SUCCESS) {
        Log_Debug("Error attaching socket fd to wolfSSL.\n");
        goto cleanupLabel;
    }

    /* Connect to wolfSSL on the server side, poll for non-blocking socket */
    do
    {
        ret = wolfSSL_connect(ssl);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    if (ret != WOLFSSL_SUCCESS) {
        Log_Debug("ERROR: wolfSSL_connect, reason = %d\n", wolfSSL_get_error(ssl, ret));
        goto cleanupLabel;
    }

    /*
        Phase III: Configure a MQTT client to talk to the server
    */

    /* setup a client */
    struct mqtt_client client;
    uint8_t sendbuf[2048]; /* sendbuf should be large enough to hold multiple whole mqtt messages */
    uint8_t recvbuf[1024]; /* recvbuf should be large enough any whole mqtt message expected to be received */
    mqtt_init(&client, ssl, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), publish_callback);
    /* Create an anonymous session */
    const char* client_id = NULL;
    /* Ensure we have a clean session */
    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    /* Send connection request to the broker. */
    mqtt_connect(&client, client_id, NULL, NULL, 0, NULL, NULL, connect_flags, 400);
    if (client.error != MQTT_OK) {
        Log_Debug("ERROR: %s\n", mqtt_error_str(client.error));
        goto cleanupLabel;
    }

    /* start a thread to refresh the client (handle egress and ingree client traffic) */
    pthread_t client_daemon;
    if (pthread_create(&client_daemon, NULL, client_refresher, &client)) {
        Log_Debug("ERROR: Failed to start client daemon.\n");
        goto cleanupLabel;
    }

    /* subscribe */
    mqtt_subscribe(&client, SUB_TOPIC, 0);

    /* get the current time */
    time_t timer;
    time(&timer);
    struct tm* tm_info = localtime(&timer);
    char timebuf[26];
    strftime(timebuf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    /* print a message */
    char application_message[256];
    snprintf(application_message, sizeof(application_message), "The time is %s", timebuf);
    Log_Debug("%s published : \"%s\"\n", argv[0], application_message);

    /* publish the time */
    mqtt_publish(&client, PUB_TOPIC, application_message, strlen(application_message) + 1, MQTT_PUBLISH_QOS_2);
    if (client.error != MQTT_OK) {
        Log_Debug("ERROR: %s\n", mqtt_error_str(client.error));
        mqtt_disconnect(&client);
        pthread_cancel(client_daemon);
        goto cleanupLabel;
    }

    while (1) {
        struct timespec ts = { 60, 0 };
        while ((-1 == nanosleep(&ts, &ts)) && (EINTR == errno));
    }

    mqtt_disconnect(&client);
    pthread_cancel(client_daemon);

    ret_status = 0;

cleanupLabel:
    free(ca_path);
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */

    return ret_status;       /* Return reporting a success              */
}
