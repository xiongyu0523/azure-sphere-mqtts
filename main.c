#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

#include "applibs_versions.h"
#include <applibs/log.h>
#include <applibs/networking.h>
#include <applibs/storage.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

#include "eventloop_timer_utilities.h"
#include "mqtt.h"

#define MQTT_SERVER "broker.emqx.io"
#if defined(CLIENT_AUTENTICATION)
#define MQTT_PORT   "8884"
#else
#define MQTT_PORT   "8883"
#endif
#define PUB_TOPIC  "azsphere/deviceid/time"
#define SUB_TOPIC  "azsphere/deviceid/led"

/// <summary>
/// Exit codes for this application. These are used for the
/// application exit code. They must all be between zero and 255,
/// where zero is reserved for successful termination.
/// </summary>
typedef enum {
    ExitCode_Success = 0,
    ExitCode_TermHandler_SigTerm = 1,
    ExitCode_TimerHandler_Consume = 2,
    ExitCode_Init_EventLoop = 3,
    ExitCode_Init_Timer = 4,
    ExitCode_Main_EventLoopFail = 5,
    ExitCode_Init_MQTT = 6
} ExitCode;

static void TerminationHandler(int signalNumber);
static void PubLocalTime(void);
static void TimerEventHandler(EventLoopTimer* timer);
static ExitCode InitHandlers(void);
static void CloseHandlers(void);

static EventLoop* eventLoop = NULL;
static EventLoopTimer* tmrHandle = NULL;
static const char networkInterface[] = "wlan0";

static volatile sig_atomic_t exitCode = ExitCode_Success;

static struct mqtt_client mqttClient;
static int sockfd = -1;
WOLFSSL_CTX* ctx = NULL;
WOLFSSL* ssl = NULL;

uint8_t sendbuf[2048]; /* sendbuf should be large enough to hold multiple whole mqtt messages */
uint8_t recvbuf[1024]; /* recvbuf should be large enough any whole mqtt message expected to be received */

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
 * mqtt_daemon who is actually deal with networt packets
 */
void* mqtt_daemon(void* client)
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
 * init MQTT conneciton and subscribe desired topics
 */
int initMQTT(const char *server, const char *port)
{
    int ret_status = -1;

    /*
        Phase I: Open and connect a non blocking TCP socket to server
    */
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

    if (getaddrinfo(server, port, &hints, &answer) < 0 || answer == NULL) {
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

    if (!wait_for_async_connection(sockfd, 10000)) {
        close(sockfd);
        return -1;
    }

    /*
        Phase II: Init WOLFSSL and setup TLS connection
    */

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
        free(ca_path);
        goto cleanupLabel;
    }

    free(ca_path);

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
    mqtt_init(&mqttClient, ssl, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), publish_callback);
    /* Create an anonymous session */
    const char* client_id = NULL;
    /* Ensure we have a clean session */
    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    /* Send connection request to the broker. */
    mqtt_connect(&mqttClient, client_id, NULL, NULL, 0, NULL, NULL, connect_flags, 400);
    if (mqttClient.error != MQTT_OK) {
        Log_Debug("ERROR: %s\n", mqtt_error_str(mqttClient.error));
        goto cleanupLabel;
    }

    /* start a thread to refresh the client (handle egress and ingree client traffic) */
    pthread_t client_daemon;
    if (pthread_create(&client_daemon, NULL, mqtt_daemon, &mqttClient)) {
        Log_Debug("ERROR: Failed to start client daemon.\n");
        goto cleanupLabel;
    }

    /* subscribe */
    mqtt_subscribe(&mqttClient, SUB_TOPIC, 0);

    return 0;

cleanupLabel:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */

    return -1;              /* Return reporting a success               */
}

/// <summary>
///     Signal handler for termination requests. This handler must be async-signal-safe.
/// </summary>
static void TerminationHandler(int signalNumber)
{
    // Don't use Log_Debug here, as it is not guaranteed to be async-signal-safe.
    exitCode = ExitCode_TermHandler_SigTerm;
}


/// <summary>
///     The timer event handler.
/// </summary>
static void PubLocalTime(void)
{
    /* get the current time */
    time_t timer;
    time(&timer);
    struct tm* tm_info = localtime(&timer);
    char timebuf[26];
    strftime(timebuf, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    /* print a message */
    char application_message[256];
    snprintf(application_message, sizeof(application_message), "The time is %s", timebuf);
    Log_Debug("Published : \"%s\"\n", application_message);

    /* publish the time */
    mqtt_publish(&mqttClient, PUB_TOPIC, application_message, strlen(application_message) + 1, MQTT_PUBLISH_QOS_0);
    if (mqttClient.error != MQTT_OK) {
        Log_Debug("ERROR: %s\n", mqtt_error_str(mqttClient.error));
    }
}

/// <summary>
///     The timer event handler.
/// </summary>
static void TimerEventHandler(EventLoopTimer* timer)
{
    if (ConsumeEventLoopTimerEvent(timer) != 0) {
        exitCode = ExitCode_TimerHandler_Consume;
        return;
    }

    PubLocalTime();
}

/// <summary>
///     Set up SIGTERM termination handler and event handlers.
/// </summary>
/// <returns>
///     ExitCode_Success if all resources were allocated successfully; otherwise another
///     ExitCode value which indicates the specific failure.
/// </returns>
static ExitCode InitHandlers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = TerminationHandler;
    sigaction(SIGTERM, &action, NULL);

    eventLoop = EventLoop_Create();
    if (eventLoop == NULL) {
        Log_Debug("Could not create event loop.\n");
        return ExitCode_Init_EventLoop;
    }

    static const struct timespec tenSeconds = { .tv_sec = 10, .tv_nsec = 0 };
    tmrHandle = CreateEventLoopPeriodicTimer(eventLoop, &TimerEventHandler, &tenSeconds);
    if (tmrHandle == NULL) {
        return ExitCode_Init_Timer;
    }

    if (initMQTT(MQTT_SERVER, MQTT_PORT) < 0) {
        return ExitCode_Init_MQTT;
    }

    return ExitCode_Success;
}

/// <summary>
///     Clean up the resources previously allocated.
/// </summary>
static void CloseHandlers(void)
{
    DisposeEventLoopTimer(tmrHandle);
    EventLoop_Close(eventLoop);
}

/// <summary>
///     Main entry point for this sample.
/// </summary>
int main(int argc, char* argv[])
{
    Log_Debug("MQTT over TLS client demo on Azure Sphere\n");
    Log_Debug("Minimum required API set is 6 on 20.07 OS\n");

    bool isInternetConnected = false;
    do {
        isInternetConnected = IsNetworkInterfaceConnectedToInternet();
    } while (isInternetConnected == false);

    exitCode = InitHandlers();
    if (exitCode == ExitCode_Success) {
        PubLocalTime();
    }

    // Use event loop to wait for events and trigger handlers, until an error or SIGTERM happens
    while (exitCode == ExitCode_Success) {
        EventLoop_Run_Result result = EventLoop_Run(eventLoop, -1, true);
        // Continue if interrupted by signal, e.g. due to breakpoint being set.
        if (result == EventLoop_Run_Failed && errno != EINTR) {
            exitCode = ExitCode_Main_EventLoopFail;
        }
    }

    CloseHandlers();
    Log_Debug("Application exiting.\n");
    return exitCode;
}
