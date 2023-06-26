#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>

int file;
char info[1024];
char timestr[300];

void printLog(char* info) {
	printf("%s", info);
	file = fopen("log", "a+");
	fprintf(file, "%s", info);
	fclose(file);
}

/*tlsclient.c*/
/* define HOME to be dir for key and cert files... */
#define HOME	"./cert/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
        sprintf(info, "[info]  认证通过!\n");
        system("echo `date` >> log");
		printLog(info);
    }
    else {
       int err = X509_STORE_CTX_get_error(x509_ctx);

       if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
           sprintf(info, "[info]  忽略认证结果: %s.\n", X509_verify_cert_error_string(err));
           system("echo `date` >> log");
		    printLog(info);
           return 1;
		}

        sprintf(info, "[fail]  认证失败: %s.\n", X509_verify_cert_error_string(err));
        system("echo `date` >> log");
		printLog(info);
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

#if 0
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif  
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
	ERR_print_errors_fp(stderr);
	exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
	ERR_print_errors_fp(stderr);
	exit(-3);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        sprintf(info, "[fail]  私钥不匹配证书的公钥!\n");
        system("echo `date` >> log");
		printLog(info);
        exit(-4);
    }
    ssl = SSL_new(ctx);

    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}

int setupTCPClient(const char* hostname, int port)
{
    struct sockaddr_in server_addr;

    // Get the IP address from hostname
    struct hostent *hp = gethostbyname(hostname);

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Fill in the destination information (IP, port #, and family)
    memset(&server_addr, '\0', sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    //server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;

    // Connect to the destination
    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    return sockfd;
}
/*tlsclient.c*/

/*vpnclient.c*/
int createTunDevice() {
    int tunfd;
    struct ifreq ifr;
    int ret;
     
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunfd = open("/dev/net/tun", O_RDWR);		// 打开TUN设备
	if (tunfd == -1) {
        sprintf(info, "[fail]	打开/dev/net/tun失败! (%d: %s)\n", errno, strerror(errno));
        system("echo `date` >> log");
		printLog(info);
        return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);		// 设置TUN设备
	if (ret == -1) {
        sprintf(info, "[fail]  设置TUN接口失败! (%d: %s)\n", errno, strerror(errno));
        system("echo `date` >> log");
		printLog(info);
        return -1;
	}

    sprintf(info, "[info]  成功启动TUN接口!\n");
    system("echo `date` >> log");
    printLog(info);
    ioctl(tunfd, TUNSETIFF, &ifr);

    return tunfd;
}
/*vpnclient.c*/

typedef struct thread_data{
    int tunfd;
    SSL *ssl;
}THDATA,*PTHDATA;


char* last;

void* listen_tun(void* threadData)
{
    PTHDATA ptd = (PTHDATA) threadData;
    while (1)
    {
        int len;
        char buff[2000];

        bzero(buff, 2000);
        len = read(ptd->tunfd, buff, 2000);		// 从TUN设备读取数据
        if (len > 19 && buff[0] == 0x45)
        {
            if ((int) buff[15] == atoi(last))
			{
                sprintf(info, "[info]  接收到TUN传来的数据，长度为%3d\n", len);
                system("echo `date` >> log");
		        printLog(info);
                SSL_write(ptd->ssl, buff, len);
            }
            else
            {
                sprintf(info, "[error] 错误的IP地址: 192.168.53.%s", last);
                system("echo `date` >> log");
		        printLog(info);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    /*vpnclient.c*/
    char* hostname = "yuanzhongsheng";
    int port = 4433;
    
    char us[100];
    char ps[100];
    char iipp[100];    

    hostname = argv[1];
    port = atoi(argv[2]);

	printf("\
                           _ _            _   \n\
                          | (_)          | |\n\
 __   ___ __  _ __     ___| |_  ___ _ __ | |_\n\
 \\ \\ / / '_ \\| '_ \\   / __| | |/ _ \\ '_ \\| __|\n\
  \\ V /| |_) | | | | | (__| | |  __/ | | | |_\n\
   \\_/ | .__/|_| |_|  \\___|_|_|\\___|_| |_|\\__|\n\
       | |\n\
       |_|   \n");
	printf("请输入您的用户名：\n> ");
    scanf("%s",us);
    getchar();
	printf("请输入您的用户名密码: \n> ");
	system("stty -echo");
	scanf("%s",ps);
	system("stty echo");
	getchar();
	printf("\n");
	// printf("Input the tun ip:192.168.53.");
    // scanf("%s",iipp);
    // getchar();
    // last=iipp;

    /*----------------TLS initialization -----------------------*/
    SSL *ssl = setupTLSClient(hostname);

    /*----------------Create a TCP connection ------------------*/
    int sockfd = setupTCPClient(hostname, port);

    /*----------------TLS handshake ----------------------------*/
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    
    CHK_SSL(err);

    sprintf(info, "[info]  SSL连接成功，使用%s加密算法\n", SSL_get_cipher(ssl));
    system("echo `date` >> log");
    printLog(info);
    /*vpnclient.c*/

    SSL_write(ssl, us, strlen(us));
    SSL_write(ssl, ps, strlen(ps));
	// SSL_write(ssl, last, strlen(last));
	char ip[100];
	ip[SSL_read(ssl, ip, sizeof(ip) - 1)] = '\0';
    sprintf(info, "[info]  您的tun ip为192.168.53.%s\n", ip);
    system("echo `date` >> log");
    printLog(info);
    last = ip;

    /*----------------Send/Receive data -------------------------*/
    int tunfd = createTunDevice();
    pthread_t listen_tun_thread;
    THDATA threadData;
    threadData.tunfd = tunfd;
    threadData.ssl = ssl;
    pthread_create(&listen_tun_thread, NULL, listen_tun, (void*) &threadData);  // 创建线程监听TUN设备

    // redirect and routing
    char cmd[100];
	sprintf(cmd, "sudo ifconfig tun0 192.168.53.%s/24 up && sudo route add -net 192.168.60.0/24 tun0", ip);
    sprintf(info, "[info]  成功开启网卡并设置路由表\n");
    system("echo `date` >> log");
    printLog(info);
    system(cmd);

    int len;
    do
    {
        char buf[9000];
        len = SSL_read(ssl, buf, sizeof(buf) - 1);  // 接收数据
        write(tunfd, buf, len);
        sprintf(info, "[info]  接收到SSL传来的数据，长度为%3d\n", len);
        system("echo `date` >> log");
		printLog(info);
    } while (len > 0);
    pthread_cancel(listen_tun_thread);
    sprintf(info, "[info]  关闭连接\n");
    system("echo `date` >> log");
    printLog(info);
    return 0;
}

