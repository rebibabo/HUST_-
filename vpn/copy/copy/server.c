
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <shadow.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

int file;
char info[1024];
char timestr[300];
/*vpnserver.c*/

void printLog(char* info) {
	printf("%s", info);
	file = fopen("log", "a+");
	fprintf(file, "%s", info);
	fclose(file);
}

int createTunDevice()		// 创建TUN设备，返回TUN设备的文件描述符
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;	

	tunfd = open("/dev/net/tun", O_RDWR);	// 打开TUN设备
	if (tunfd == -1) {
		sprintf(info, "[fail]  打开/dev/net/tun失败! (%d: %s)\n", errno, strerror(errno));
		system("echo `date` >> log");
		printLog(info);
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);	// 设置TUN设备
	if (ret == -1) {
		system("echo `date` >> log");
		sprintf(info, "[fail]  设置TUN接口失败! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	// printf("[info]  成功设置TUN接口!\n");
	// 调用system函数，将当前时间echo到vpnserver.log中，不换行
	system("echo `date` >> log");
	sprintf(info, "[info]  成功设置TUN接口!\n");
	printLog(info);
	return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl)		// 从TUN设备读取数据，发送到UDP套接字
{
	int len;
	char buff[BUFF_SIZE];

	sprintf(info, "[info]  接收到来自TUN的数据包\n");
	system("echo `date` >> log");
	printLog(info);

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	// sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
	SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, int sockfd, SSL *ssl)	// 从UDP套接字读取数据，发送到TUN设备
{
	int len;
	char buff[BUFF_SIZE];

	sprintf(info, "[info]  接收到来自tunnel的数据包\n");
	system("echo `date` >> log");
	printLog(info);

	bzero(buff, BUFF_SIZE);
	// len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
	len = SSL_read(ssl, buff, BUFF_SIZE);
	write(tunfd, buff, len);
}
/*vpnserver.c*/ 

/*tlsserver.c*/ 
/* define HOME to be dir for key and cert files... */
#define HOME	"./cert/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)		if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	// printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		sprintf(info, "[info]  认证通过!\n");
		system("echo `date` >> log");
		printLog(info);
	}
	else {
		int err = X509_STORE_CTX_get_error(x509_ctx);
		sprintf(info, "[fail]  认证失败: %s.\n", X509_verify_cert_error_string(err));
		system("echo `date` >> log");
		printLog(info);
	}
	return preverify_ok;
}

SSL* setupTLSServer() {
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	int err;

	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

#if 1
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "[fail]  私钥与公钥不匹配\n");
		exit(5);
	}
	// Step 3: Create a new SSL structure for a connection
	ssl = SSL_new(ctx);
	return ssl;
}

int setupTCPServer()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(4433);
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	return listen_sock;
}
/*tlsserver.c*/ 

typedef struct pipe {
    char *pipe_file;
    SSL *ssl;
} PIPE;

int login(char *user, char *passwd) {
    struct spwd *pw;
    char *epasswd;
    pw = getspnam(user);	// 获取用户信息
    if (pw == NULL) {
		sprintf(info, "[error] 密码为空\n");
		system("echo `date` >> log");
		printLog(info);
		return 0;
    }

    printf("[info]  用户名为: %s\n", pw->sp_namp);

    epasswd = crypt(passwd, pw->sp_pwdp);		// 加密用户输入的密码
    if (strcmp(epasswd, pw->sp_pwdp)) {			// 比较加密后的密码
		sprintf(info, "[error] 密码错误\n");	// 密码错误
		system("echo `date` >> log");
		printLog(info);
		return 0;
    }
    return 1;
}

void *listen_pipe(void *threadData) {	// 监听管道文件
    PIPE *ptd = (PIPE*)threadData;		// 线程数据
    int pipefd = open(ptd->pipe_file, O_RDONLY);		// 打开管道文件

    char buff[2000];
    int len;
    do {		// 读取管道文件内容并发送给客户端
        len = read(pipefd, buff, 2000);		
        SSL_write(ptd->ssl, buff, len);
    } while (len > 0);
	fprintf(info, "[info]  关闭连接，删除管道文件%s\n", ptd->pipe_file);
	system("echo `date` >> log");
	printLog(info);
	remove(ptd->pipe_file);
}

void *listen_tun(void *tunfd) {		// 监听TUN设备
    int fd = *((int *)tunfd);		// TUN设备文件描述符
    char buff[2000];
    while (1) {
        int len = read(fd, buff, 2000);
		if (len > 19 && buff[0] == 0x45) {		// 判断是否为IP数据包
			sprintf(info, "[info]  接收到TUN传来的数据，长度为%3d，来自192.168.53.%d\n", len, (int)buff[19]);
			system("echo `date` >> log");
			printLog(info);
			char pipe_file[10];
            sprintf(pipe_file, "./pipe/%d", (int)buff[19]);		// 根据目的IP地址创建管道文件
            int fd = open(pipe_file, O_WRONLY);			// 打开管道文件
            if (fd == -1) {
				sprintf(info, "[error] 管道文件%s不存在\n", pipe_file);
				system("echo `date` >> log");
				printLog(info);
			}
			else {
                write(fd, buff, len);		// 将数据包写入管道文件
            }
        }
    }
}

int main()
{
	/*tlsserver.c*/
	SSL* ssl = setupTLSServer();

	struct sockaddr_in sa_client;
	size_t client_len = sizeof(sa_client);;
	int listen_sock = setupTCPServer();

	printf(" __   ___ __  _ __    ___  ___ _ ____   _____ _ __\n\
 \\ \\ / / '_ \\| '_ \\  / __|/ _ \\ '__\\ \\ / / _ \\ '__|\n\
  \\ V /| |_）| | | | \\__ \\  __/ |   \\ V /  __/ |\n\   
   \\_/ | .__/|_| |_| |___/\\___|_|    \\_/ \\___|_|\n\   
       | |\n\                                         
       |_|\n");
	fprintf(stderr, "listen_sock = %d\n", listen_sock);
	int tunfd = createTunDevice();
	system("sudo ifconfig tun0 192.168.53.1/24 up && sudo sysctl net.ipv4.ip_forward=1");
	sprintf(info, "[info]  设置TUN设备IP地址并开启IP转发\n");
	system("echo `date` >> log");
	printLog(info);
	system("rm -rf pipe");
	mkdir("pipe", 0666);
	sprintf(info, "[info]  创建管道文件夹\n");
	system("echo `date` >> log");
	printLog(info);

	pthread_t listen_tun_thread;
	pthread_create(&listen_tun_thread, NULL, listen_tun, (void*)&tunfd);

	while (1) {
		int sock = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);

		// fprintf(stderr, "sock = %d\n", sock);
		if (sock == -1) {
			fprintf(stderr, "[fail]  TCP连接失败! (%d: %s)\n", errno, strerror(errno));
			continue;
		}
		if (fork() == 0) {	// The child process
			close(listen_sock);
            
            SSL_set_fd(ssl, sock);
			int err = SSL_accept(ssl);

			// fprintf(stderr, "SSL_accept return %d\n", err);
			CHK_SSL(err);
			sprintf(info, "[info]  成功建立SSL连接\n");
			system("echo `date` >> log");
			printLog(info);	

			// 登录验证
            char username[1024], password[1024], last_ip_buff[1024];
            username[SSL_read(ssl, username, sizeof(username) - 1)] = '\0';
            password[SSL_read(ssl, password, sizeof(password) - 1)] = '\0';
			// last_ip_buff[SSL_read(ssl, last_ip_buff, sizeof(last_ip_buff) - 1)] = '\0';

			if (login(username, password)) {
				sprintf(info, "[info]  客户端登录成功!\n");
				system("echo `date` >> log");
				printLog(info);
				char pipe_file[1024];

				// 获取pipe下面的所有文件名
				DIR* dir;
				struct dirent* ptr;
				dir = opendir("./pipe");
				// 根据文件名获取IP地址
				int ip_pool[256] = { 0 };
				ip_pool[0] = ip_pool[1] = ip_pool[255] = 1;
				while ((ptr = readdir(dir)) != NULL) {
					if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) {
						continue;
					}
					int ip = atoi(ptr->d_name);
					ip_pool[ip] = 1;
				}
				closedir(dir);
				// 分配IP地址
				int ip = 2;
				while (ip_pool[ip] == 1) {
					ip++;
				}
				if (ip == 255) {
					sprintf(info, "[fail]  IP池已满，分配虚拟IP失败!\n");
					system("echo `date` >> log");
					printLog(info);
					return 0;
				}

				sprintf(pipe_file, "pipe/%d", ip);
				sprintf(last_ip_buff, "%d", ip);
				sprintf(info, "[info]  管道文件为%s\n", pipe_file);
				system("echo `date` >> log");
				printLog(info);
				SSL_write(ssl, last_ip_buff, strlen(last_ip_buff));	// 发送给客户端分配的IP地址

				if (mkfifo(pipe_file, 0666) < 0) {
					//打印错误原因
					sprintf(info, "[error] 创建管道文件失败：%s\n", strerror(errno));
					system("echo `date` >> log");
					printLog(info);
				}
				else {
					pthread_t listen_pipe_thread;
					PIPE PIPE;
                    PIPE.pipe_file = pipe_file;
                    PIPE.ssl = ssl;
                    pthread_create(&listen_pipe_thread, NULL, listen_pipe, (void *)&PIPE);	// 创建监听管道文件的线程
					char buf[1024];
					int len;
					do {
						len = SSL_read(ssl, buf, sizeof(buf) - 1);	// 读取客户端发送的数据
						buf[len] = '\0';
						write(tunfd, buf, len);
						sprintf(info, "[info]  接收到来自客户端的数据，长度为%3d\n", len);			// 打印客户端发送的数据
						system("echo `date` >> log");
						printLog(info);
					} while (len > 0);
					sprintf(info, "[info]  关闭SSL连接!\n");
					system("echo `date` >> log");
					printLog(info);
					pthread_cancel(listen_pipe_thread);
					remove(pipe_file);
					// 删除ip
					ip_pool[ip] = 0;
				}
			}
			else {
				sprintf(info, "[error] 用户名验证失败!\n");
				system("echo `date` >> log");
				printLog(info);
			}
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sock);
			sprintf(info, "[info]  子进程退出!\n");
			system("echo `date` >> log");
			printLog(info);
			return 0;
		} else {	// The parent process
			close(sock);
		}
	}
}

