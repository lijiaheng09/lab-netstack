
all: echo_client echo_server perf_client perf_server

wrap: echo_client_wrap echo_server_wrap perf_client_wrap perf_server_wrap

%: %.c
	gcc -o $@ $^ unp.c $(CFLAGS) $(LIBS)

%_wrap: %.c
	g++ -g3 -o $@ $^ unp.c $(CFLAGS) $(LIBS) \
		-L ../../build/lib -llab-netstack-socket -lstdc++ -llab-netstack -lpcap -lpthread \
		-Wl,--wrap,socket -Wl,--wrap,bind -Wl,--wrap,listen -Wl,--wrap,connect -Wl,--wrap,accept -Wl,--wrap,read -Wl,--wrap,write -Wl,--wrap,close -Wl,--wrap,getaddrinfo -Wl,--wrap,freeaddrinfo

clean:
	rm echo_client echo_server perf_client perf_server echo_client_wrap echo_server_wrap perf_client_wrap perf_server_wrap
