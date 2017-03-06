object = main.o server.o symlib.o

server.exe:$(object)
	cc $(object) -lpthread -lrt -o server.exe
	@echo $(object) 1111111

main.o:type.h server.h

server.o:type.h server.h

symlib.o:type.h server.h

%:
	@echo $(object) 1111111

.PHONY:clean

clean:
	-rm server.exe *.o
	 
