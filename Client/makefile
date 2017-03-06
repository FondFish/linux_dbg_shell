object = client.o 

client.exe:$(object)
	cc $(object) -lpthread -lrt -lreadline -ltermcap -o client.exe
	@echo $(object) 1111111

client.o:type.h client.h

%:
	@echo $(object) 1111111

.PHONY:clean

clean:
	-rm client.exe *.o
	 
