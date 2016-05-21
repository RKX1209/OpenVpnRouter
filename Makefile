DEBUG		=  1
VROUTER	=  vrouter
OBJS		=  router.o

CURPATH = 	$(shell pwd)
INCLUDE =		$(CURPATH)/include

CXX 		= 	g++ -fstack-protector-all -D_FORTIFY_SOURCE=2

ifdef DEBUG
	CXXFLAG =		-Wall -I$(INCLUDE) -std=c++11 $(LIBSDL_CXXFLAGS) -fexceptions -g -o
else
	CXXFLAG =		-Wall -I$(INCLUDE) -std=c++11 $(LIBSDL_CXXFLAGS) -fexceptions -o
endif

LDFLAG	=		-Wl,-z,relro,-z,now

CHKSEC	=		$(shell which checksec.sh)

all:
	$(MAKE) $(VROUTER)

$(VROUTER) : $(OBJS)
	$(CXX) $(CXXFLAG) $@ $^ $(LDFLAG)

security:
ifneq ("$(CHKSEC)","")
	$(CHKSEC) --file $(VROUTER)
else
	echo '[**ERROR**] checksec.sh not found'
endif

clean :
	rm -rf $(VROUTER)
	find . -regex ".*\.o" -exec rm -rf {} \;

%.o : %.c
	$(CXX) $(CXXFLAG) $*.o -c $*.c
%.o : %.cpp
	$(CXX) $(CXXFLAG) $*.o -c $*.cpp
