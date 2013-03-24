CPPFLAGS = -O3 -DNDEBUG

OBJECTS = \
  out/config.o \
  out/filterer.o \
  out/filterer_file.o \
  out/filterer_net.o \
  out/jail.o \
  out/report.o \
  out/signal_tab.o \
  out/syscall_tab.o \

M32OBJECTS = \
  out/m32/config.o \
  out/m32/filterer.o \
  out/m32/filterer_file.o \
  out/m32/filterer_net.o \
  out/m32/jail.o \
  out/m32/report.o \
  out/m32/signal_tab.o \
  out/m32/syscall_tab.o \

all: jail jailm32

out/m32/%.o: %.cpp
	@mkdir -p `dirname out/m32/$*.o`
	g++ -m32 $(CPPFLAGS) -c $*.cpp -o out/m32/$*.o

out/%.o: %.cpp
	@mkdir -p `dirname out/$*.o`
	g++ $(CPPFLAGS) -c $*.cpp -o out/$*.o

jailm32: $(M32OBJECTS)
	g++ -m32 $(CPPFLAGS) $(M32OBJECTS) -o jailm32

jail: $(OBJECTS)
	g++ $(CPPFLAGS) $(OBJECTS) -o jail

clean:
	rm -f jail jailm32
	rm -rf out
