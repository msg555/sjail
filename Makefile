CPPFLAGS = -O3 -DNDEBUG -Wall -Werror

OBJECTS = \
  out/config.o \
  out/filter.o \
  out/filter_file.o \
  out/filter_net.o \
  out/filter_proc.o \
  out/jail.o \
  out/memory.o \
  out/report.o \
  out/signal_tab.o \
  out/process_state.o \

M32OBJECTS = \
  out/m32/config.o \
  out/m32/filter.o \
  out/m32/filter_file.o \
  out/m32/filter_net.o \
  out/m32/filter_proc.o \
  out/m32/jail.o \
  out/m32/memory.o \
  out/m32/report.o \
  out/m32/signal_tab.o \
  out/m32/process_state.o \

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
