CPPFLAGS = -O3 -Wall -Werror

OBJECTS = \
  out/config.o \
  out/filter.o \
  out/filter_file.o \
  out/filter_net.o \
  out/filter_proc.o \
  out/sjail.o \
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
  out/m32/sjail.o \
  out/m32/memory.o \
  out/m32/report.o \
  out/m32/signal_tab.o \
  out/m32/process_state.o \

all: sjail sjailm32

out/m32/%.o: %.cpp
	@mkdir -p `dirname out/m32/$*.o`
	g++ -m32 $(CPPFLAGS) -c $*.cpp -o out/m32/$*.o

out/%.o: %.cpp
	@mkdir -p `dirname out/$*.o`
	g++ $(CPPFLAGS) -c $*.cpp -o out/$*.o

sjailm32: $(M32OBJECTS)
	g++ -m32 $(CPPFLAGS) $(M32OBJECTS) -o sjailm32

sjail: $(OBJECTS)
	g++ $(CPPFLAGS) $(OBJECTS) -o sjail

clean:
	rm -f sjail sjailm32
	rm -rf out
