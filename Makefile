PROGRAM = xfrmpaser
ARCH    = i686
OS      = linux

LEX     = flex

#header directory
INCDIRS += src

#source directory
SRCDIRS += src

OBJECTS += $(OBJDIR)/parser.o

include ../commk/Common.mk

# Do it manually now, maybe commk.mk should support flex
src/parser.c: parser.lex
	$(LEX) -o src/parser.c src/parser.lex 
