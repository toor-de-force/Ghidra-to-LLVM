CXX = g++
CXXFLAGS = -Wall -g

SRCDIR =  ./src
OBJDIR = ./obj

SRCS := $(shell find $(SRCDIR) -name "*.cpp")
OBJS := $(subst $(SRCDIR),$(OBJDIR),$(SRCS))
OBJS := $(OBJS:.cpp=.o)

all: $(OBJS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
		$(CXX) $(CXXFLAGS) -o $@ $<
clean: 
		rm -f $(OBJDIR)/*
