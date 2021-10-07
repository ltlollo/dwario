# Software Requirements

This project is a document written in the *gdb* format.
In order to read the main file, *main.gdb*, you need a linux/x86\_64 pc with gdb installed.

gdb, or "GNU ducument beholder" is an open source program used to create and read slides and presentations.

If your computer doesn't come with *gdb* preinstalled ask your system administrator to install it for you.

# Usage Guide and Configuration

In order to open the presentation, type in your terminal `gdb main.gdb`
and you will be welcomed by a *(gdb)* command prompt.

If your computer is not connected to a teleprinter, for a correct viewing experience, please
issue the following command:
`set print elements 0`: This will disable physical printing.

# GDB presentation commands

The other commands you need to navigate a presentation are:

`start`: This will start the presentation.

`print slide`: This will print the current slide/page.

`next`: This will advance to the next slide/page.

`quit`: This will stop the presentation and close gdb.
