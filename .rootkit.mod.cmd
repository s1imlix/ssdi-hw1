cmd_/home/kyle/shared/ssdi-hw1/rootkit.mod := printf '%s\n'   rootkit.o | awk '!x[$$0]++ { print("/home/kyle/shared/ssdi-hw1/"$$0) }' > /home/kyle/shared/ssdi-hw1/rootkit.mod
