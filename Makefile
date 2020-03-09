CC = gcc
CFLAGS = -fno-stack-protector -z execstack -Wall -Iutil -Iatm -Ibank -Irouter -I.
LIBS = -lssl -lcrypto -lm

all: bin bin/atm bin/bank bin/router bin/init

bin:
	mkdir -p bin

bin/atm : atm/atm-main.c atm/atm.c atm-bank/atm-bank.c
	${CC} ${CFLAGS} atm/atm.c atm-bank/atm-bank.c atm/atm-main.c -o bin/atm ${LIBS}

bin/bank : bank/bank-main.c bank/bank.c atm-bank/atm-bank.c util/hash_table.c util/list.c
	${CC} ${CFLAGS} bank/bank.c atm-bank/atm-bank.c bank/bank-main.c util/hash_table.c util/list.c -o bin/bank ${LIBS}

bin/router : router/router-main.c router/router.c
	${CC} ${CFLAGS} router/router.c router/router-main.c -o bin/router ${LIBS}

bin/init : init/init.c
	${CC} ${CFLAGS} init/init.c -o bin/init

test : util/list.c util/list_example.c util/hash_table.c util/hash_table_example.c
	${CC} ${CFLAGS} util/list.c util/list_example.c -o bin/list-test
	${CC} ${CFLAGS} util/list.c util/hash_table.c util/hash_table_example.c -o bin/hash-table-test

clean:
	rm -f *.bank *.atm && cd bin && rm -f atm bank router init list-test hash-table-test *.bank *.atm
