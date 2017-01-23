# This is how we want to name the binary output
BINARY=backup_ldap

# These are the values we want to pass for Version and BuildTime
VERSION=0.9.2
#BUILD_TIME=`date +%FT%T%z`

# Setup the -ldflags option for go build here, interpolate the variable values
#LDFLAGS=-ldflags "-X github.com/ariejan/roll/core.Version=${VERSION} -X github.com/ariejan/roll/core.BuildTime=${BUILD_TIME}"

all:
	go get ./...
	go build  -o ${BINARY} backup_ldap.go

clean:
	rm -f ${BINARY}
	rm -f *.gz

tar:
	mkdir ${BINARY}-${VERSION}
	cp backup_ldap.go LICENSE backup-ldap.service backup_ldap.spec ${BINARY}-${VERSION}/
	tar -cvzf ${BINARY}-${VERSION}.tar.gz ${BINARY}-${VERSION}/
	rm -rf ${BINARY}-${VERSION}/	
