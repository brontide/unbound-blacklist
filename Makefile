DC := docker-compose

up: download build xup

backup: ;

stop: down

download:
	mkdir filter.d || exit 0
	curl -o filter.d/StevenBlack.hosts https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

build:
	${DC} build

xup:
	${DC} up -d

down:
	${DC} down	

logs:
	${DC} logs -f
