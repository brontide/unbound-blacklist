DC := docker-compose

download:
	make filter.d
	curl -o filter.d/StevenBlack.hosts https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

build:
	${DC} build

up:
	${DC} up -d

down:
	${DC} down	

logs:
	${DC} logs -f
