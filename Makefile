DC := docker-compose

download:
	curl -o filter.d/StevenBlack.hosts https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

build:
	${DC} build

up:
	${DC} up -d

down:
	${DC} down	
