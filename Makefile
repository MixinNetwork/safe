all:
	git checkout VERSION
	sed -i --  "s/COMMIT/`git rev-parse --short HEAD`/g" VERSION || exit
	go build -o safe
	git checkout VERSION
