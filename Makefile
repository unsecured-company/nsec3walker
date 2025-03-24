.PHONY: all linux mac windows clean

all: linux mac windows
linux: linux_amd64 linux_arm64
mac: mac_amd64 mac_arm64

linux_amd64:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build -o bin/nsec3walker.amd.elf cmd/nsec3walker.go

linux_arm64:
	@echo "Building for Linux ARM64..."
	GOOS=linux GOARCH=arm64 go build -o bin/nsec3walker.arm.rpi cmd/nsec3walker.go

mac_amd64:
	@echo "Building for macOS (AMD64)..."
	GOOS=darwin GOARCH=amd64 go build -o bin/nsec3walker.mac_amd64 cmd/nsec3walker.go

mac_arm64:
	@echo "Building for macOS (ARM64)..."
	GOOS=darwin GOARCH=arm64 go build -o bin/nsec3walker.mac_arm64 cmd/nsec3walker.go

windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build -o bin/nsec3walker.exe cmd/nsec3walker.go

clean:
	@echo "Removing builds..."
	rm -f bin/nsec3walker.*
