all: linuxamd64 linuxarm64

linuxamd64:
	GOOS=linux GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/ltfw-amd64 ${BUILD_FILES}

linuxarm64:
	GOOS=linux GOARCH=arm64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o bin/ltfw-arm64 ${BUILD_FILES}
