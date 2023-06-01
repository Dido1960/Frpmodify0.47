# compile for version
make
if [ $? -ne 0 ]; then
    echo "make error"
    exit 1
fi

tool_version=`./bin/server --version`
echo "build version: $tool_version"

# cross_compiles
make -f ./Makefile.cross-compiles

rm -rf ./release/packages
mkdir -p ./release/packages

os_all='linux windows darwin freebsd'
arch_all='386 amd64 arm arm64 mips64 mips64le mips mipsle riscv64'

cd ./release

for os in $os_all; do
    for arch in $arch_all; do
        tool_dir_name="tool_${tool_version}_${os}_${arch}"
        tool_path="./packages/tool_${tool_version}_${os}_${arch}"

        if [ "x${os}" = x"windows" ]; then
            if [ ! -f "./client_${os}_${arch}.exe" ]; then
                continue
            fi
            if [ ! -f "./server_${os}_${arch}.exe" ]; then
                continue
            fi
            mkdir ${tool_path}
            mv ./client_${os}_${arch}.exe ${tool_path}/client.exe
            mv ./server_${os}_${arch}.exe ${tool_path}/server.exe
        else
            if [ ! -f "./client_${os}_${arch}" ]; then
                continue
            fi
            if [ ! -f "./server_${os}_${arch}" ]; then
                continue
            fi
            mkdir ${tool_path}
            mv ./client_${os}_${arch} ${tool_path}/client
            mv ./server_${os}_${arch} ${tool_path}/server
        fi  
        cp ../LICENSE ${tool_path}
        cp -rf ../conf/* ${tool_path}

        # packages
        cd ./packages
        if [ "x${os}" = x"windows" ]; then
            zip -rq ${tool_dir_name}.zip ${tool_dir_name}
        else
            tar -zcf ${tool_dir_name}.tar.gz ${tool_dir_name}
        fi  
        cd ..
        rm -rf ${tool_path}
    done
done

cd -
