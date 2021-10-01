src_dir="$(cd "$(dirname "$0")"; pwd)"
echo ${src_dir}
#cd ${src_dir}
#echo "show dir: $src_dir"
echo $PWD
g++ watchdog.cpp -o ../../objs/watchdog