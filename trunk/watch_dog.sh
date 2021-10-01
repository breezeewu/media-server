cur_dir="$(cd "$(dirname "$0")"; pwd)"
cd $cur_dir

#./objs/srs -c sv_master.conf &
./objs/watchdog "./objs/srs -c sv_master.conf"
#./objs/srs -c sv_edge.conf &	

