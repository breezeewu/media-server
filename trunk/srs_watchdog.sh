#./objs/nginx/sbin/nginx &
cur_dir="$(cd "$(dirname "$0")"; pwd)"
cd $cur_dir
#./objs/srs -c sv_master.conf &
#./objs/srs -c sv_edge.conf &	
#nohup ./srs_watchdog srs sv_start.sh >/dev/null 2>&1 &
nohup ./srs_watchdog srs sv_start.sh >./watchdog.log 2>&1 &
