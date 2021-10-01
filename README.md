#srs流媒体服务器
##简介：
	用于sunvalley云存储作为rtmp流媒体服务器，将客户端的rtmp流写成ts文件以便业务服务器转码已及上传到第三方云服务上。
	
##编译：
	./configure
	make
如果需要编译release版
打开configure
GDBDebug=" -g -O0"
改为：
#GDBDebug=" -g -O0"

##配置
###1.sudo chmod 777 ./objs/srs

###2.修改sv_master.conf配置文件
		# redis数据库域名/IP
		hls_redis_server_ip					ec2-54-177-131-71.us-west-1.compute.amazonaws.com;
			
		# redis数据库端口
		hls_redis_server_port				6379;
			
		# redis数据库密码
		hls_redis_pwd						TbudkSCWAGBUfest;
			
		# redis数据库索引
		hls_redis_dbidx						2;
		
		# rtmp连接回调接口地址（云存）
		on_connect		http://localhost:2117/route/add;
		
		# rtmp推流token校验接口
		on_authorize	http://13.52.84.117:2115/connection/token/check;
		# rtmp token校验，0：不校验，1：弱校验，有就校验，无便不校验 2：强校验，必须校验token
		
		# rtmp连接关闭回调接口地址
		on_close		http://13.52.84.117:2115/connection/disconnect;
##启动srs服务
sh sv_start.sh