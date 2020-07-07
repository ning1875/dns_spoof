
# 整体流程说明:
- 获取线上dns_dist配置文件到本地备份
- 在本地装配配置文件
- 推送到此region的线下测试机上检查配置并重启服务
- 发起对线下测试机的主域名测试(即存量测试)
- 发起对线下测试机的劫持测试: case1: 直接劫持的期望直接是A记录 case2: 转发的期望需要去对应的server query一次
- 测试正常后,灰度一台推送到线上机器(如果线上机器dist重启失败则会摘bird)
- 全量其余机器
- 注意:上述流程是链式的,中间任何一部失败都会终止操作


# 使用说明
## 环境准备 vars.yaml
- 各个view的dns_dist ip :每个region包含一个线上同步配置的server和线下测试的机器,以及全量缓存机器
  view-a:
    online_ip: 1.1.1.1
    offline_ip: 1.1.1.4
    online_all:
      - 1.1.1.2
      - 1.1.1.3
- 修改dnsdist_conf/dns_dist.conf中的标志位:对应就是
  spoof:
      # dnsdist配置文件中劫持标志注释行
      g_dist_spoof_flag_line: --auto spoof by sys sre
      # dnsdist配置文件中转发标志注释行
      g_dist_pool_flag_line: --auto forward pool by sys sre  

## 调用参数说明
- region: 代表劫持生效的region
- 类型: spoof代表直接劫持,forward代表转发的
- 域名: 要劫持的域名
- a记录列表或者dns server ip列表,空格分隔

## 劫持域名到指定ip列表 
- eg: 将baidu.com在view-a中的记录劫持为1.1.1.1,1.1.1.2两个A记录
- 参数: region type domain ips 
- 多个域名用空格分隔
- 触发: python spoof_action.py  -S -r view-a -t spoof  -d baidu.com -i  1.1.1.1 1.1.1.2
- case1: 劫持型,原纪录为劫持型,变更
- case2: 劫持型,原纪录为转发型,肯定pool存在,变更
- case3: 劫持型,原纪录不存在,新增


## 劫持域名转发的指定dns server列表
- eg: 将stackoverflow.com 在view-a中 劫持到8.8.8.8 dns上解析
- 参数: region type domain ips 
- 多个域名用空格分隔
- 触发: python spoof_action.py  -S -r view-a -t forward  -d  stackoverflow.com -i  8.8.8.8
- case1: 转发型,原纪录为劫持型,pool存在
- case2: 转发型,原纪录为劫持型,pool不存在
- case3: 转发型,原纪录为转发型,pool存在
- case4: 转发型,原纪录为转发型,pool不存在
- case5: 转发型,原纪录不存在,pool存在
- case6: 转发型,原纪录不存在,pool不存在

## 使用指定的配置文件回滚
- 参数: region 和配置文件
- 触发: python spoof_action.py  -R -r view-a -f ./dnsdist_conf/view-a/dnsdist.conf_2_2019-09-19_stackoverflow.com





