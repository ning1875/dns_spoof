# coding:utf-8
import difflib
import re
import time
import validators
import redis
import yaml

from ansi_api import PlaybookApi
from dns_dig_diff import query, run_diff
import argparse
import coloredlogs, logging
import sys
from IPy import IP

# const
G_VAR_YAML = "vars.yaml"
G_DIST_SPOOF_FLAG_LINE = None
G_DIST_POOL_FLAG_LINE = None


def load_global_dist_var(config):
    global G_DIST_SPOOF_FLAG_LINE
    global G_DIST_POOL_FLAG_LINE
    G_DIST_SPOOF_FLAG_LINE = config.get("spoof").get("g_dist_spoof_flag_line")
    G_DIST_POOL_FLAG_LINE = config.get("spoof").get("g_dist_pool_flag_line")


# Create a logger object.
logger = logging.getLogger(__name__)

coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s '
                                                      '%(hostname)s '
                                                      '[pid:%(process)d] '
                                                      '[%(filename)s:%(funcName)s]'
                                                      '[line:%(lineno)d] '
                                                      '%(levelname)s '
                                                      '%(message)s')


def judge_is_existed(new_str, text):
    if re.search(new_str, text, re.IGNORECASE):
        return True
    return False


def valid_ip(ip):
    try:
        IP(ip)
    except Exception as e:
        logger.critical("[ip:{} not valid error:{}]".format(ip, str(e)))
        sys.exit(3)


def validate_domain(doamin):
    res = validators.domain(doamin)
    return res


def format_dist_ips(ips):
    ip_line = ""
    for ip in ips:
        ip_line += '\"{}\"'.format(ip) + ","
    ip_line = ip_line[:-1]
    return ip_line


def file_diff(text1, text2, file1, file2):
    for line in difflib.unified_diff(text1.strip().splitlines(), text2.strip().splitlines(), fromfile=file1,
                                     tofile=file2, lineterm=''):
        print(line)


def run_main_domain_check(region, online_ip, offline_ip, ):
    logger.debug("[region:{} start check main_domain online_ip:{},offline_ip:{}]".format(region, online_ip, offline_ip))
    run_diff([online_ip], [offline_ip])
    logger.debug("[region:{} start check main_domain online_ip:{},offline_ip:{} successfully]".format(region, online_ip,
                                                                                                      offline_ip))


def run_spoof_check(type, server_ip, domain, expected_as):
    remote_set = query([server_ip], domain)
    if remote_set != set(expected_as):
        logger.critical("[ip:{} spoof  check {} failed ...expected:{},actually:{}]".format(server_ip,
                                                                                           domain,
                                                                                           str(expected_as),
                                                                                           str(remote_set)
                                                                                           ))
        if type == "spoof":
            # 如果是转发的,就不错强制退出了,因为外部dns记录可能变化很频繁
            sys.exit(2)

    logger.debug("[ip:{} spoof  check {}   success]".format(server_ip, domain))


def run_audit(config, args, full_cmd_line):
    file_name = ""
    uniq_name = ""
    try:
        redis_addr = config.get("redis").get("addr")
        redis_port = config.get("redis").get("port")
        redis_serial_key = config.get("redis").get("redis_serial_key")
        redis_map_key = config.get("redis").get("redis_serial_key")
        conn = redis.Redis(host=redis_addr, port=int(redis_port))
        serial_num = conn.get(redis_serial_key)
        if not serial_num:
            serial_num = 1
        else:
            serial_num = int(serial_num) + 1

        uniq_name = "{}_{}".format(serial_num, time.strftime('%Y-%m-%d', time.localtime(time.time())))
        file_name = "{}_{}".format(uniq_name, args.domain)
        conn.set(redis_serial_key, serial_num)
        conn.hset(redis_map_key, file_name, full_cmd_line)
    except Exception as e:
        logger.critical("[run_audit get error :{}]".format(str(e)))
    finally:
        return file_name, uniq_name


def run_get_online_config(yaml_path, region, ip, conf_dir, bk_file_name):
    logger.debug("[region:{} start get conf from :{} save to :{}]".format(region, ip, conf_dir))
    t = PlaybookApi([ip], yaml_path, {"conf_dir": conf_dir, "bk_file_name": bk_file_name})
    t.run()
    if not t.get_result():
        sys.exit(2)
    if not t.get_result().get("success").get(ip):
        logger.critical("[region:{} start get conf from :{} failed]".format(region, ip))
        sys.exit(2)


def run_restart_service(yaml_path, region, ip, app, action="restart"):
    t = PlaybookApi([ip], yaml_path, {"app": app})
    t.run()
    if not t.get_result():
        return False
    if t.get_result().get("failed").get(ip):
        err_lines = t.get_result().get("failed").get(ip)._result.get("stderr_lines")
        logger.error("[region:{} run_{}_service:{} is {}]".format(region, action, ip, str(err_lines)))

        logger.critical("[region:{} run_{}_service :{} failed]".format(region, action, ip))
        return False
    logger.debug("[region:{} ip:{} app:{} run_{}_service successfully ]".format(region, action, ip, app))
    return True


def run_send_conf_roll_back(yaml_path, region, ip, conf_path):
    logger.debug("[region:{} start run_send_conf_roll_back on  ip :{} conf_path:{}]".format(region, ip, conf_path))
    t = PlaybookApi([ip], yaml_path, {"conf_path": conf_path, })
    t.run()

    if not t.get_result():
        sys.exit(2)
    if t.get_result().get("failed").get(ip):
        err_lines = t.get_result().get("failed").get(ip)._result.get("stderr_lines")
        logger.error("[region:{} error_msg_on:{} is {}]".format(region, ip, str(err_lines)))

        logger.critical("[region:{} start send_remote :{} failed]".format(region, ip))
        sys.exit(2)
    logger.debug(
        "[region:{} remote :{} conf_path :{} check config and restart successfully ]".format(region, ip, conf_path))


def run_send_remote(yaml_path, region, ip, conf_dir, bk_file_name):
    logger.debug("[region:{} start run_send_remote on  :{}]".format(region, ip, conf_dir))
    t = PlaybookApi([ip], yaml_path, {"conf_dir": conf_dir, "bk_file_name": bk_file_name})
    t.run()

    if not t.get_result():
        sys.exit(2)
    if t.get_result().get("failed").get(ip):
        err_lines = t.get_result().get("failed").get(ip)._result.get("stderr_lines")
        logger.error("[region:{} error_msg_on:{} is {}]".format(region, ip, str(err_lines)))

        logger.critical("[region:{} start send_remote :{} failed]".format(region, ip))
        sys.exit(2)
    logger.debug("[region:{} remote :{} check config and restart successfully ]".format(region, ip, conf_dir))


def run_local_conf_impl(conf_path, type, domain, ips, uniq_name):
    with open(conf_path) as f:
        text = f.read()
    origin_text = text
    # type = spoof
    if type == "spoof":
        spoof_impl(conf_path, origin_text, domain, ips)
    elif type == "forward":
        forward_impl(conf_path, origin_text, domain, ips, uniq_name)


def forward_impl(conf_path, text, domain, ips, uniq_name):
    base_msg = "[start forward impl  domain:{} ips:{}]".format(domain, str(ips))
    new_text = text

    # find pool
    pool_name = ""
    extend_msg = ""
    for ip in ips:
        pool_head = r'newServer\({address="%s", pool.*?\n' % (ip)
        if judge_is_existed(pool_head, text):
            # pool已存在
            first_re = re.compile(r'newServer\({address="%s", pool="(.*?)"}\)\n' % (ip), re.S)
            pool_name = first_re.findall(text)[0]
            extend_msg += "[dns:{} pool:{}已存在]".format(ip, pool_name)
            break
        else:
            continue
    if not pool_name:
        # pool不存在

        pool_name = "fp_{}".format(uniq_name)
        extend_msg += "[新建pool:{}]".format(pool_name)
        new_pool_line = ""
        for ip in ips:
            new_pool_line += 'newServer({address="%s", pool="%s"})\n' % (ip, pool_name)
        new_text = re.sub(G_DIST_POOL_FLAG_LINE, r'{}\n{}'.format(G_DIST_POOL_FLAG_LINE, new_pool_line), new_text)

    # 新建转发记录
    action_head = r'addAction\(makeRule\({"%s"}\).*?\n' % (domain.strip())
    new_line = 'addAction(makeRule({"%s"}), PoolAction("%s"))\n' % (domain, pool_name)
    if judge_is_existed(action_head, text):
        # 这个记录存在而且是转发型的
        # 修改之
        new_text = re.sub(action_head, new_line, new_text)
        extend_msg += "[这个记录{} 存在而且是转发型的pool:{}]".format(domain, pool_name)
    else:

        new_text = re.sub(G_DIST_SPOOF_FLAG_LINE, r'{}\n{}'.format(G_DIST_SPOOF_FLAG_LINE, new_line), new_text)
        extend_msg += "[这个记录{} 不存在]".format(domain)
    logger.debug(base_msg + extend_msg)
    with open(conf_path, 'w') as f:
        f.write(new_text)


def spoof_impl(conf_path, text, domain, ips):
    base_msg = "[start spoof impl  domain:{} ips:{}]".format(domain, str(ips))
    ip_line = format_dist_ips(ips)
    new_line = 'addAction(makeRule({"%s"}), SpoofAction(%s))\n' % (domain.strip(), ip_line)
    action_head = r'addAction\(makeRule\({"%s"}\).*?\n' % (domain.strip())
    if judge_is_existed(action_head, text):
        # 之前添加过属于修改
        # 原来是转发，想改成直接劫持
        # addAction(makeRule({"zoom.us"}), PoolAction("masq"))
        # addAction(makeRule({"zoom.us"}), SpoofAction("3.3.3.3"))
        new_text = re.sub(action_head, new_line, text)
        extend_msg = "[劫持记录:{} 存在,修改...]".format(domain)
    else:
        # 新增
        new_text = re.sub(G_DIST_SPOOF_FLAG_LINE, r'{}\n{}'.format(G_DIST_SPOOF_FLAG_LINE, new_line), text)
        extend_msg = "[劫持记录:{} 不存在,新增...]".format(domain)
    logger.debug(base_msg + extend_msg)
    file_diff(text, new_text, conf_path, "new_conf")
    with open(conf_path, 'w') as f:
        f.write(new_text)


def load_base_config():
    yaml_path = G_VAR_YAML
    with open(yaml_path) as f:
        config = yaml.load(f)
    return config


def load_region_info(region):
    config = load_base_config()
    region_info = config.get("dns_dist").get(region)
    if not region_info:
        logger.critical(["region:{} not supported ".format(region)])
    online_ip = region_info.get("online_ip", None)
    offline_ip = region_info.get("offline_ip", None)
    conf_dir = region_info.get("conf_dir", None)
    if not online_ip or not offline_ip or not conf_dir:
        logger.critical(["lack of region info "])
        sys.exit(2)
    return region_info, config


def get_username_from_klist():
    username = "root"
    return username


def start_spoof_work(full_cmd_line, region_info, args, config):
    online_ip = region_info.get("online_ip")
    offline_ip = region_info.get("offline_ip")
    conf_dir = region_info.get("conf_dir")
    conf_path = "{}/dnsdist.conf".format(conf_dir)

    # prestep 生成serial_num 和file_name
    bk_file_name, uniq_name = run_audit(config, args, full_cmd_line)
    if not bk_file_name:
        logger.critical("[bk_file_name empty exit .....]")
        sys.exit(2)
    # 第1步 获取线上配置到本地并备份
    get_online_yaml = config.get("yaml").get("get_from_online")
    run_get_online_config(get_online_yaml, args.region, online_ip, conf_dir, bk_file_name)

    # 第2步 本地装配
    run_local_conf_impl(conf_path, args.type, args.domain, args.ips, uniq_name)

    # 第3步 发往离线远端,check,重启
    send_offline_yaml = config.get("yaml").get("send_remote_offline")
    run_send_remote(send_offline_yaml, args.region, offline_ip, conf_dir, bk_file_name)

    # 第4步 主域域名解析测试测试
    run_main_domain_check(args.region, online_ip, offline_ip)

    # 第5步 劫持测试
    expected_as = args.ips
    if args.type == "forward":
        # 如果是forward 期望的a记录应该去对应的server上解析一次
        expected_as = list(query(args.ips, args.domain))

    run_spoof_check(args.type, offline_ip, args.domain, expected_as)

    # 第6步 checkok 发往线上一台,进行灰度,重启服务
    send_online_yaml = config.get("yaml").get("send_remote_online")
    run_send_remote(send_online_yaml, args.region, online_ip, conf_dir, bk_file_name)

    # 第8步 灰度线上check正常,重启dist

    restart_yaml = config.get("yaml").get("restart_service")
    stop_yaml = config.get("yaml").get("stop_service")

    restart_res = run_restart_service(restart_yaml, args.region, online_ip, "dnsdist")
    # restart_res = run_restart_service(restart_yaml, args.region, online_ip, "adnsdist")
    if not restart_res:
        # 重启dnsdist失败 摘bird

        run_restart_service(stop_yaml, args.region, online_ip, "bird", action="stop")

        sys.exit(2)

    logger.debug("[region:{} gray push online on ip  :{} successfully]".format(args.region, online_ip))

    time.sleep(2)
    # 获取其余线上cache,上线
    all_other_online_ips = list(set(region_info.get("online_all")) - set(online_ip))
    for ip in all_other_online_ips:
        run_send_remote(send_online_yaml, args.region, ip, conf_dir, bk_file_name)
        this_restart_res = run_restart_service(restart_yaml, args.region, ip, "dnsdist")
        if not this_restart_res:
            # 重启dnsdist失败 摘bird
            run_restart_service(stop_yaml, args.region, ip, "bird", action="stop")
            sys.exit(2)
        logger.debug("[region:{}  push online on ip  :{} successfully]".format(args.region, ip))

    logger.debug("[region:{}  劫持{} 变更完毕]".format(args.region, args.domain))

    # 最后本地备份为了回滚
    local_backup_yaml = config.get("yaml").get("local_backup")
    run_local_backup(args.region, local_backup_yaml, conf_dir, bk_file_name)


def run_local_backup(region, yaml_path, conf_dir, bk_file_name):
    ip = "localhost"
    logger.debug("[region:{} start get conf from :{} save to :{}]".format(region, ip, conf_dir))
    t = PlaybookApi([ip], yaml_path, {"conf_dir": conf_dir, "bk_file_name": bk_file_name})
    t.run()


def start_roll_back(region_info, args):
    conf_path = args.conf_path
    online_ip = region_info.get("online_ip")
    offline_ip = region_info.get("offline_ip")
    # 第1步 发往离线远端,check,重启
    rollback_offline_yaml = config.get("yaml").get("rollback_remote_offline")
    run_send_conf_roll_back(rollback_offline_yaml, args.region, offline_ip, conf_path)

    # 第2步 主域域名解析测试
    run_main_domain_check(args.region, online_ip, offline_ip)
    # 第3步 全量

    restart_yaml = config.get("yaml").get("restart_service")
    stop_yaml = config.get("yaml").get("stop_service")
    rollback_online_yaml = config.get("yaml").get("rollback_remote_online")

    # 获取其余线上cache,上线
    for ip in region_info.get("online_all"):
        run_send_conf_roll_back(rollback_online_yaml, args.region, ip, conf_path)
        this_restart_res = run_restart_service(restart_yaml, args.region, ip, "dnsdist")
        if not this_restart_res:
            # 重启dnsdist失败 摘bird
            run_restart_service(stop_yaml, args.region, ip, "bird", action="stop")
            sys.exit(2)
        logger.debug("[region:{} rollback online on ip  :{} successfully]".format(args.region, ip))

    logger.debug("[region:{}  回滚{} 变更完毕]".format(args.region, conf_path))


def run_test_expect(offline_ip, type, domain, ips):
    if type == "forward":
        # 如果是forward 期望的a记录应该去对应的server上解析一次
        expected_as = list(query(ips, domain))
        print(expected_as)
        run_spoof_check(type, offline_ip, domain, expected_as)


def show_history(config):
    redis_addr = config.get("redis").get("addr")
    redis_port = config.get("redis").get("port")
    redis_serial_key = config.get("redis").get("redis_serial_key")
    redis_map_key = config.get("redis").get("redis_serial_key")
    conn = redis.Redis(host=redis_addr, port=int(redis_port))
    res = conn.hgetall(redis_map_key)
    if not res:
        return
    if not isinstance(res, dict):
        return
    keys = sorted(res.keys())
    serial_num = int(conn.get(redis_serial_key))
    logger.debug("[共有:{}次操作]".format(serial_num))
    for k in keys:
        num, date, domain = k.split("_")
        full_cmd_line = res.get(k)
        logger.debug("[serial num:{} date:{} domain:{} full_cmd_line:{} ]".format(num, date, domain, full_cmd_line))


if __name__ == '__main__':
    full_cmd_line = " ".join(sys.argv)
    username = get_username_from_klist()
    full_cmd_line = "{} {}".format(username, full_cmd_line)
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    # 代表查看历史
    group.add_argument("-H", action="store_true", help="查看历史")
    # 代表回滚
    group.add_argument("-R", action="store_true", help="回滚")
    # 代表劫持
    group.add_argument("-S", action="store_true", help="劫持")

    parser.add_argument("-f", "--conf_path", help="回滚的文件路径 eg: ")

    parser.add_argument("-r", "--region", help="在哪个reigon/view生效", choices=["view-a", "view-b", "view-c"])
    parser.add_argument("-t", "--type", help="类型:spoof代表直接劫持,forward代表转发的制定dns server", choices=["spoof", "forward"])
    parser.add_argument("-d", "--domain", help="劫持的域名")
    parser.add_argument("-i", "--ips", help="A记录列表或者转发的dns serverip列表", nargs='+')

    args = parser.parse_args()

    if args.H:
        print("查看历史")
        config = load_base_config()
        show_history(config)

        exit(2)
    if args.R:
        print("回滚")
        if not args.region:
            print("劫持必须选择region eg:-r view-a|view-b|view-c ")
            exit(2)

        if not args.conf_path:
            print("劫持必须选择region eg:-f 3_2019-09-19_agoogle.cn  3为serial_num 时间 domain")
            exit(2)
        region_info, config = load_region_info(args.region)
        start_roll_back(region_info, args)
        # 开始回滚
    if args.S:
        if not args.region:
            print("劫持必须选择region eg:-r view-a|view-b|view-c ")
            exit(2)
        if not args.type:
            print("劫持必须选择类型 eg: -t  spoof|forward ")
            exit(2)
        if not args.domain:
            print("劫持必须给出domain eg: -d baidu.com ")
            exit(2)
        if not args.ips:
            print("劫持必须给出a记录或者dns ips eg: -i 1.1.1.1 2.2.2.2 ")
            exit(2)

        if not validate_domain(args.domain):
            print("劫持domain:{} 不合规 ".format(args.domain))
            exit(2)
        for ip in args.ips:
            valid_ip(ip)
        logger.debug("[input_args: region:{} type:{} domain:{}  ips:{}]".format(
            args.region,
            args.type,
            args.domain,
            args.region,
            args.ips,
        ))
        region_info, config = load_region_info(args.region)
        load_global_dist_var(config)
        start_spoof_work(full_cmd_line, region_info, args, config)
