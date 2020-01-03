import psutil
import yagmail
from datetime import datetime, timedelta
from socket import getfqdn, gethostname
import os


def mem():
    """
    显示服务器的内存使用量
    :return:显示内存使用的百分比
    """
    # 查看内存的所有参数
    server_mem = psutil.virtual_memory()
    return server_mem[2]


def disk():
    """
    显示服务器的硬盘使用量
    :return: 服务器使用量的百分比
    """
    # 查看根目录下面的硬盘容量
    server_disk = psutil.disk_usage('/')
    return server_disk[3]


def cpu():
    """
    获取cpu使用量
    :return: 服务器的cpu使用量
    """
    # 计算cpu使用率的时间间隔
    server_cpu = psutil.cpu_percent(2)
    return server_cpu


def analysis_pid():
    """
    分析正在运行的所有进程，并且对于非常大的进程筛选出来
    :return:
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    records_file_name = current_dir + "/server_pid_records.txt"
    problem_file_name = current_dir + "/problem_records.txt"
    p_ids = psutil.pids()  # 列出所有的进程PID,列表类型
    now_time = datetime.now()  # 当前时间时间轴

    with open(records_file_name, 'a', encoding="utf-8") as f1:
        # with open(problem_file_name, 'a', encoding="utf-8") as f2:
        dict_records = {}
        for i in p_ids:
            p = psutil.Process(i)  # 实例化一个Process对象，参数为进程PID
            p_username = p.username()
            p_status = p.status()  # 进程状态
            # if p_username == "caoyiping":
            p_name = p.name()  # 进程名
            p_memory_percent = p.memory_percent()
            if p_memory_percent > 5:
                f1.write("时间:{},名称:{},pid:{},状态:{},内存使用量:{}\n".format(now_time, p_name, i, p_status, p_memory_percent))
                    # records = {'id': i, 'name': p_name, 'memory_percent': p_memory_percent}
                    # dict_records[records['id']] = records
        # f2.write("{}\n".format(dict_records))


def write_record(mem_num, disk_num, cpu_num):
    """
    写入日志文件件，将每次执行的内存使用量、硬盘使用量、cpu使用量记录下来
    判断file_name是否存在，如果file_name不存在，则自动创建；如果存在，则直接添加
    :param mem_num: str 内存使用量
    :param disk_num: str 硬盘使用量
    :param cpu_num: str cpu使用量
    :return:
    """
    # 获取当前的文件路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_name = current_dir + "/server_record.txt"

    # 直接在后面添加进入
    with open(file_name, "a", encoding='utf-8') as f:
        now_time = datetime.now().strftime("%y-%m-%d %H:%M:%S")
        men_num_str = "{}:当前服务器内存使用量为{}%\n".format(now_time, mem_num)
        disk_num_str = "{}:当前服务器disk使用量为{}%\n".format(now_time, disk_num)
        cpu_num_str = "{}:当前服务器cpu使用量为{}%\n".format(now_time, cpu_num)
        f.write(men_num_str + disk_num_str + cpu_num_str)
        # 对需要发送警报的时候进行进程分析
        if mem_num > 80:
            f.write("内存警报\n" + analysis_pid())
        elif disk_num > 70:
            f.write("硬盘警报\n" + analysis_pid())
        elif cpu_num > 90:
            f.write("cpu警报\n" + analysis_pid())


def analysis_log():
    """
    分析日志 是否之前存在警报
    :return: 1为 内存警报 2为 硬盘警报 3为 cpu警报 0为 正常
    """
    # 获取当前的文件路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_name = current_dir + "/server_record.txt"
    with open(file_name, "r", encoding="utf-8") as f:
        read_rest = f.read()
        if "内存警报" in read_rest:
            return 1
        elif "硬盘警报" in read_rest:
            return 2
        elif "cpu警报" in read_rest:
            return 3
        else:
            return 0


def main():
    """
    执行操作
    :return:
    """
    menmory_num = mem()
    disk_num = disk()
    cpu_num = cpu()
    host_user = ""  # 主机邮箱
    host_passwd = ""
    host_smtp = ""  # 解析地址
    target_addr = ""  # 目标邮箱
    target_cc_addr = ""  # 抄送邮箱
    now_time = datetime.now().strftime("%y-%m-%d %H:%M:%S")  # 当前时间时间轴
    server_name = getfqdn(gethostname())  # 主机名

    yag = yagmail.SMTP(user=host_user, password=host_passwd, host=host_smtp)  # 发送邮件的函数

    if menmory_num > 80 and analysis_log() != 1:
        subject = "内存报警"
        contents = "{0}: 您的服务器{1}运行内存超过80%请尽快处理".format(now_time, server_name)
        yag.send(to=target_addr, subject=subject, contents=contents, cc=target_cc_addr)
        yag.close()
        analysis_pid()      # 对进程进行分析，并且写入到pid日志文件中
    # 如果硬盘数值超过70，三十分钟之内没有出现过的发送报警邮件
    elif disk_num > 70 and analysis_log() != 2:
        subject = "系统磁盘报警"
        contents = "{0}: 您的服务器{1}系统磁盘超过70%请尽快处理".format(now_time, server_name)
        yag.send(to=target_addr, subject=subject, contents=contents, cc=target_cc_addr)
        yag.close()
        analysis_pid()      # 对进程进行分析，并且写入到pid日志文件中
    # 如果cpu数值超过90，三十分钟之内没有出现过的发送报警邮件
    elif cpu_num > 90 and analysis_log() != 3:
        subject = "cpu报警"
        contents = "{0}: 您的服务器{1}cpu超过90%请尽快处理".format(now_time, server_name)
        yag.send(to='xxx@qq.com', subject=subject, contents=contents, cc=target_cc_addr)
        yag.close()
        analysis_pid()      # 对进程进行分析，并且写入到pid日志文件中


if __name__ == "__main__":
    write_record(mem(), disk(), cpu())
    main()
    analysis_pid()
