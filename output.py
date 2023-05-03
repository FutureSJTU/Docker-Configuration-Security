import paramiko
import subprocess
import os
import json
from decimal import *

# 读取配置文件
# config_path = os.getcwd() + os.sep + 'config.json'
# with open(config_path) as T:
#     config = json.loads(T.read())

# 建立SSH连接
# IP_address = config['IP_address']
# username = config['username']
# password = config['password']
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(IP_address,username,password)

# 发起检测命令
# stdin, stdout, stderr = ssh.exec_command("sudo -s")
# pswd = '{}\n'.format(password)
# stdin.write(pswd)
# stdin,stdout, stderr = ssh.exec_command('sudo inspec exec cis-docker-benchmark')
p = subprocess.Popen(["inspec", "exec", "cis-docker-benchmark"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

# 获取检测结果
result=p.stdout.read().decode('utf-8')
print(result)

print("---------------------------------------")

# 低威胁等级
hosts = ['host-1.3','host-1.4','host-1.6','host-1.7','host-1.8','host-1.9','host-1.10','host-1.11','host-1.12','host-1.13','host-1.14','host-1.15']
hostinfos = ['Harden the container host',
             'Remove all non-essential services from the host',
             'Only allow trusted users to control Docker daemon',
             'Audit docker daemon',
             'Audit Docker files and directories - /var/lib/docker',
             'Audit Docker files and directories - /etc/docker',
             'Audit Docker files and directories - docker.service',
             'Audit Docker files and directories - docker.socket',
             'Audit Docker files and directories - /etc/default/docker',
             'Audit Docker files and directories - /etc/docker/daemon.json',
             'Audit Docker files and directories - /usr/bin/docker-containerd',
             'Audit Docker files and directories - /usr/bin/docker-runc']

print("威胁等级：低")

num = 0
for host in hosts:
    if result.find('↺  '+host) >= 0:
        print('\033[33m[note]\033[0m'+host+': '+hostinfos[num])
    elif result.find('✔  '+host) >= 0:
        print('\033[32m[pass]\033[0m'+host + ': ' + hostinfos[num])
    elif result.find('×  '+host) >= 0:
        print('\033[31m[warn]\033[0m'+host + ': ' + hostinfos[num])
    num = num + 1

# Docker版本
dockers = ['docker-2.8','docker-2.19',
           'docker-3.19','docker-3.20',
           'docker-4.2','docker-4.3','docker-4.4','docker-4.6','docker-4.7','docker-4.8','docker-4.10','docker-4.11',
           'docker-5.1','docker-5.2','docker-5.27']
dockerinfos = ['Enable user namespace support',
               'Encrypt data exchanged between containers on different nodes on the overlay network',
               'Verify that /etc/default/docker file ownership is set to root:root',
               'Verify that /etc/default/docker file permissions are set to 644 or more restrictive',
               'Use trusted base images for containers',
               'Do not install unnecessary packages in the container',
               'Rebuild the images to include security patches',
               'Add HEALTHCHECK instruction to the container image',
               'Do not use update instructions alone in the Dockerfile',
               'Remove setuid and setgid permissions in the images',
               'Do not store secrets in Dockerfiles',
               'Install verified packages only',
               'Verify AppArmor Profile, if applicable',
               'Verify SELinux security options, if applicable',
               'Ensure docker commands always get the latest version of the image']



num = 0
for docker in dockers:
    if result.find('↺  '+docker) >= 0:
        print('\033[33m[note]\033[0m'+docker+': '+dockerinfos[num])
    elif result.find('✔  '+docker) >= 0:
        print('\033[32m[pass]\033[0m'+docker + ': ' + dockerinfos[num])
    elif result.find('×  '+docker) >= 0:
        print('\033[31m[warn]\033[0m'+docker + ': ' + dockerinfos[num])
    num = num + 1

# 中威胁等级
print('威胁等级：中')

mediums = ['docker-2.1','docker-2.2','docker-2.3','docker-2.4','docker-2.5','docker-2.6','docker-2.7',
           'docker-2.9','docker-2.10','docker-2.11','docker-2.12','docker-2.13','docker-2.14',
           'docker-2.15','docker-2.16','docker-2.17','docker-2.18','docker-2.20','docker-2.21','docker-2.22','docker-2.23','docker-2.24'
           'docker-3.1','docker-3.5','docker-4.5','docker-4.9','docker-5.9','docker-5.10']

mediuminfos = ['Restrict network traffic between containers',
               'Set the logging level',
               'Allow Docker to make changes to iptables',
               'Do not use insecure registries',
               'Do not use the aufs storage driver',
               'Configure TLS authentication for Docker daemon',
               'Set default ulimit as appropriate',
               'Confirm default cgroup usage',
               'Do not change base device size until needed',
               'Use authorization plugin',
               'Configure centralized and remote logging',
               'Disable operations on legacy registry (v1)',
               'Enable live restore',
               'Do not enable swarm mode, if not needed',
               'Control the number of manager nodes in a swarm',
               'Bind swarm services to a specific host interface',
               'Disable Userland Proxy',
               'Apply a daemon-wide custom seccomp profile, if needed',
               'Avoid experimental features in production',
               'Use Docker\\\'s secret management commands for managing secrets in a Swarm cluster',
               'Run swarm manager in auto-lock mode',
               'Rotate swarm manager auto-lock key periodically',
               'Verify that docker.service file ownership is set to root:root',
               'Verify that /etc/docker directory ownership is set to root:root',
               'Enable Content trust for Docker',
               'Use COPY instead of ADD in Dockerfile',
               'Do not share the hosts network namespace',
               'Limit memory usage for container'
               ]

mediums3=['docker-3.1','docker-3.2','docker-3.3','docker-3.4','docker-3.5','docker-3.6','docker-3.7',
          'docker-3.8','docker-3.9','docker-3.10','docker-3.11','docker-3.12','docker-3.13','docker-3.14',
          'docker-3.15','docker-3.16','docker-3.17','docker-3.18',]
mediuminfos3=[]

mediums4=['docker-4.1','docker-4.5','docker-4.9']
mediuminfos4=[]

mediums5=['docker-5.4','docker-5.5','docker-5.6','docker-5.7','docker-5.8','docker-5.9','docker-5.10',
          'docker-5.11','docker-5.12','docker-5.13','docker-5.14','docker-5.15','docker-5.16','docker-5.17',
          'docker-5.18','docker-5.19','docker-5.20','docker-5.21','docker-5.22','docker-5.23','docker-5.24',
          'docker-5.25','docker-5.26']
mediuminfos5=[]

num = 0
for medium in mediums:
    if result.find('↺  '+medium) >= 0:
        print('\033[33m[note]\033[0m'+medium+': '+ mediuminfos[num])
    elif result.find('✔  '+medium) >= 0:
        print('\033[32m[pass]\033[0m'+medium + ': ' + mediuminfos[num])
    elif result.find('×  '+medium) >= 0:
        print('\033[31m[warn]\033[0m'+medium + ': ' + mediuminfos[num])
    num = num + 1

# 高威胁等级
print('威胁等级：高')
highs = ['self-define 1','self-define 2','self-define 3','self-define 4','self-define 5','self-define 6','self-define 7','self-define 8','self-define 9','self-define 10']
highinfos=['docker-runc CVE-2019-5736',
           'docker-cp CVE-2019-14271',
           'containerd-shim CVE-2020-15257',
           'dirtycow CVE-2016-5195',
           'Capabilities Escaping--CAP_SYS_MODULE',
           'Capabilities Escaping--CAP_DAC_READ_SEARCH',
           'Capabilities Escaping--CAP_SYS_ADMIN',
           'Capabilities Escaping--CAP_SYS_PTRACE',
           'Procfs Escaping',
           'docker.sock Escaping']

num = 0
for high in highs:
    if result.find('↺  '+high+':') >= 0:
        print('\033[33m[note]\033[0m'+high+': '+highinfos[num])
    elif result.find('✔  '+high+':') >= 0:
        print('\033[32m[pass]\033[0m'+high + ': ' + highinfos[num])
    elif result.find('×  '+high+':') >= 0:
        print('\033[31m[warn]\033[0m'+high + ': ' + highinfos[num])
    num = num + 1


# terminal
while(1):
    number = input('\033[0m查看详细信息，请输入编号（输入0退出）：\033[0m')

    # 高威胁等级
    if number in highs:
        start = result.find('↺  ' + number + ':')
        if start < 0:
            start = result.find('✔  ' + number + ':')
            if start < 0:
                start = result.find('×  ' + number + ':')
        end = result.find('self-define', start + 20) - 5
        print(result[start:end])
        continue
    temp = number

    if temp.replace(".",'').isdigit():
        number = float(number)
        intpart = int(number)
        decimalpart = Decimal(str(number)) - Decimal(intpart)
        decimalpart = str((decimalpart*10).normalize())

        if not decimalpart.isdigit():
            decimalpart = Decimal(decimalpart)*10
            print(decimalpart)
    # 低威胁等级
        decimalpart = int(decimalpart)
        if number == 0:
            break
        elif number < 2.0:
            start = int(result.find('host-'+str(intpart) + '.' + str(decimalpart)))
            if start:
                sign = 1
                while(1):
                    end = int(result.find('host-'+str(intpart) + '.' + str(decimalpart+sign)))
                    sign = sign + 1
                    if end > 0:
                        break
                start = start - 5
                end = end - 5
                print(result[start:end])
            else:
                print('\033[0m该编号不存在\033[0m')
                continue
    # 中威胁等级
        elif 2.0 < number < 7.0 :
            start = int(result.find('docker-' + str(intpart) + '.' + str(decimalpart)))
            if start:
                sign = 1
                while (1):
                    end = int(result.find('docker-' + str(intpart) + '.' + str(decimalpart+sign)))
                    sign = sign + 1
                    if end > 0:
                        break
                start = start - 5
                end = end - 5
                print(result[start: end])
            else:
                print('\033[0m该编号不存在\033[0m')
                continue
        else:
            print('\033[0m该编号不存在\033[0m')
            continue

    else:
        print('\033[0m请输入正确信息\033[0m')
        continue

