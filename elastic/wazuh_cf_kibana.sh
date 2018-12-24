#!/bin/bash
# Install Kibana instance using Cloudformation template
# Support for Amazon Linux

set -exf

elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
kibana_port=$(cat /tmp/wazuh_cf_settings | grep '^KibanaPort:' | cut -d' ' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2  | cut -d' ' -f1)
wazuh_master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
wazuh_api_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiPort:' | cut -d' ' -f2)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Downloading and installing JRE
url_jre="https://download.oracle.com/otn-pub/java/jdk/8u191-b12/2787e4a523244c269598db4e85c51e0c/jre-8u191-linux-x64.rpm"
jre_rpm="/tmp/jre-8-linux-x64.rpm"
curl -Lo ${jre_rpm} --header "Cookie: oraclelicense=accept-securebackup-cookie" ${url_jre}
rpm -qlp ${jre_rpm} > /dev/null 2>&1 || $(echo "Unable to download JRE. Exiting." && exit 1)
yum -y localinstall ${jre_rpm} && rm -f ${jre_rpm}

# Configuring Elastic repository
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-${elastic_major_version}.x]
name=Elasticsearch repository for ${elastic_major_version}.x packages
baseurl=https://artifacts.elastic.co/packages/${elastic_major_version}.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Installing Elasticsearch
yum -y install elasticsearch-${elastic_version}
chkconfig --add elasticsearch

# Installing Elasticsearch plugin for EC2
/usr/share/elasticsearch/bin/elasticsearch-plugin install --batch discovery-ec2

# Configuration file created by AWS Cloudformation template
# Because of it we set the right owner/group for the file
mv -f /tmp/wazuh_cf_elasticsearch.yml /etc/elasticsearch/elasticsearch.yml
chown elasticsearch:elasticsearch /etc/elasticsearch/elasticsearch.yml

# Configuring jvm.options
cat > /etc/elasticsearch/jvm.options << 'EOF'
-Xms16g
-Xmx16g
-XX:+UseConcMarkSweepGC
-XX:CMSInitiatingOccupancyFraction=75
-XX:+UseCMSInitiatingOccupancyOnly
-XX:+AlwaysPreTouch
-Xss1m
-Djava.awt.headless=true
-Dfile.encoding=UTF-8
-Djna.nosys=true
-XX:-OmitStackTraceInFastThrow
-Dio.netty.noUnsafe=true
-Dio.netty.noKeySetOptimization=true
-Dio.netty.recycler.maxCapacityPerThread=0
-Dlog4j.shutdownHookEnabled=false
-Dlog4j2.disable.jmx=true
-Djava.io.tmpdir=${ES_TMPDIR}
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/lib/elasticsearch
-XX:ErrorFile=/var/log/elasticsearch/hs_err_pid%p.log
8:-XX:+PrintGCDetails
8:-XX:+PrintGCDateStamps
8:-XX:+PrintTenuringDistribution
8:-XX:+PrintGCApplicationStoppedTime
8:-Xloggc:/var/log/elasticsearch/gc.log
8:-XX:+UseGCLogFileRotation
8:-XX:NumberOfGCLogFiles=32
8:-XX:GCLogFileSize=64m
9-:-Xlog:gc*,gc+age=trace,safepoint:file=/var/log/elasticsearch/gc.log:utctime,pid,tags:filecount=32,filesize=64m
9-:-Djava.locale.providers=COMPAT
EOF

# Configuring RAM memory in jvm.options
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
ram=$(( (${ram_gb} / 2) - 1 ))
if [ $ram -eq "0" ]; then ram=1; fi
sed -i "s/-Xms16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options
sed -i "s/-Xmx16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options

# Allowing unlimited memory allocation
echo 'elasticsearch soft memlock unlimited' >> /etc/security/limits.conf
echo 'elasticsearch hard memlock unlimited' >> /etc/security/limits.conf

# Starting Elasticsearch
service elasticsearch start
sleep 90

# Loading and tuning Wazuh alerts template
url_alerts_template="https://raw.githubusercontent.com/wazuh/wazuh/v${wazuh_version}/extensions/elasticsearch/wazuh-elastic6-template-alerts.json"
alerts_template="/tmp/wazuh-elastic6-template-alerts.json"
curl -Lo ${alerts_template} ${url_alerts_template}
sed -i 's/"index.refresh_interval": "5s"/"index.refresh_interval": "5s",/' ${alerts_template}
sed -i '/"index.refresh_interval": "5s",/ a\    "index.number_of_shards": 2,' ${alerts_template}
sed -i '/"index.number_of_shards": 2,/ a\    "index.number_of_replicas": 1' ${alerts_template}
curl -XPUT "http://${eth0_ip}:9200/_template/wazuh" -H 'Content-Type: application/json' -d@${alerts_template}

# Inserting Wazuh alert sample
alert_sample="/tmp/alert_sample.json"
curl -Lo ${alert_sample} "https://raw.githubusercontent.com/wazuh/wazuh/v${wazuh_version}/extensions/elasticsearch/alert_sample.json"
curl -XPUT "http://${eth0_ip}:9200/wazuh-alerts-3.x-"`date +%Y.%m.%d`"/wazuh/sample" -H 'Content-Type: application/json' -d@${alert_sample}
rm -f ${alert_sample}

# Installing Kibana
yum -y install kibana-${elastic_version}
chkconfig --add kibana

# Creating key and certificate
openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout /etc/kibana/kibana.key -out /etc/kibana/kibana.cert

# Configuring kibana.yml
cat > /etc/kibana/kibana.yml << EOF
elasticsearch.url: "http://${eth0_ip}:9200"
server.port: ${kibana_port}
server.host: "0.0.0.0"
server.ssl.enabled: true
server.ssl.key: /etc/kibana/kibana.key
server.ssl.certificate: /etc/kibana/kibana.cert
EOF

# Allow Kibana to listen on privileged ports
setcap 'CAP_NET_BIND_SERVICE=+eip' /usr/share/kibana/node/bin/node

# Configuring Kibana default settings
cat > /etc/default/kibana << 'EOF'
ser="kibana"
group="kibana"
chroot="/"
chdir="/"
nice=""
KILL_ON_STOP_TIMEOUT=0
NODE_OPTIONS="--max-old-space-size=4096"
EOF

# Installing Wazuh plugin for Kibana
/usr/share/kibana/bin/kibana-plugin install  https://packages.wazuh.com/wazuhapp/wazuhapp-${wazuh_version}_${elastic_version}.zip
cat >> /usr/share/kibana/plugins/wazuh/config.yml << 'EOF'
wazuh.shards: 1
wazuh.replicas: 1
wazuh-version.shards: 1
wazuh-version.replicas: 1
wazuh.monitoring.shards: 1
wazuh.monitoring.replicas: 1
EOF

# Configuring Wazuh API in Kibana plugin
api_config="/tmp/api_config.json"
api_time=$(($(date +%s%N)/1000000))

cat > ${api_config} << EOF
{
  "api_user": "wazuh_api_user",
  "api_password": "wazuh_api_password",
  "url": "https://wazuh_master_ip",
  "api_port": "wazuh_api_port",
  "insecure": "false",
  "component": "API",
  "cluster_info": {
    "manager": "wazuh-manager",
    "cluster": "disabled",
    "status": "disabled"
  }
}
EOF

sed -i "s/wazuh_api_user/${wazuh_api_user}/" ${api_config}
sed -i "s/wazuh_api_password/${wazuh_api_password}/" ${api_config}
sed -i "s/wazuh_master_ip/${wazuh_master_ip}/" ${api_config}
sed -i "s/wazuh_api_port/${wazuh_api_port}/" ${api_config}

curl -s -XPUT "http://${eth0_ip}:9200/.wazuh/wazuh-configuration/${api_time}" -H 'Content-Type: application/json' -d@${api_config}
rm -f ${api_config}

# Starting Kibana
service kibana start

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
