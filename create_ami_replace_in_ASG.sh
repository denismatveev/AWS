#!/bin/bash 

# this script based on 
# https://docs.aws.amazon.com/imagebuilder/latest/userguide/security-best-practices.html

# Some static variables

SECURITYGROUPS=
INSTANCETYPE=
KEYNAME=
AUTOSCALINGGROUPNAME=


usage()
{
    echo "Usage: $(basename $0) [Option]"
    echo ""
    echo " Options:"
    echo "  -i <identity>           Optional: ssh identity to connect to EC2 instance(private key) "
    echo "  -h                      Show this message."
    echo "  -a <ip addr>            Required: Public or local ip address of EC2 instance image to be created from "
    echo ""
}

if [  "$#" -eq 0 ];then
    usage
    exit 1
fi 

valid_ip()
{
    # returns 0 if ip is valid, otherwise returns not zero
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    echo $stat

}

# getopts
   while getopts ":hi:a:" opt
    do
     case "$opt" in
      h)
       usage
       exit 1
       ;;
      i)
       sshkey="$OPTARG"
       continue
       ;;
      a)
       ipaddr="$OPTARG"
       continue
       ;;
      ?)
       usage
       exit 1
       ;;
     esac
    done
shift $((OPTIND-1))
if [ -z "${ipaddr:+x}" ]; then
   usage
   exit 1;
fi

if [[ "$(valid_ip "$ipaddr")" != 0 ]] ; then 
   echo "Wrong IP address: "$ipaddr""
   usage
   exit 1;
fi
if [ -z "${sshkey:+x}" ]; then
   SSHCOMMAND="ssh centos@"$ipaddr" -p2222 /bin/bash" # The option -T will disable pseudo terminal allocation. Is it suitable for replacing '/bin/bash' ?
else 
   SSHCOMMAND="ssh -i $sshkey centos@"$ipaddr" -p2222 /bin/bash" # a bug is here
fi

FILES=(

        # Secure removal of RSA encrypted SSH host keys.
        "/etc/ssh/ssh_host_rsa_key"
        "/etc/ssh/ssh_host_rsa_key.pub"

        # Secure removal of ECDSA encrypted SSH host keys.
        "/etc/ssh/ssh_host_ecdsa_key"
        "/etc/ssh/ssh_host_ecdsa_key.pub"

        # Secure removal of ED25519 encrypted SSH host keys.
        "/etc/ssh/ssh_host_ed25519_key"
        "/etc/ssh/ssh_host_ed25519_key.pub"

        # Secure removal of "root" user approved SSH keys list.
        "/root/.ssh/authorized_keys"

        # Secure removal of "centos" user approved SSH keys list.
        "/home/centos/.ssh/authorized_keys"

        # Secure removal of file which tracks system updates
        "/etc/.updated"
        "/var/.updated"

        # Secure removal of file with aliases for mailing lists
        "/etc/aliases.db"

        # Secure removal of file which contains the hostname of the system
        "/etc/hostname"

        # Secure removal of files with system-wide locale settings
        "/etc/locale.conf"

        # Secure removal of cached GPG signatures of yum repositories
        "/var/cache/yum/x86_64/2/.gpgkeyschecked.yum"

        # Secure removal of audit framework logs
        "/var/log/audit/audit.log"

        # Secure removal of boot logs
        "/var/log/boot.log"

        # Secure removal of kernel message logs
        "/var/log/dmesg"

        # Secure removal of cloud-init logs
        "/var/log/cloud-init.log"

        # Secure removal of cloud-init output logs
        "/var/log/cloud-init-output.log"

        # Secure removal of cron logs
        "/var/log/cron"

        # Secure removal of aliases file for the Postfix mail transfer agent
        "/var/lib/misc/postfix.aliasesdb-stamp"

        # Secure removal of master lock for the Postfix mail transfer agent
        "/var/lib/postfix/master.lock"

        # Secure removal of spool data for the Postfix mail transfer agent
        "/var/spool/postfix/pid/master.pid"

        # Secure removal of history of Bash commands
        "/home/centos/.bash_history"

        # Secure removal of list of sudo users
        "/etc/sudoers.d/90-cloud-init-users"
)

CUSTOM_FILES=(
    "/var/lib/webalizer/*"
    "/var/www/usage/*"
    "/var/webmin/miniserv.log*"
    "/var/webmin/miniserv.error*"
    "/var/spool/mail/*"
    "/var/lib/auditbeat/beat.db"
    "/root/.mysql_history"
    "/home/centos/.mysql_history"
)

remove_files()
{
   declare -a FS=("${!1}")
   for FILE in "${FS[@]}"; do
       echo "Deleting the $FILE"
       sudo bash -c 'find '$FILE' -type f -exec shred -zuf {} \; 1>/dev/null 2>&1' || echo "Failed to delete '$FILE'. Skipping."
   done
}
REMOTE_CFILES=$(typeset -p CUSTOM_FILES)
REMOTE_FILES=$(typeset -p FILES)
$SSHCOMMAND <<EOF
$REMOTE_CFILES
$REMOTE_FILES
$(typeset -f remove_files)
echo "Stopping some services ..."
sudo systemctl stop filebeat
sudo systemctl stop auditbeat
sudo systemctl stop packetbeat
sudo /etc/init.d/webmin stop
# Secure removal of system activity reports/logs
if [[ \$( sudo bash -c 'find /var/log/sa/sa* -type f' | sudo bash -c 'wc -l' ) -gt 0 ]]; then
      echo "Deleting /var/log/sa/sa*"
      sudo bash -c 'shred -zuf /var/log/sa/sa*'
fi

# Secure removal of DHCP client leases that have been acquired
if [[ \$( sudo bash -c 'find /var/lib/dhclient/dhclient*.lease -type f' | sudo bash -c 'wc -l' ) -gt 0 ]]; then
      echo "Deleting /var/lib/dhclient/dhclient*.lease"
      sudo bash -c 'shred -zuf /var/lib/dhclient/dhclient*.lease'
fi

# Secure removal of cloud-init files
if [[ \$( sudo bash -c 'find /var/lib/cloud -type f' | sudo bash -c 'wc -l' ) -gt 0 ]]; then
      echo "Deleting files within /var/lib/cloud/*"
      sudo bash -c 'find /var/lib/cloud -type f -exec shred -zuf {} \;'
fi

# Secure removal of temporary files
if [[ \$( sudo bash -c 'find /var/tmp -type f' | sudo bash -c 'wc -l' ) -gt 0 ]]; then
      echo "Deleting files within /var/tmp/*"
      sudo bash -c 'find /var/tmp -type f -exec shred -zuf {} \;'
fi

# Shredding is not guaranteed to work well on rolling logs

# Removal of system logs
if [[ -f "/var/lib/rsyslog/imjournal.state" ]]; then
      echo "Deleting /var/lib/rsyslog/imjournal.state"
      sudo bash -c 'shred -zuf /var/lib/rsyslog/imjournal.state'
      sudo bash -c 'rm -f /var/lib/rsyslog/imjournal.state'
fi

# Removal of journal logs
if [[ \$( sudo bash -c 'ls /var/log/journal/' | sudo bash -c 'wc -l' ) -gt 0 ]]; then
      echo "Deleting /var/log/journal/*"
      sudo bash -c 'find /var/log/journal/ -type f -exec shred -zuf {} \;'
      sudo bash -c 'rm -rf /var/log/journal/*'
fi
# Deleting all log files
echo "Deleting all log files in /var/log/, directories will remain as is"
sudo bash -c 'find /var/log/ -type f -exec shred -zuf {} \;'
echo "Deleting filebeat registered files"
sudo bash -c 'find /var/lib/filebeat/registry/filebeat/ -type f -exec shred -zuf {} \;'
sudo bash -c 'rmdir /var/lib/filebeat/registry/filebeat/'

remove_files CUSTOM_FILES[@]
remove_files FILES[@] # removing the last, because contains sudoers file which necessary to perform sudo accross all the script 
echo "Erasing files done"
EOF

############
# Functions to interact with AWS
export AWS_PAGER=""
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_DEFAULT_REGION=eu-west-2

get_instance_id()
{
  echo "Getting instance ID"
  if [ -z "${1:+x}" ];then
    echo "Function didn't receive ip address of the instance. Exit"
    exit 2
  fi
  local ip=$1
  local instance_id
  instance_id=$(/usr/local/bin/aws ec2 describe-instances --filters Name=ip-address,Values="$ip" --query "Reservations[*].Instances[*].InstanceId" --output text)
  if [ $? != 0 ]; then
    echo "While getting instance ID AWS API returned an error. Exit."
    exit 2
  fi
  echo "$instance_id"
}

create_ami()
{
  local instance_id=$1
  if [ -z "${1:+x}" ];then
    echo "Function didn't receive instance_id. Exit."
    exit 2
  fi
  echo "Creating AMI from instance ""$instance_id"
# n is a count of AMI created on this date
  n=$(/usr/local/bin/aws ec2 describe-images --filters Name=name,Values=floralfrog-$(date +%Y%m%d)-* --query 'Images[*].[ImageId]' --output text | wc -l)
  local ami_name=floralfrog-$(date +%Y%m%d)-$n

  local ami_id=$(/usr/local/bin/aws ec2 create-image --name "$ami_name" --instance-id "$instance_id" --output text)
  if [ $? != 0 ]; then
    echo "While AMI was being created AWS API returned an error. Exit"
    exit 2
  fi
  echo "$ami_id"
}


# Then in autoscaling group press "Start instance Refresh" to terminate instances with previous version AMI and run new AMIs
NewLaunchConfiguration()
{
    if [[ -z ${1:+x} ]]; then
       echo "No AMI provided for creating LaunchConfiguration"
       exit 3
    fi
    local ami=$1
    echo "Creating new Launch Configuration with new AMI"
    # Get number of LaunchConfigurations created on given date
    local n=$(/usr/local/bin/aws autoscaling describe-launch-configurations --query 'reverse(sort_by(LaunchConfigurations, &CreatedTime))[0].[LaunchConfigurationName]' | grep floralfrog-$(date +%Y%m%d) | wc -l)
    NewLaunchConfigurationName=floralfrog-$(date +%Y%m%d)-$n
    # Get the latest LaunchConfiguration
    NewLaunchConfiguration=$(/usr/local/bin/aws autoscaling create-launch-configuration --launch-configuration-name "$NewLaunchConfigurationName" --image-id "$ami" --security-groups "$SECURITYGROUPS" --instance-type "$INSTANCETYPE" --instance-monitoring Enabled=true --associate-public-ip-address --key-name "$KEYNAME")
   if [[ $? -ne 0 ]]; then
      echo "Creating new Launch Configuration failed. Check AWS Cloud for details. Probably Launch Configuration Limit exceeded."
      exit 3
   fi
   echo $NewLaunchConfiguration

}
Reconfigure_AutoScalingGroup()
{
    echo "Reconfiguring AutoScaling Group to use new Launch Configuration"
    if [[ -z ${1:+x} ]];then
        echo "No LaunchConfigurationName provided for Autoscaling group"
        exit 3;
    fi
    LC=$1
     /usr/local/bin/aws/ autoscaling update-auto-scaling-group --auto-scaling-group-name "$AUTOSCALINGGROUPNAME" --launch-configuration-name  "$LC"
}
GetAMIState()
{
    if [[ -z ${1:+x} ]]; then
       echo "No AMI provided for getting state"
       exit 3
    fi
    local ami=$1
    local ami_state=$(/usr/local/bin/aws ec2 describe-images --image-ids "$ami" --query 'Images[*].[State]')    
    echo $ami_state

}
# main
instance=$(get_instance_id "$ipaddr")
ami=$(create_ami "$instance")
# waiting while image is being prepared
while[ $(GetAMIStatus "$ami") != "available" ]
do
    sleep 5;
done

NewLC=$(NewLaunchConfiguration "$ami")

Reconfigure_AutoScalingGroup "$NewLC"
echo "Congratulation! New Launch Configuration in an Autoscaling Group has been created."
