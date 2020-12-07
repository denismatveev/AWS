# AWS AMI preparation script

The script for preparing AWS AMI image. This script is connecting over ssh to a VM which will be used as a basement for AMI and deleting all logs, ssh keys and other sensitive data.
Then using AWS API launches creating an AMI.

To use the sctipt, firstly add your AWS credentials:
```
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
```

and replace the following if necessary:

```
export AWS_DEFAULT_REGION=eu-west-2
```

Secondly, put your own data here:
```
SECURITYGROUPS=
INSTANCETYPE=t2.medium 
KEYNAME=
AUTOSCALINGGROUPNAME=
```
Where 

`SECURITYGROUP` - a list of groups should be connected to the VM after launching

`INSTANCETYPE` - instance you want to launch

`KEYNAME` - ssh public key to be placed into VM from the keypair KEYNAME

`AUTOSCALINGGROUPNAME` - auto scaling group the instance should be connected to


Then run the script and wait until an instance will be launched. To monitor its status go to AWS console.
