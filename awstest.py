import boto3
ec2 = boto3.resource('ec2')

instances = ec2.instances.filter()
key_pair = ec2.KeyPair('MyKeyPair')

print key_pair.key_name

for instance in instances:
    print(instance.id, instance.state["Name"], instance.public_dns_name)


    
    
if True:
	ids = [i.id for i in instances]
	try:
		ec2.instances.filter(InstanceIds=ids).stop()
		ec2.instances.filter(InstanceIds=ids).terminate()
	except Exception as e:
		print e

if False:
	print ec2.create_instances(
		ImageId='ami-f95ef58a', 
		InstanceType='t2.micro',
		SecurityGroupIds= [ 'sg-001d6367' ],
		MinCount=1, 
		MaxCount=1 )