import time
import sys

from fds.fds_client_configuration import FDSClientConfiguration
from fds.galaxy_fds_client import GalaxyFDSClient
from fds.galaxy_fds_client_exception import GalaxyFDSClientException
from fds.model.permission import AccessControlList
from fds.model.permission import Grant
from fds.model.permission import Grantee
from fds.model.permission import Permission

# Create default client
access_key = 'your_access_key'
access_secret = 'your_access_secret'
config = FDSClientConfiguration()
bucket_name = 'fds-python-example-%d' % int(time.time())

fds_client = GalaxyFDSClient(access_key, access_secret, config)

#####################
# List buckets
buckets = fds_client.list_buckets()
print 'buckets list:'
for bucket in buckets:
  print bucket
print

# Check and create the bucket
if not fds_client.does_bucket_exist(bucket_name):
  fds_client.create_bucket(bucket_name)
#####################

#####################
# Put a string object
object_name = 'test1.txt'
object_content = 'Hello world! This is a simple test!'
fds_client.put_object(bucket_name, object_name, object_content)

# Get the object content
obj = fds_client.get_object(bucket_name, object_name)
for chunk in obj.stream:
  sys.stdout.write(chunk)
print '\n'

# Download the object file
data_file = "/tmp/fds_file"
client.download(bucket_name, object_name, data_file)
data_file2 = "/tmp/fds_file2"
client.download_object_with_uri("fds://" + bucket_name + "/" + object_name, data_file2)

# Delete the object
fds_client.delete_object(bucket_name, object_name)
#####################

#####################
# Put a file object
object_name = 'fds_client_example.py'
object_content = open(object_name, 'r')
fds_client.put_object(bucket_name, object_name, object_content)
object_content.close()

# Generate a pre-signed url
import urllib2
url = fds_client.generate_presigned_uri(None, bucket_name, object_name,
    time.time() * 1000 + 60000)

# Get the object content
print urllib2.urlopen(url).read()

# Delete the object
fds_client.delete_object(bucket_name, object_name)
#####################

#####################
# Create another client
other_ak = 'other_access_key' # corresponding developerId is 109901
other_access_secret = 'other_access_secret'
other_developerId = 'other_developerId'
other_client = GalaxyFDSClient(other_ak, other_access_secret)

# Create a object and grant READ permission to others
object_name = 'shared-object'
fds_client.put_object(bucket_name, object_name, 'shared_content')
object_acl = AccessControlList()
object_acl.add_grant(Grant(Grantee(other_developerId), Permission.READ))
fds_client.set_object_acl(bucket_name, object_name, object_acl)
# Read the shared object by another client
for chunk in other_client.get_object(bucket_name, object_name).stream:
    sys.stdout.write(chunk)
print '\n'

# Grant FULL_CONTROL permission of bucket to others
bucket_acl = AccessControlList()
bucket_acl.add_grant(Grant(Grantee(other_developerId), Permission.FULL_CONTROL))
fds_client.set_bucket_acl(bucket_name, bucket_acl)

# Post an object by others
result = other_client.post_object(bucket_name, 'post')
print result.object_name
other_client.delete_object(bucket_name, result.object_name)
#####################

#####################
# List objects
result = fds_client.list_objects(bucket_name)
if result.is_truncated:
  while result.is_truncated:
    result = fds_client.list_next_batch_of_objects(result)
    for object_summary in result.objects:
      print object_summary.object_name
else:
  for object_summary in result.objects:
    print object_summary.object_name
#####################

# Delete the bucket
try:
  fds_client.delete_bucket(bucket_name)
except GalaxyFDSClientException, e:
  print e.message

fds_client.delete_object(bucket_name, object_name)
fds_client.delete_bucket(bucket_name)
