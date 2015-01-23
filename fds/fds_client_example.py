import time

from fds_client_configuration import FDSClientConfiguration
from galaxy_fds_client import GalaxyFDSClient

access_key = 'your_app_access_key'
access_secret = 'your_app_secret_key'
config = FDSClientConfiguration()
bucket_name = 'fds-python-example-%d' % int(time.time());

fds_client = GalaxyFDSClient(access_key, access_secret, config)

# Check and create the bucket
if not fds_client.does_bucket_exist(bucket_name):
  fds_client.create_bucket(bucket_name)

#####################
# Put a string object
object_name = "test1.txt"
object_content = "Hello world! This is a simple test!"
fds_client.put_object(bucket_name, object_name, object_content)

# Get the object content
read_object_content = fds_client.get_object(bucket_name, object_name)
print read_object_content

# Delete the object
fds_client.delete_object(bucket_name, object_name)
#####################

#####################
# Put a file object
object_name = 'fds_client_example.py'
object_content = open(object_name, 'r')
fds_client.put_object(bucket_name, object_name, object_content)
object_content.close()

# Get the object content
read_object_content = fds_client.get_object(bucket_name, object_name)
#print read_object_content

# Streaming get the object
for data in fds_client.get_object(bucket_name, object_name, streaming=True):
  print data

# Delete the object
fds_client.delete_object(bucket_name, object_name)
#####################

# Delete the bucket
fds_client.delete_bucket(bucket_name)
