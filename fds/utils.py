def uri_to_bucket_and_object(uri):
  if uri.startswith("fds://") == False:
    return None, None

  bucket_object_pair = uri[6:].split('/', 1)
  bucket = bucket_object_pair[0]
  object = bucket_object_pair[1]
  return bucket, object
