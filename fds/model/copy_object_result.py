from fds.model.put_object_result import PutObjectResult


class CopyObjectResult(PutObjectResult):
  def from_put_object_result(self, put_object_result):
    self.access_key_id = put_object_result.access_key_id
    self.bucket_name = put_object_result.bucket_name
    self.expires = put_object_result.expires
    self.object_name = put_object_result.object_name
    self.previous_version_id = put_object_result.previous_version_id
    self.signature = put_object_result.signature
    return self
