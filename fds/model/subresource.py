# -*- coding: utf-8 -*-
class SubResource(object):
  """SubResource is used to manage the subresource."""

  ACL = "acl"
  QUOTA = "quota"
  UPLOADS = "uploads"
  PART_NUMBER = "partNumber"
  UPLOAD_ID = "uploadId"
  STORAGE_ACCESS_TOKEN = "storageAccessToken"
  METADATA = "metadata"

  @staticmethod
  def get_all_subresource():
    """Return all the subresources"""

    return [SubResource.ACL,
            SubResource.QUOTA,
            SubResource.UPLOADS,
            SubResource.PART_NUMBER,
            SubResource.UPLOAD_ID,
            SubResource.STORAGE_ACCESS_TOKEN,
            SubResource.METADATA
    ]
