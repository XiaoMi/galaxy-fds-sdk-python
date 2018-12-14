class UploadPartResultList(dict):
  """
  The Upload Part Result List class
  """

  def __init__(self, json):
    if json:
      self.uploadPartResultList = json['uploadPartResultList']

  @property
  def uploadPartResultList(self):
    return self.uploadPartResultList

  @uploadPartResultList.setter
  def uploadPartResultList(self, upload_part_result_list):
    self['uploadPartResultList'] = upload_part_result_list
