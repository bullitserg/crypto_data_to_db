certificate_data_insert_query = '''INSERT INTO
  certificate_data
  SET
  `server` = %(server)s,
  `storageNum` = %(storage_num)s,
  `storageName` = %(storage_name)s,
  orderNum = %(OrderNum)s,
  `serial` = %(Serial)s,
  subjKeyID = %(SubjKeyID)s,
  `issuer` = %(Issuer)s,
  `subject` = %(Subject)s,
  notValidBeforeDateTime = %(Not valid before)s,
  notValidAfterDateTime = %(Not valid after)s,
  privateKeyLink = %(PrivateKey Link)s,
  publicKeyAlgorithm = %(PublicKey Algorithm)s,
  signatureAlgorithm = %(Signature Algorithm)s,
  sha1Hash = %(SHA1 Hash)s,
  insertDateTime = %(datetime)s
  ;'''


crl_data_insert_query = '''INSERT INTO
crl_data
SET `server` = %(server)s,
    orderNum = %(OrderNum)s,
    subjKeyID = %(AuthKeyID)s,
    thisUpdateDateTime = %(ThisUpdate)s,
    nextUpdateDateTime = %(NextUpdate)s,
    insertDateTime = %(datetime)s
;'''


certificate_data_delete_query = '''DELETE
  FROM certificate_data
WHERE insertDateTime < SUBDATE(NOW(), INTERVAL %s MINUTE)
AND `server` = %s
;'''


crl_data_delete_query = '''DELETE
  FROM crl_data
WHERE insertDateTime < SUBDATE(NOW(), INTERVAL %s MINUTE)
AND `server` = %s
;'''

certificate_data_drop_active = '''UPDATE certificate_data cd
SET cd.active = 0
WHERE cd.active = 1
AND cd.`server` = %s
;'''

crl_data_drop_active = '''UPDATE crl_data cd
SET cd.active = 0
WHERE cd.active = 1
AND cd.`server` = %s
;'''


crl_data_drop_active_for_auth_key = '''UPDATE crl_data cd
SET cd.active = 0
WHERE cd.active = 1
AND cd.subjKeyID = %s
AND cd.`server` = %s
;'''