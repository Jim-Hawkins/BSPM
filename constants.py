ERR_REC_NOT_SELECTED = "Please select a record"
ERR_MISSING_PARAMS = "Name, telephone, email and description are required"
ERR_DATA_NOT_VERIFIED ="Some data are not verified, please consider checking it"
ERR_FATAL_DECRYPT ="Fatal error while decrypting"

DATA_VERIFIED = "All the data is verified"

DB_NAME = "database.db"

pepe=False

if pepe:
    QUERY_INSERT = "INSERT INTO agenda VALUES(NULL, ?, ?, ?, ?);"
    QUERY_DELETE = "DELETE FROM agenda WHERE name = ?;"
    QUERY_UPDATE = "UPDATE agenda SET name = ?, telephone = ?, email = ?, description = ?  WHERE name = ? AND telephone = ? AND email = ? AND description = ?;"
    QUERY_GET    = "SELECT * FROM agenda;"

    QUERY_INSERT_IVSTORE = "INSERT INTO ivstore VALUES(NULL, ?, ?, ?, ?);"
    QUERY_DELETE_IVSTORE = "DELETE FROM ivstore WHERE 1=1;"

    QUERY_INSERT_SALT_HMAC_STORE = "INSERT INTO salt_hmac_store VALUES(NULL, ?, ?, ?, ?);"
    QUERY_DELETE_SALT_HMAC_STORE = "DELETE FROM salt_hmac_store WHERE 1=1;"

    QUERY_GET_IVSTORE         = "SELECT * FROM ivstore;"
    QUERY_GET_SALT_HMAC_STORE = "SELECT * FROM salt_hmac_store;"

    QUERY_GET_CRYPTO          = "SELECT * FROM cryptostore;"
    QUERY_DELETE_CRYPTO       = "DELETE FROM cryptostore WHERE 1=1;"
    QUERT_INSERT_CRYPTO       = "INSERT INTO cryptostore VALUES(NULL, ?);"

    QUERY_INSERT_HMAC = "INSERT INTO hmac VALUES (NULL ,?, ?, ?, ?);"
    QUERY_DELETE_HMAC = "DELETE FROM hmac WHERE 1=1;"
    QUERY_GET_HMAC = "SELECT * FROM hmac;"
else:
    QUERY_INSERT = "INSERT INTO password_info_X VALUES(NULL, ?, ?, ?, ?);"
    QUERY_DELETE = "DELETE FROM password_info_X WHERE name = ?;"
    #QUERY_UPDATE = "UPDATE password_info_X SET name = ?, login = ?, url = ?, description = ?  WHERE name = ? AND login = ? AND url = ? AND description = ?;"
    QUERY_UPDATE = "UPDATE password_info_X SET name = ?, description = ?, url = ?, login = ?  WHERE id = ?;"
    QUERY_GET    = "SELECT * FROM password_info_X;"

    QUERY_INSERT_IVSTORE = "INSERT INTO ivstore_X VALUES(NULL, ?, ?, ?, ?);"
    QUERY_DELETE_IVSTORE = "DELETE FROM ivstore_X WHERE 1=1;"

    QUERY_INSERT_SALT_HMAC_STORE = "INSERT INTO salt_hmac_store_X VALUES(NULL, ?, ?, ?, ?);"
    QUERY_DELETE_SALT_HMAC_STORE = "DELETE FROM salt_hmac_store_X WHERE 1=1;"

    QUERY_GET_IVSTORE         = "SELECT * FROM ivstore_X;"
    QUERY_GET_SALT_HMAC_STORE = "SELECT * FROM salt_hmac_store_X;"

    QUERY_GET_CRYPTO          = "SELECT * FROM cryptostore;"
    QUERY_DELETE_CRYPTO       = "DELETE FROM cryptostore WHERE 1=1;"
    QUERT_INSERT_CRYPTO       = "INSERT INTO cryptostore VALUES(NULL, ?);"

    QUERY_INSERT_HMAC = "INSERT INTO hmac_X VALUES (NULL ,?, ?, ?, ?);"
    QUERY_DELETE_HMAC = "DELETE FROM hmac_X WHERE 1=1;"
    QUERY_GET_HMAC = "SELECT * FROM hmac_X;"