# status error
PAGING_ERROR = "PAGING_ERROR"
VALIDATE_ERROR = "VALIDATE_ERROR"
USERNAME_IS_EXITS = "USERNAME_IS_EXITS"

DATE_NOT_GT = "DATE_NOT_GT"
DATE_NOT_GE = "DATE_NOT_GE"
DATE_NOT_LT = "DATE_NOT_LT"
DATE_NOT_LE = "DATE_NOT_LE"

LOCATION_INVALID = "LOCATION_INVALID"

VALUES_NOT_MATCH = "VALUE_NOT_MATCH"

UPLOAD_FILE_ERROR = "UPLOAD_FILE_ERROR"
CHECK_FILE_ERROR = "CHECK_FILE_ERROR"
FILE_SIZE_ERROR = "FILE_SIZE_ERROR"
SERVICE_FILE_ERROR = "SERVICE_FILE_ERROR"
SERVICE_TEMPLATE_ERROR = "SERVICE_TEMPLATE_ERROR"
DUPLICATE_ITEM = "DUPLICATE_ITEM"

# DATABASE ERROR
DATABASE_INSERT_FAILED = "DATABASE_INSERT_FAILED"
QUERY_DATA_ERROR = "QUERY_DATA_ERROR"
NOT_FOUND = "NOT_FOUND"
ID_NOT_FOUND = "ID_NOT_FOUND"
UNHANDLE_EXCEPTION = "UNHANDLE_EXCEPTION"
MULTIPLE_RESULT_FOUND_WITH_FILTER = "MULTIPLE_RESULT_FOUND_WITH_FILTER"

# CONFIGS
VALIDATE_PROVINCE = "VALIDATE_PROVINCE"
VALIDATE_DISTRICT = "VALIDATE_DISTRICT"
VALIDATE_TYPE_LOAN = "VALIDATE_TYPE_LOAN"
VALIDATE_LOAN_PRODUCT = "VALIDATE_LOAN_PRODUCT"
VALIDATE_PARTNER = "VALIDATE_PARTNER"
VALIDATE_BUSINESS_TYPE_SH = "VALIDATE_BUSINESS_TYPE_SH"
VALIDATE_TYPE_EXCEPTION = "VALIDATE_TYPE_EXCEPTION"
VALIDATE_RELATIONSHIP_OTHER_VALUE_FLAG = "VALIDATE_RELATIONSHIP_OTHER_VALUE_FLAG"
VALIDATE_VEHICLE_TYPE = "VALIDATE_VEHICLE_TYPE"

# CIC
CIC_IDENTITY_INVALID = "CIC_IDENTITY_INVALID"

# COLLATERAL
COLLATERAL_OWNER_INVALID = "COLLATERAL_OWNER_INVALID"
COLLATERAL_AUTHORIZED_PERSON_INVALID = "COLLATERAL_AUTHORIZED_PERSON_INVALID"
COLLATERAL_CERTIFICATE_PERSON_INVALID = "COLLATERAL_CERTIFICATE_PERSON_INVALID"
ITEM_REQUIRE_IN_LIST = "ITEM_REQUIRE_IN_LIST"
ITEM_FORBIDDEN_IN_LIST = "ITEM_FORBIDDEN_IN_LIST"

WORKFLOW_LOGGER_SERVICE_ERROR = "WORKFLOW_LOGGER_SERVICE_ERROR"
WORKFLOW_LOG_FAILED = "WORKFLOW_LOG_FAILED"

TOKEN_EXPIRED = "TOKEN_EXPIRED"
ERROR_INVALID_TOKEN = "ERROR_INVALID_TOKEN"
UNAUTHORIZED = "UNAUTHORIZED "
ACCESS_DENIED = "ACCESS_DENIED"
msg_templates = {
    # error
    PAGING_ERROR: "Can not found page!",
    FILE_SIZE_ERROR: "File size error !",
    SERVICE_FILE_ERROR: "Service file error!",
    SERVICE_TEMPLATE_ERROR: "Service template error!",

    DATE_NOT_GT: "ensure this value is greater then {limit_value}",
    DATE_NOT_GE: "ensure this value is greater or equal to {limit_value}",
    DATE_NOT_LT: "ensure this value is less than {limit_value}",
    DATE_NOT_LE: "ensure this value is less than or equal to {limit_value}",

    LOCATION_INVALID: "invalid location; province: '{province}' district: '{district}', ward: '{ward}'",

    VALUES_NOT_MATCH: "values not match; expected: '{expected}', actual: '{actual}' ",

    QUERY_DATA_ERROR: "Query data error",
    UNHANDLE_EXCEPTION: "Something went wrong",
    DATABASE_INSERT_FAILED: "insert failed",
    ID_NOT_FOUND: "'{id}' not found",
    NOT_FOUND: "NOT_FOUND",

    VALIDATE_PROVINCE: "Not found province",
    VALIDATE_DISTRICT: "Not found district",
    VALIDATE_TYPE_LOAN: "Not found type loan",
    VALIDATE_LOAN_PRODUCT: "Not found loan product",
    VALIDATE_PARTNER: "Not found partner",
    VALIDATE_BUSINESS_TYPE_SH: "Not found code business type SH",
    VALIDATE_TYPE_EXCEPTION: "Not found code type exception",
    VALIDATE_VEHICLE_TYPE: "Not found code vehicle type",
    MULTIPLE_RESULT_FOUND_WITH_FILTER: "'{filter}' multiple result found. Expected one",
    VALIDATE_RELATIONSHIP_OTHER_VALUE_FLAG: "Not found code other value flag",

    ITEM_REQUIRE_IN_LIST: "list must contain '{item}'",
    ITEM_FORBIDDEN_IN_LIST: "list can not contain '{item}'",

    # COLLATERAL
    COLLATERAL_OWNER_INVALID: "person_uuid '{person_uuid}' with owner_type: {owner_type} must define in {legal_person_types}",
    COLLATERAL_AUTHORIZED_PERSON_INVALID: "person_uuid '{person_uuid}' must define in legal_info",
    COLLATERAL_CERTIFICATE_PERSON_INVALID: "person_uuid '{person_uuid}' must define in owners",

    # CIC
    CIC_IDENTITY_INVALID: "identity uuid: '{uuid}', number: '{number}', type: '{type}' must define in legal_info",
    DUPLICATE_ITEM: "list not allow duplicate elements",

    WORKFLOW_LOGGER_SERVICE_ERROR: "workflow logger service error",
    WORKFLOW_LOG_FAILED: "workflow log failed - loan_type: {loan_type}, los_id: {los_id}, action: {action}, position: {position}, transition_id: {transition_id}",

    TOKEN_EXPIRED: "token expired",
    ERROR_INVALID_TOKEN: "error invalid token",
    UNAUTHORIZED: "unauthorized ",
    ACCESS_DENIED: "Access is denied"
}
