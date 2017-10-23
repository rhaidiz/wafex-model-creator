
class AslanppModel:
    """ Represents an ASLan++ model. """
    # aslanpp constants
    _page_constants = set()
    _params_constants = set()
    _taglist = set()

    # aslanpp variables
    _params_webapp_variables = set()

    _webapp_branch = ""
    _client_branch = ""

    # database
    _sql_file = ""
    _aslanpp_tables = set()
    _init_database = ""
    
    # concretization
    _concretization = dict()
