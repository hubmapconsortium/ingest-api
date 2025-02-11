import logging

LOGGER = logging.getLogger(__name__)

def merge_sources(source_type, this_source_type):
    initial_source_type = source_type  # for diagnostics
    if source_type is None:
        source_type = this_source_type
    elif source_type == this_source_type:
        pass
    else:
        if this_source_type.upper() == "HUMAN":
            source_type = "HUMAN"
    LOGGER.debug(f"merge_sources {initial_source_type} + {this_source_type} -> {source_type}")
    return source_type


def source_is_human(entity_id_list, fetch_json_fun):
    """
    entity_id_list may be list of samples or datasets,
    in uuid or HuBMAP/SENNET id form.
    fetch_json_fun is a function with signature:

        fetch_json_fun(entity_id: str) -> dict:

    which returns a dict of entity information, where
    entity_id can be a uuid or HuBMAP/SENNET ID specifying
    a dataset, sample, or source.  Typically it fetches
    the json by making a request of entity-api.

    """
    LOGGER.debug(f"source_is_human {entity_id_list}")
    try:
        source_type = None
        for elt in entity_id_list:
            entity_json = fetch_json_fun(elt)
            assert "entity_type" in entity_json, "entity json has no entity_type"
            entity_type = entity_json["entity_type"]
            if entity_type.upper() == "SOURCE":
                LOGGER.debug(f"{elt} is a Source")
                assert "source_type" in entity_json, "source json has no source_type"
                this_source_type = entity_json["source_type"]
            elif entity_type.upper() == "SAMPLE":
                LOGGER.debug(f"{elt} is a Sample")
                assert "source" in entity_json, "source json has no source"
                source = entity_json["source"]
                assert "source_type" in source, "source.source json has no source_type"
                this_source_type = source["source_type"]
            elif entity_type.upper() == "DATASET":
                LOGGER.debug(f"{elt} is a Dataset")
                assert "sources" in entity_json, "dataset json has no sources"
                this_source_type = None
                for idx, source in enumerate(entity_json["sources"]):
                    assert "source_type" in source, ("dataset.sources.source[{idx}]"
                                                     " has no source_type")
                    this_this_source_type = source["source_type"]
                    this_source_type = merge_sources(this_source_type,
                                                     this_this_source_type)
            else:
                raise AssertionError(f"Unsupported entity json type {entity_type}")

            source_type = merge_sources(source_type, this_source_type)

        return source_type.upper() == "HUMAN" # we trapped partial human earlier
    except AssertionError as excp:
        LOGGER.debug(f"AssertionError, assuming HUMAN: {excp}")
        return True # fail safe
