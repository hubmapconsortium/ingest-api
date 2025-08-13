import requests
import yaml

# helper class to read and parse the provenance schema yaml file in entity-api
class ProvenanceSchemaHelper:
        
    def __init__(self, config):
        self.appconfig = config
        self.entity_schema_yaml = None
        self.metadata_properties_to_exclude = None
        
    # helper method to load yaml at the end of a url and put it into a dict
    def load_yaml_from_url(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            yaml_content = response.text
            data = yaml.safe_load(yaml_content)
            return data
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error fetching yaml from {url}: {e}")
        except yaml.YAMLError as e:
            raise Exception(f"Error parsing YAML content from {url}: {e}")
        
    #get the schema yaml file defined by entity-api and convert to a dict
    def get_entity_schema_yaml(self):
        if not self.entity_schema_yaml is None:
            return self.get_entity_schema_yaml
        
        if not 'SCHEMA_YAML_URL' in  self.appconfig:
            raise Exception("ERROR: SCHEMA_YAML_URL property not found in app.cfg")
        
        self.entity_schema_yaml = self.load_yaml_from_url(self.appconfig['SCHEMA_YAML_URL'])
        
        return self.entity_schema_yaml
    
    #get the list of Dataset.metadata.* properties that excluded from public response
    def get_metadata_properties_to_exclude(self):
        if not self.metadata_properties_to_exclude is None:
            return self.metadata_properties_to_exclude

        yml = self.get_entity_schema_yaml()
        if 'ENTITIES' in yml and 'Dataset' in yml['ENTITIES'] and 'excluded_properties_from_public_response' in yml['ENTITIES']['Dataset']:
            self.metadata_properties_to_exclude = []
            for xprops in yml['ENTITIES']['Dataset']['excluded_properties_from_public_response']:
                if isinstance(xprops, dict) and 'metadata' in xprops.keys():
                    for prop in xprops['metadata']:
                        if not prop in self.metadata_properties_to_exclude:
                            self.metadata_properties_to_exclude.append(prop)
            return self.metadata_properties_to_exclude
        else:
            raise Exception("Unable to locate Dataset excluded_properties_from_public_response in entity provenance schema yaml file")    
