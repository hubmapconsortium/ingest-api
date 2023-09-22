import json
import yaml

ASSAY_TYPES_YAML = '/tmp/assay_types.yaml'

PREAMBLE = [
    {"type": "note",
     "match": "metadata_schema_id == null",
     "value": "{'not_dcwg': true, 'is_dcwg': false}"
     },
    {"type": "note",
     "match": "metadata_schema_id != null",
     "value": "{'not_dcwg': false, 'is_dcwg': true}"
     },
    {"type": "note",
     "match": "not_dcwg and assay_type == null and data_types != null",
     "value": "{'is_derived': true, 'not_derived': false}"
     },
    {"type": "note",
     "match": "not_dcwg and is_derived == null",
     "value": "{'is_derived': false, 'not_derived': true}"
     },
]

def main() -> None:
    with open(ASSAY_TYPES_YAML) as f:
        old_assay_types_dict = yaml.safe_load(f)
    
    json_block = PREAMBLE
    for canonical_name in old_assay_types_dict:
        type_dict = old_assay_types_dict[canonical_name]
        all_assay_types = ([canonical_name]
                           + [elt for elt in type_dict.get('alt-names', [])
                              if isinstance(elt, str)])
        all_assay_types = ["'" + tp + "'" for tp in all_assay_types]
        vitessce_hints = type_dict.get('vitessce-hints', [])
        description = type_dict.get('description', '')
        print(type_dict)
        if type_dict['primary']:
            json_block.append(
                {"type": "match",
                 "match": f"not_dcwg and not_derived and assay_type in [{', '.join(all_assay_types)}]",
                 "value": (f"{{'assaytype': '{canonical_name}',"
                           f" 'vitessce_hints': {vitessce_hints},"
                           f" 'description': '{description}'}}"
                           )
                 }
            )
        else:
            json_block.append(
                {"type": "match",
                 "match": f"not_dcwg and is_derived and data_types[0] in [{', '.join(all_assay_types)}]",
                 "value": (f"{{'assaytype': '{canonical_name}',"
                           f" 'vitessce_hints': {vitessce_hints},"
                           f" 'description': '{description}'}}"
                           )
                 }
            )
    # Histology example
    json_block.append(
        {"type": "match",
         "match": f"is_dcwg and dataset_type == 'Histology'",
         "value": ("{'assaytype': 'histology',"
                   " 'vitessce_hints': [],"
                   " 'description': 'Histology'}"
                   )
         }
    )

    with open('/tmp/testing_rule_chain.json', 'w') as ofile:
        json.dump(json_block, ofile, indent=4)

    print('done')

if __name__ == '__main__':
    main()
