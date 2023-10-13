import json
import yaml

ASSAY_TYPES_YAML = '/tmp/assay_types.yaml'

PREAMBLE = [
    {"type": "note",
     "match": "metadata_schema_id == null",
     "value": "{'not_dcwg': true, 'is_dcwg': false}",
     "rule_description": "Preamble rule identifying DCWG"
     },
    {"type": "note",
     "match": "metadata_schema_id != null",
     "value": "{'not_dcwg': false, 'is_dcwg': true}",
     "rule_description": "Preamble rule identifying non-DCWG"     
     },
    {"type": "note",
     "match": "not_dcwg and assay_type == null and data_types != null",
     "value": "{'is_derived': true, 'not_derived': false}",
     "rule_description": "Preamble rule identifying derived non-DCWG"     
     },
    {"type": "note",
     "match": "not_dcwg and is_derived == null",
     "value": "{'is_derived': false, 'not_derived': true}",
     "rule_description": "Preamble rule identifying non-derived non-DCWG"
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
                           ),
                 "rule_description": f"non-DCWG primary {canonical_name}"
                 }
            )
        else:
            json_block.append(
                {"type": "match",
                 "match": f"not_dcwg and is_derived and data_types[0] in [{', '.join(all_assay_types)}]",
                 "value": (f"{{'assaytype': '{canonical_name}',"
                           f" 'vitessce_hints': {vitessce_hints},"
                           f" 'description': '{description}'}}"
                           ),
                 "rule_description": f"non-DCWG derived {canonical_name}"
                 }
            )
    # Histology example
    json_block.append(
        {"type": "match",
         "match": f"is_dcwg and dataset_type == 'Histology'",
         "value": ("{'assaytype': 'histology',"
                   " 'vitessce_hints': [],"
                   " 'description': 'Histology'}"
                   ),
         "rule_description": "DCWG Histology"
         }
    )

    # 10X Multiome example
    json_block.append(
        {"type": "match",
         "match": f"is_dcwg and dataset_type == '10X Multiome'",
         "value": ("{'assaytype': '10x_multiome',"
                   " 'vitessce_hints': [],"
                   " 'description': '10X Multiome',"
                   " 'can_contain': ['ATACseq', 'RNAseq', 'Histology']}"
                   ),
         "rule_description": "DCWG 10X Multiome"
         }
    )

    # RNAseq example
    json_block.append(
        {"type": "match",
         "match": ("is_dcwg and dataset_type == 'RNAseq' "
                   " and assay_input_entity == 'single nucleus'"
                   " and barcode_size == 16"
                   " and umi_size == 12"
                   ),
         "value": ("{'assaytype': 'snRNAseq-10xGenomics-v3',"
                   " 'vitessce_hints': [],"
                   " 'description': 'snRNA-seq (10x Genomics v3)'}"
                   ),
         "rule_description": "DCWG 10X snRNAseq v3"
         }
    )

    # ATACseq example
    json_block.append(
        {"type": "match",
         "match": ("is_dcwg and dataset_type == 'ATACseq' "
                   " and assay_input_entity == 'single nucleus'"
                   " and barcode_read =~~ 'Read 2'"
                   ),
         "value": ("{'assaytype': 'snATACseq',"
                   " 'vitessce_hints': [],"
                   " 'description': 'snATACseq'}"
                   ),
         "rule_description": "DCWG snATACseq"
         }
    )    

    with open('/tmp/testing_rule_chain.json', 'w') as ofile:
        json.dump(json_block, ofile, indent=4)

    print('done')

if __name__ == '__main__':
    main()
