import json
import yaml
import re
from pathlib import Path
from pprint import pprint
from collections import defaultdict

ASSAY_TYPES_YAML = '/tmp/assay_types.yaml'

INGEST_VALIDATION_TABLE_PATH = '/home/welling/git/hubmap/ingest-validation-tools/src/ingest_validation_tools/table-schemas/assays'
INGEST_VALIDATION_DIR_SCHEMA_PATH = '/home/welling/git/hubmap/ingest-validation-tools/src/ingest_validation_tools/directory-schemas'

SCHEMA_SPLIT_REGEX = r'(.+)-v(\d)'

CHAIN_OUTPUT_PATH = '/tmp/testing_rule_chain.json'

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
    {"type": "note",
     "match": "not_dcwg and not_derived and version == null",
     "value": "{'version': 0}",
     "rule_description": "Cover default schema version = 0 for non-DCWG metadata"
    },
]

def get_assay_list(table_schema_path):
    with open(table_schema_path) as f:
        dct = yaml.safe_load(f)
    try:
        assay_lst = []
        for fld_dct in dct['fields']:
            if 'name' not in fld_dct:
                continue
            if fld_dct['name'] == 'assay_type':
                assert 'constraints' in fld_dct
                assert 'enum' in fld_dct['constraints']
                assay_lst = fld_dct['constraints']['enum'][:]
        if not assay_lst:
            raise RuntimeError("No assay_type list found")
    except Exception as excp:
        raise RuntimeError(f"Parse of {table_schema_path.name} failed: {excp}")
    return assay_lst


def test_is_hca(table_schema_path):
    with open(table_schema_path) as f:
        for line in f:
            if (line.lower().startswith('# include:')
                and '../includes/fields/source_project.yaml' in line):
                return True
    return False


def main() -> None:
    with open(ASSAY_TYPES_YAML) as f:
        old_assay_types_dict = yaml.safe_load(f)

    table_dir_path = Path(INGEST_VALIDATION_TABLE_PATH)
    split_regex = re.compile(SCHEMA_SPLIT_REGEX)
    name_to_schema_name_dict = {}
    table_schema_version_dict = defaultdict(list)
    schema_name_to_filename_dict = {}
    dir_schema_version_dict = defaultdict(list)
    schema_name_to_name_list_dict = defaultdict(list)
    for table_schema_path in table_dir_path.glob('*.yaml'):
        m = split_regex.match(table_schema_path.stem)
        if m:
            schema_name = m.group(1)
            schema_version = int(m.group(2))
            table_schema_version_dict[schema_name].append(schema_version)
        else:
            raise RuntimeError("Failed to parse schema name from table"
                               f" schema {table_schema_path.name}")
        is_hca = test_is_hca(table_schema_path)
        assay_lst = get_assay_list(table_schema_path)
        for elt in assay_lst:
            name_to_schema_name_dict[(elt.lower(), schema_version, is_hca)] = schema_name
            schema_name_to_name_list_dict[(schema_name.lower(), schema_version, is_hca)].append(elt)
            # if elt in name_to_schema_name_dict:
            #     old_schema_name, old_schema_version = name_to_schema_name_dict[elt]
            #     if old_schema_name == schema_name:
            #         pass
            #     else:
            #         print(f"CHANGE due to {table_schema_path.name}"
            #               f" for {elt}: ({old_schema_name} {old_schema_version})"
            #               f" to ({schema_name} {schema_version})")
            #         name_to_schema_name_dict[elt] = (schema_name, schema_version)
            # else:
            #     name_to_schema_name_dict[elt] = (schema_name, schema_version)
    dir_schema_dir_path = Path(INGEST_VALIDATION_DIR_SCHEMA_PATH)
    for dir_schema_path in dir_schema_dir_path.glob('*.yaml'):
        m = split_regex.match(dir_schema_path.stem)
        if m:
            schema_name = m.group(1)
            schema_version = int(m.group(2))
            dir_schema_version_dict[schema_name].append(schema_version)
            schema_name_to_filename_dict[(schema_name, schema_version)] = str(dir_schema_path.stem)
        else:
            raise RuntimeError("Failed to parse dir schema name from table"
                               f" schema {dir_schema_path.name}")

    print('----- name_to_schema_name_dict follows ------')
    pprint(name_to_schema_name_dict)
    print('----- table_schema_version_dict follows ------')
    pprint(table_schema_version_dict)
    print('----- dir_schema_version_dict follows ------')
    pprint(dir_schema_version_dict)
    print('----- schema_name_to_filename_dict follows ------')
    pprint(schema_name_to_filename_dict)
    print('----- schema_name_to_name_list_dict follows -----')
    pprint(schema_name_to_name_list_dict)
        
    json_block = PREAMBLE
    mapping_failures = []
    debug_me = ['lc-ms_label-free', 'lc-ms-ms_label-free', 'DART-FISH', 'LC-MS-untargeted', 'Targeted-Shotgun-LC-MS', 'lc-ms-ms_labeled', 'TMT-LC-MS', 'lc-ms_labeled']
    for canonical_name in old_assay_types_dict:
        type_dict = old_assay_types_dict[canonical_name]
        all_assay_types = ([canonical_name]
                           + [elt for elt in type_dict.get('alt-names', [])
                              if isinstance(elt, str)])
        quoted_assay_types = ["'" + tp + "'" for tp in all_assay_types]
        vitessce_hints = type_dict.get('vitessce-hints', [])
        description = type_dict.get('description', '')
        is_primary = type_dict['primary']

        if is_primary:
            # Long mechanics follow to figure out what directory schema is appropriate
            schema_assay_name = None
            try:
                if canonical_name in debug_me: print(f"Trying {canonical_name} {all_assay_types}")
                candidate_schema_list = []
                for this_name in all_assay_types:
                    for tpl, schema_list in schema_name_to_name_list_dict.items():
                        schema_name, schema_version, is_hca = tpl
                        if is_hca:
                            continue # reject hca out of hand
                        if this_name in schema_list:
                            candidate_schema_list.append(schema_name)
                candidate_schema_list = list(set(candidate_schema_list))
                if canonical_name in debug_me: print(f"candidate schema list: {candidate_schema_list}")
                for schema_name in candidate_schema_list:
                    tbl_versions = table_schema_version_dict[schema_name.lower()]
                    if canonical_name in debug_me: print(f"{schema_name} -> {tbl_versions}")
                    if tbl_versions:
                        break
                else:
                    raise RuntimeError("No mapping found")
                tbl_versions = list(set(tbl_versions))
                tbl_versions.sort()
                if len(tbl_versions) > 1:
                    max_tbl_version = tbl_versions[-2]
                else:
                    max_tbl_version = tbl_versions[0]
                for this_name in all_assay_types:
                    key = (this_name.lower(), max_tbl_version, False)
                    if canonical_name in debug_me: print(f"Trying lookup {key}")
                    if key in name_to_schema_name_dict:
                        schema_assay_name = name_to_schema_name_dict[key]
                        break
                else:
                    raise RuntimeError("Final lookup failed")
            except Exception as excp:
                print(f"FAILED for {canonical_name}: {excp}")
                mapping_failures.append(canonical_name)
            print(f"{canonical_name} -> {this_name} {max_tbl_version} -> {schema_assay_name}")
            dir_schema_filename = None
            if schema_assay_name:
                dir_schema_version_list = dir_schema_version_dict[schema_assay_name]
                dir_schema_version_list.sort()
                if len(dir_schema_version_list) > 1:
                    dir_schema_version = dir_schema_version_list[-2]
                else:
                    dir_schema_version = dir_schema_version_list[0]
                dir_schema_filename = schema_name_to_filename_dict[(schema_assay_name,
                                                                    dir_schema_version)]
            print(f"  -> {dir_schema_filename}")
            # At last we have a directory schema

            if dir_schema_filename:
                dir_schema_str = f"'dir_schema': '{dir_schema_filename}',"
            else:
                dir_schema_str = ""
            if schema_assay_name:
                tbl_schema_str = f"'tbl_schema': '{schema_assay_name}-v'+version.to_str,"
            else:
                tbl_schema_str = ""
            json_block.append(
                {"type": "match",
                 "match": f"not_dcwg and not_derived and assay_type in [{', '.join(quoted_assay_types)}]",
                 "value": (f"{{'assaytype': '{canonical_name}',"
                           f" {dir_schema_str}"
                           f" {tbl_schema_str}"
                           f" 'vitessce_hints': {vitessce_hints},"
                           f" 'description': '{description}'}}"
                           ),
                 "rule_description": f"non-DCWG primary {canonical_name}"
                 }
            )
        else:
            json_block.append(
                {"type": "match",
                 "match": f"not_dcwg and is_derived and data_types[0] in [{', '.join(quoted_assay_types)}]",
                 "value": (f"{{'assaytype': '{canonical_name}',"
                           f" 'vitessce_hints': {vitessce_hints},"
                           f" 'description': '{description}'}}"
                           ),
                 "rule_description": f"non-DCWG derived {canonical_name}"
                 }
            )
    mapping_failures = list(set(mapping_failures))
    print(f"MAPPING FAILURES: {mapping_failures}")
            
    # 10X Multiome example
    json_block.append(
        {"type": "match",
         "match": ("is_dcwg and dataset_type == '10X Multiome'"
                   " and barcode_size == 16"
                   " and barcode_offset == 8"
                   ),
         "value": ("{'assaytype': '10x_multiome',"
                   " 'vitessce_hints': [],"
                   " 'description': '10X Multiome',"
                   " 'must_contain': ['????', '????']}"
                   ),
         "rule_description": "DCWG 10X Multiome"
         }
    )

    # Visium v3 (current CEDAR template)
    for data_type, is_probes_used, assay, description, must_contain, schema in [
            ('Visium (no probes)', 'No', 'visium-no-probes', 'Visium (No probes)',
             ['Histology', 'RNAseq'], 'visium-no-probes-v2'),
            ('Visium (with probes)', 'Yes', 'visium-with-probes', 'Visium (With probes)',
             ['Histology', 'RNAseq (with probes)'], 'visium-with-probes-v2'),
    ]:
        must_contain_str = ','.join(["'" + elt + "'" for elt in must_contain])
        json_block.append(
            {"type": "match",
             "match": (f"is_dcwg and dataset_type == '{data_type}'"
                       ),
             "value": ("{"
                       f"'assaytype': '{assay}',"
                       " 'vitessce_hints': [],"
                       f" 'dir_schema': '{schema}',"
                       f" 'description': '{description}',"
                       f" 'must_contain': [{must_contain_str}]"
                       "}"
                       ),
             "rule_description": f"DCWG {assay}"
             }
            
        )

    # RNAseq [sn/sc]RNAseq-10xGenomics-[v2/v3]
    for entity, umi_size, assay, description in [
            ('single nucleus', 12, 'snRNAseq-10xGenomics-v3', 'snRNA-seq (10x Genomics v3)'),
            ('single nucleus', 10, 'snRNAseq-10xGenomics-v2', 'snRNA-seq (10x Genomics v2)'),
            ('single cell', 12, 'scRNAseq-10xGenomics-v3', 'scRNA-seq (10x Genomics v3)'),
            ('single cell', 10, 'scRNAseq-10xGenomics-v2', 'scRNA-seq (10x Genomics v2)'),
    ]:
        json_block.append(
            {"type": "match",
             "match": ("is_dcwg and dataset_type == 'RNAseq'"
                       f" and assay_input_entity == '{entity}'"
                       " and barcode_read =~~ 'Read 1'"
                       " and barcode_size == 16"
                       " and barcode_offset == 0"
                       " and umi_read =~~ 'Read 1'"
                       f" and umi_size == {umi_size}"
                       " and umi_offset == 16"
                       ),
             "value": ("{"
                       f"'assaytype': '{assay}',"
                       " 'vitessce_hints': [],"
                       " 'dir_schema': 'scrnaseq-v2',"
                       f" 'description': '{description}'"
                       "}"
                       ),
             "rule_description": "DCWG {assay}"
             }
        )

    # ATACseq cases
    for entity, barcode_read, barcode_size, barcode_offset, assay, description, schema in [
            ("single nucleus", "Read 2", 16, 0, "snATACseq", "snATAC-seq", "scatacseq-v2"),
            ("single cell", "Not applicable", None, None, "sciATACseq", "sciATAC-seq", "scatacseq-v2"),
            #("single nucleus", "Read 2", 16, 8, "????", "10X Multiome ATACseq", "scatacseq-v2"),
    ]:
        bc_size_line = (f" and barcode_size == {barcode_size}"
                        if barcode_size is not None else "")
        bc_offset_line = (f" and barcode_offset == {barcode_offset}"
                          if barcode_offset is not None else "")
        json_block.append(
            {"type": "match",
             "match": ("is_dcwg and dataset_type == 'ATACseq' "
                       f" and assay_input_entity == '{entity}'"
                       f" and barcode_read =~~ '{barcode_read}'"
                       f"{bc_size_line}"
                       f"{bc_offset_line}"
                       ),
             "value": ("{"
                       f"'assaytype': '{assay}',"
                       " 'vitessce_hints': [],"
                       f" 'dir_schema': '{schema}',"
                       f" 'description': '{description}'"
                       "}"
                       ),
             "rule_description": f"DCWG {assay}"
             }
        )    

    # Histology assays
    for stain_name, assay, description, schema in [
            ('PAS', 'PAS', 'PAS Stained Microscopy', 'histology-v2'),
            ('H&E', 'h-and-e', 'H&E Stained Microscopy', 'histology-v2'),
    ]:
        json_block.append(
            {"type": "match",
             "match": (f"is_dcwg and dataset_type == 'Histology' "
                       f" and stain_name == '{stain_name}'"
                       ),
             "value": ("{"
                       f"'assaytype': '{assay}',"
                       " 'vitessce_hints': [],"
                       f" 'dir_schema': '{schema}',"
                       f" 'description': '{description}'"
                       "}"
                       ),
             "rule_description": f"DCWG {assay}"
             }
        )

    # Simple assays
    for data_type, assay, description, schema in [
            ('CODEX', 'CODEX', 'CODEX', 'codex-v2'),
            ('PhenoCycler', 'phenocycler', 'PhenoCycler', 'phenocycler-v2'),
            ('CycIF', 'cycif', 'CycIF', 'cycif-v2'),
            ('MERFISH', 'merfish', 'MERFISH', 'merfish-v2'),
            ('Cell Dive', 'cell-dive', 'Cell DIVE', 'celldive-v2'),
            ('MALDI', 'MALDI-IMS', 'MALDI IMS', 'maldi-v2'),
            ('SIMS', 'SIMS-IMS', 'SIMS-IMS', 'sims-v2'),
            ('DESI', 'DESI-IMS', 'DESI', 'desi-v2'),
            ('MIBI', 'MIBI', 'Multiplex Ion Beam Imaging', 'mibi-v2'),
            ('2D Imaging Mass Cytometry', 'IMC2D', 'Imaging Mass Cytometry (2D)', 'imc-v2'),
            ('LC-MS', 'LC-MS', 'LC-MS', 'lcms-v2'),
            ('nanoSPLITS', 'nano-splits', 'nanoSPLITS', 'nano-splits-v2'),
            ('Auto-fluorescence', 'AF', 'Autofluorescence Microscopy', 'af-v2'),
            ('Light Sheet', 'Lightsheet', 'Lightsheet Microsopy', 'lightsheet-v2'),
            ('Confocal', 'confocal', 'Confocal Microscopy', 'confocal-v2'),
            ('Thick section Multiphoton MxIF', 'thick-section-multiphoton-mxif', 'Thick section Multiphoton MxIF', 'thick-section-multiphoton-mxif-v2'),
            ('Second Harmonic Generation (SHG)', 'second-harmonic-generation', 'Second Harmonic Generation (SHG)', 'second-harmonic-generation-v2'),
            ('Enhanced Stimulated Raman Spectroscopy (SRS)', 'enhanced-srs', 'Enhanced Stimulated Raman Spectroscopy (SRS)', 'enhanced-srs-v2'),
            ('Molecular Cartography', 'molecular-cartography', 'Molecular Cartography', 'mc-v2'),
    ]:
        json_block.append(
            {"type": "match",
             "match": (f"is_dcwg and dataset_type == '{data_type}'"
                       ),
             "value": ("{"
                       f"'assaytype': '{assay}',"
                       " 'vitessce_hints': [],"
                       f" 'dir_schema': '{schema}',"
                       f" 'description': '{description}'"
                       "}"
                       ),
             "rule_description": f"DCWG {assay}"
             }
        )
    
    with open(CHAIN_OUTPUT_PATH, 'w') as ofile:
        json.dump(json_block, ofile, indent=4)

    print('done')

if __name__ == '__main__':
    main()