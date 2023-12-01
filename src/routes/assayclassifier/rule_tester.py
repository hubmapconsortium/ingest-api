import sys
import requests
import json
import yaml
import re
from os.path import isdir
from pprint import pprint
import pandas as pd

AUTH_TOK = 'some_token'

TEST_BASE_URL = 'http://localhost:5000/'

def main() -> None:
    for argfile in sys.argv[1:]:
        if argfile.endswith('~'):
            print(f"Skipping {argfile}")
            continue  # probably an editor backup file
        if isdir(argfile):
            print(f"Skipping directory {argfile}")
            continue
        print(f"Reading {argfile}")
        arg_df = None
        if argfile.endswith('.tsv'):
            arg_df = pd.read_csv(argfile, sep='\t')
        else:
            raise RuntimeError(f"Arg file {argfile} is of an"
                               " unrecognized type")
        if len(arg_df.columns) == 1 and 'uuid' in arg_df.columns:
            for idx, row in arg_df.iterrows():
                print(f"{row['uuid']} ->")
                try:
                    rply = requests.get(
                        TEST_BASE_URL + 'assaytype' + '/' + row['uuid'],
                        headers={
                            'Authorization': 'Bearer ' + AUTH_TOK,
                            'content-type': 'application/json'
                        }
                    )
                    rply.raise_for_status()
                    rslt = rply.json()
                    pprint(rslt)
                    if not rslt:
                        print("NOT MAPPED!")
                except requests.exceptions.HTTPError as excp:
                    print(f"ERROR: {excp}")
        else:
            #print(arg_df)
            for idx, row in arg_df.iterrows():
                payload = {col: row[col] for col in arg_df.columns}
                #pprint(payload)
                rply = requests.post(
                    TEST_BASE_URL + 'assaytype',
                    data=json.dumps(payload),
                    headers={
                        'Authorization': 'Bearer ' + AUTH_TOK,
                        'content-type': 'application/json'
                    }
                )
                rply.raise_for_status()
                rslt = rply.json()
                print(f"{argfile} {idx} ->")
                pprint(rslt)
                if not rslt:
                    print("Payload follows")
                    pprint(payload)
    print('done')

if __name__ == '__main__':
    main()
