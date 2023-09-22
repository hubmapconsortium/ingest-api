import sys
import requests
import json
import yaml
import re
import pandas as pd
from pprint import pprint

AUTH_TOK = 'AgDDB6l0kEXpjm6Gp2yvxwO6a4OjmpvM9PljQ9Jmlp4NOjMdgasaCzm940Gdr7a4vr1qq1wY4n2dx6IoBN7DmUk7Mm'

TEST_BASE_URL = 'http://localhost:5000/'

def main() -> None:
    for argfile in sys.argv[1:]:
        arg_df = None
        if argfile.endswith('.tsv'):
            arg_df = pd.read_csv(argfile, sep='\t')
        else:
            raise RuntimeError(f"Arg file {argfile} is of an unrecognized type")
        if len(arg_df.columns) == 1 and 'uuid' in arg_df.columns:
            for idx, row in arg_df.iterrows():
                rply = requests.get(
                    TEST_BASE_URL + 'assaytype' + '/' + row['uuid'],
                    headers={
                        'Authorization': 'Bearer ' + AUTH_TOK,
                        'content-type': 'application/json'
                    }
                )
                rply.raise_for_status()
                print(f"{row['uuid']} ->")
                pprint(rply.json())
        else:
            print(arg_df)
            for idx, row in arg_df.iterrows():
                payload = {col: row[col] for col in arg_df.columns}
                pprint(payload)
                rply = requests.post(
                    TEST_BASE_URL + 'assaytype',
                    data=json.dumps(payload),
                    headers={
                        'Authorization': 'Bearer ' + AUTH_TOK,
                        'content-type': 'application/json'
                    }
                )
                rply.raise_for_status()
                print(f"{argfile} {idx} ->")
                pprint(rply.json())
    print('done')

if __name__ == '__main__':
    main()
