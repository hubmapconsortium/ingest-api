import sys
import requests
import json
import yaml
import re
import pandas as pd
from pprint import pprint

AUTH_TOK = 'AgloVpmN88Gwq1rkXmKEpD9y438v94V8QX1Dq1jDJjn8dN410S8CxJppxBgQV2nga61pJlN03086KHY757VYh0Kkm'

TEST_BASE_URL = 'http://localhost:5000/'
import pandas as pd
from pprint import pprint

AUTH_TOK = 'AgloVpmN88Gwq1rkXmKEpD9y438v94V8QX1Dq1jDJjn8dN410S8CxJppxBgQV2nga61pJlN03086KHY757VYh0Kkm'

TEST_BASE_URL = 'http://localhost:5000/'

def main() -> None:
    for argfile in sys.argv[1:]:
        arg_df = None
        if argfile.endswith('.tsv'):
            arg_df = pd.read_csv(argfile, sep='\t')
            mode = 'post'
        elif re.match('^[A-Fa-f0-9]{32}$', argfile):
            mode = 'get'
        else:
            raise RuntimeError(f"Arg file {argfile} is of an unrecognized type")
        if mode == 'post':
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
        elif mode == 'get':
            rply = requests.get(
                TEST_BASE_URL + 'assaytype' + '/' + argfile,
                headers={
                    'Authorization': 'Bearer ' + AUTH_TOK,
                    'content-type': 'application/json'
                }
            )
            rply.raise_for_status()
            print(f"{argfile} ->")
            pprint(rply.json())
        else:
            raise RuntimeError(f"Internal Error: unknown mode {mode}")
    print('done')

if __name__ == '__main__':
    main()
