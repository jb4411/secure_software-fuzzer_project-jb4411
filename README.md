# SWEN 331 Fuzzer Project

A fuzzer for testing and exploiting DVWA.


## Project Information:

Written by Jesse Burdick-Pless - <a href="mailto:jb4411@rit.edu">jb4411@rit.edu</a>


## Prerequisites

- [Python 3+](https://www.python.org/downloads/) with pip3
- The [MechanicalSoup](https://pypi.org/project/MechanicalSoup/) module.
- A working instance of [DVWA](https://dvwa.co.uk/)

If you are using docker, `- pip3 install MechanicalSoup` must be run in the docker image. 


## How to run it

1. Clone the repository and go to the root directory.
2. Start an instance of DVWA.
3. From the command line, run fuzz.py followed by any command line input (*input format below*).
4. Sit back and let the fuzzer run.


#### Command line input must conform to the following input format:

    fuzz [discover | test] url OPTIONS

    COMMANDS:
        discover  Output a comprehensive, human-readable list of all discovered inputs to the system. Techniques include both crawling and guessing.
        test      Discover all inputs, then attempt a list of exploit vectors on those inputs. Report anomalies that could be vulnerabilities.
    
    OPTIONS:
        Options can be given in any order.
    
        --custom-auth=string     Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa).
    
        Discover options:
          --common-words=file    Newline-delimited file of common words to be used in page guessing. Required.
          --extensions=file      Newline-delimited file of path extensions, e.g. ".php". Optional. Defaults to ".php" and the empty string if not specified
    
        Test options:
          --common-words=file    Same option as in discover - see above.
          --extensions=file      Same option as in discover - see above.
          --vectors=file         Newline-delimited file of common exploits to vulnerabilities. Required.
          --sanitized-chars=file Newline-delimited file of characters that should be sanitized from inputs. Defaults to just < and >
          --sensitive=file       Newline-delimited file data that should never be leaked. It's assumed that this data is in the application's database (e.g. test data), but is not reported in any response. Required.
          --slow=500             Number of milliseconds considered when a response is considered "slow". Optional. Default is 500 milliseconds

#### Example invocations:

    # Discover inputs, default extensions, no login
    fuzz discover http://localhost:8080 --common-words=mywords.txt
    
    # Discover inputs to DVWA using our hard-coded authentication, port 8080
    fuzz discover http://localhost:8080 --custom-auth=dvwa --extensions=extensions.txt --common-words=mywords.txt
    
    # Discover and Test DVWA, port 8000, default extensions: sanitized characters, extensions and slow threshold
    fuzz test http://localhost:8000 --custom-auth=dvwa --common-words=words.txt --vectors=vectors.txt --sensitive=creditcards.txt
