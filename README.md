# iChainbreaker

iChainbreaker is just PoC code for analyzing iCloud Keychain. This project will be merged with Chainbreaker

## How to use

  n0fate@MacBook-Pro:~/iChainbreaker$ python iChainbreaker.py -h
  usage: iChainbreaker.py [-h] -p PATH -k KEY [-x EXPORTFILE]
  
  Tool for iCloud Keychain Analysis by @n0fate
  
  optional arguments:
    -h, --help            show this help message and exit
    -p PATH, --path PATH  iCloud Keychain Path(~/Library/Keychains/[UUID]/)
    -k KEY, --key KEY     User Password
    -x EXPORTFILE, --exportfile EXPORTFILE
                          Sqlite filename for decrypted record (optional)
  n0fate@MacBook-Pro:~/iChainbreaker$ 


## Reference
iPhone-Data-Protection
