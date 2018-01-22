# iChainbreaker

iChainbreaker is just PoC code for analyzing iCloud Keychain. This project will be merged with Chainbreaker

## How to use

    n0fate@MacBook-Pro:~/iChainbreaker$ python iChainbreaker.py -h
    usage: iChainbreaker.py [-h] -p PATH -k KEY [-x EXPORTFILE] -v VERSION
    
    Tool for iCloud Keychain Analysis by @n0fate
    
    optional arguments:
      -h, --help            show this help message and exit
      -p PATH, --path PATH  iCloud Keychain Path(~/Library/Keychains/[UUID]/)
      -k KEY, --key KEY     User Password
      -x EXPORTFILE, --exportfile EXPORTFILE
                            Write a decrypted contents to SQLite file (optional)
      -v VERSION, --version VERSION
                            macOS version(ex. 10.13)
    n0fate@MacBook-Pro:~/iChainbreaker$ 


## Reference
Sogeti ESEC Lab, iPhone data protection in depth, HITB Amsterdam 2011.

## License
GPL v2
