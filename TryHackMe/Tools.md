# Tools #
## File analysis ##
- ### ".doc"-Analysis ### : 
    - #### OLETOOLS ####
      located in "~/…/lib/python3.11/site-packages/oletools"
      ##### Usage #####
      python3 oleid.py [FILEPATH]
      ##### Description #####
      Gives an overview over indicators which are embedded in a ".doc"-file.
      Other scripts in the "oletools" (e.g. oleobj.py) can be used for further analysis.


## Memory Image Analysis ##
- #### VOLATILITY ####
  ##### Usage #####
  vol [options]
  e.g. vol -f [filepath_to_image.raw] [plugin_name]
  Cheatsheet can be found [here](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet).
  
