import subprocess as sub
import argparse
import re

def get_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--interface', dest = 'interface', help = 'Interface name whose MAC is to be changed')
  parser.add_argument('-m', '--mac', dest = 'new_mac', help = 'New MAC Address')
  options = parser.parse_args()
  
  #Check for errors i.e if the user does not specify the interface or new MAC
  #Quit the program if any one of the argument is missing
  #While quitting also display an error message
  
  if not options.interface:
    #Code to handle if interface is not specified
    parser.error('[-] Please specify an interface in the arguments, use --help for more info.')
    
  elif not options.new_mac:
      #Code to handle if new MAC Address is not specified
      parser.error('[-] Please specify a new MAC Address, use --help for more info.')
      
  return options
  

command_args = get_args()


