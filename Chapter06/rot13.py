"""Prototype ROT-13 encoder and decoder."""
from __future__ import print_function

"""
MIT License
Copyright (c) 2018 Chapin Bryce, Preston Miller
Please share comments and questions at:
  https://github.com/PythonForensics/Learning-Python-for-Forensics
  or email pyforcookbook@gmail.com

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""

def rot_code(data):
      """
      The rot_code function encodes/decodes data using string
	  indexing
      :param data: A string
      :return: The rot-13 encoded/decoded string
      """
      rot_chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
	  'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
	  'u', 'v', 'w', 'x', 'y', 'z']
  
      substitutions = []
  
      # Walk through each individual character
      for c in data:
  
          # Walk through each individual character
          if c.isupper():
  
                  try:
                      # Find the position of the character in
					  # rot_chars list
                      index = rot_chars.index(c.lower())
                  except ValueError:
                      substitutions.append(c)
                      continue
  
                  # Calculate the relative index that is 13
				  # characters away from the index
                  substitutions.append(
				  (rot_chars[(index-13)]).upper())
  
          else:
  
                  try:
                      # Find the position of the character in
					  # rot_chars list
                      index = rot_chars.index(c)
                  except ValueError:
                      substitutions.append(c)
                      continue
  
                  substitutions.append(rot_chars[((index-13))])
  
      return ''.join(substitutions)
    
if __name__ == '__main__':
     print(rot_code('Jul, EBG-13?'))
