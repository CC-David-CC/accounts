"""Explicit application mount path; no request-supplied prefix is trusted."""
import re

def validate_base_path(value):
 if not isinstance(value,str) or len(value)>128 or (value!='' and not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)+',value)):
  raise ValueError('Base path must be empty or slash-separated ASCII names without trailing slash')
 return value
