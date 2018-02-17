#
# Simple list append filter
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from jinja2 import TemplateError
import subprocess
import string
import random
import re
import socket

class FilterModule(object):


#
# Append a number of items to the list
#
  def list_append(self,l,*argv):
    if type(l) is not list:
      raise TemplateError("First argument of append filter must be a list")

    for element in argv:
      if type(element) is list:
        l.extend(element)
      else:
        l.append(element)
    return l

  def list_flatten(self,l):
    if type(l) is not list:
      raise TemplateError("flatten filter takes a list")

    def recurse_flatten(l):
      if type(l) is not list:
        return [l]
      r = []
      for i in l:
        r.extend(recurse_flatten(i))
      return r

    return recurse_flatten(l)

  def check_duplicate_attr(self,d,attr = None,mandatory = False):
    seen = {}
    stat = []

    def get_value(value):

      def get_single_value(v,k):
        if not(k in v):
          if mandatory:
            raise TemplateError("Missing mandatory attribute %s in %s" % (k,v))
          else:
            return None
        return v[k]

      if type(attr) is list:
        retval = ""
        for a in attr:
          item = get_single_value(value,a)
          retval += " " if retval else ""
          retval += "%s=%s" % (a,item)
        return retval
      else:
        return get_single_value(value,attr)

    def check_unique_value(key,value):
      if key is not None:
        value['key'] = key
      v = get_value(value)
      if v in seen:
        stat.append("Duplicate value %s of attribute %s found in %s and %s" % 
            (v,attr,
             seen[v]['key'] if ('key' in seen[v]) else seen[v],
             value['key'] if ('key' in value) else value))
      else:
        seen[v] = value

    # sanity check: do we know which attribute to check?
    #
    if attr is None:
      raise TemplateError("You have to specify attr=name in checkunique")

    # iterate over a list or a dictionary, fail otherwise
    #
    if type(d) is list:
      for value in d:
        check_unique_value(None,value)
    elif type(d) is dict:
      for key in d:
        check_unique_value(key,d[key])
    else:
      raise TemplateError("")

    if len(stat) == 0:
      return None
    else:
      return stat


  def dict_to_list(self,o):
    if type(o) is not dict:
      raise TemplateError("dict_to_list can only be used on dictionaries")

    l = []
    for k,v in o.items():
      v['id'] = k
      l.append(v)

    return l


  def remove_keys(self,val,keylist,recurse = False):
    if type(keylist) is str:
      keylist = [ keylist ]
    if type(val) is dict:
      for k,v in val.items():
        if k in keylist:
          del val[k]
        elif recurse:
          val[k] = self.remove_keys(v,keylist,recurse)
      return val
    elif type(val) is list:
      newval = []
      for v in val:
        newval.append(self.remove_keys(v,keylist,recurse))
      return newval
    else:
      return val


  def ios_lacp_neighbor(self,text):
        '''
        Parses information from the Cisco IOS "show lacp neighbor" command
        family. This is useful for verifying various characteristics of
        an LACP neighbor's state.
        '''
        member_regex_text = r"""
            (?P<port>[A-Za-z0-9/]+)\s+
            (?P<mode>\w+)\s+
            (?P<port_pri>\d+)\s+
            (?P<sys_id>[A-Fa-f0-9.]+)\s+
            (?P<age_sec>\d+)s\s+
            (?P<admin_key>{0})\s+
            (?P<oper_key>{0})\s+
            (?P<port_num>{0})\s+
            (?P<port_state>{0})
        """.format(r'[A-Fa-f0-9x]+')
        member_regex = re.compile(member_regex_text, re.VERBOSE)
        chan_grp_regex = r'nel\s+group\s+(?P<chan_grp>\d+)\s+neighbors'

        channels = []
        chan_lines = text.strip().split('Chan')
        for c in chan_lines[1:]:
            m = re.search(chan_grp_regex, c)
            chan_dict = m.groupdict()
            chan_dict['chan_grp'] = FilterModule._try_int(
                chan_dict['chan_grp'])
            members = []
            for l in c.strip().split('\n'):
                m = member_regex.search(l)
                if not m:
                    #print("no match")
                    continue

                d = m.groupdict()

                d['port_pri'] = FilterModule._try_int(d['port_pri'])
                d['age_sec'] = FilterModule._try_int(d['age_sec'])
                d['admin_key'] = FilterModule._try_int(d['admin_key'], 16)
                d['oper_key'] = FilterModule._try_int(d['oper_key'], 16)
                d['port_num'] = FilterModule._try_int(d['port_num'], 16)
                d['port_state'] = FilterModule._try_int(d['port_state'], 16)

                port_state_flags = []
                for i in range(8):
                    bit = 2**i
                    port_state_flags.append(d['port_state'] & bit > 0)

                d.update({'port_state_flags': port_state_flags})
                members.append(d)

            chan_dict.update({'members': members})
            channels.append(chan_dict)

        return channels
  

  def filters(self):
    return {
      'append'     : self.list_append,
      'flatten'    : self.list_flatten,
      'dupattr'    : self.check_duplicate_attr,
      'to_list'    : self.dict_to_list,
      'remove_keys': self.remove_keys,
      'ios_lacp_neighbor': self.ios_lacp_neighbor
    }