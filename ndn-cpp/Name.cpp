/* 
 * Author: Jeff Thompson
 *
 * BSD license, See the LICENSE file for more information.
 */

#include <sstream>
#include "Name.hpp"

using namespace std;

namespace ndn {

/**
 * Write the value to result, escaping characters according to the NDN URI Scheme.
 * This also adds "..." to a value with zero or more ".".
 * @param value the buffer with the value to escape
 * @param result the string stream to write to.
 */
static void toEscapedString(const vector<unsigned char> &value, ostringstream &result)
{
  bool gotNonDot = false;
  for (unsigned i = 0; i < value.size(); ++i) {
    if (value[i] != 0x2e) {
      gotNonDot = true;
      break;
    }
  }
  if (!gotNonDot) {
    // Special case for component of zero or more periods.  Add 3 periods.
    result << "...";
    for (unsigned int i = 0; i < value.size(); ++i)
      result << ".";
  }
  else {
    // In case we need to escape, set to upper case hex and save the previous flags.
    ios::fmtflags saveFlags = result.flags(ios::hex | ios::uppercase);
    
    for (unsigned int i = 0; i < value.size(); ++i) {
      unsigned char x = value[i];
      // Check for 0-9, A-Z, a-z, (+), (-), (.), (_)
      if (x >= 0x30 && x <= 0x39 || x >= 0x41 && x <= 0x5a ||
        x >= 0x61 && x <= 0x7a || x == 0x2b || x == 0x2d || 
        x == 0x2e || x == 0x5f)
        result << x;
      else {
        result << "%";
        if (x < 16)
          result << "0";
        result << (unsigned int)x;
      }
    }
    
    // Restore.
    result.flags(saveFlags);
  }  
}

static const char *WHITESPACE_CHARS = " \n\r\t";

/**
 * Modify str in place to erase whitespace on the left.
 * @param str
 */
static inline void trimLeft(string &str)
{
  size_t found = str.find_first_not_of(WHITESPACE_CHARS);
  if (found != string::npos) {
    if (found > 0)
      str.erase(0, found);
  }
  else
    // All whitespace
    str.clear();    
}

/**
 * Modify str in place to erase whitespace on the right.
 * @param str
 */
static inline void trimRight(string &str)
{
  size_t found = str.find_last_not_of(WHITESPACE_CHARS);
  if (found != string::npos) {
    if (found + 1 < str.size())
      str.erase(found + 1);
  }
  else
    // All whitespace
    str.clear();
}

/**
 * Modify str in place to erase whitespace on the left and right.
 * @param str
 */
static void trim(string &str)
{
  trimLeft(str);
  trimRight(str);
}
  
/**
 * Convert the hex character to an integer from 0 to 15, or -1 if not a hex character.
 * @param c
 * @return 
 */
static int fromHexChar(unsigned char c)
{
  if (c >= '0' && c <= '9')
    return (int)c - (int)'0';
  else if (c >= 'A' && c <= 'F')
    return (int)c - (int)'A' + 10;
  else if (c >= 'a' && c <= 'f')
    return (int)c - (int)'a' + 10;
  else
    return -1;
}

/**
 * Return a copy of str, converting each escaped "%XX" to the char value.
 * @param str
 */
static string unescape(const string &str)
{
  ostringstream result;
  
  for (unsigned int i = 0; i < str.size(); ++i) {
    if (str[i] == '%' && i + 2 < str.size()) {
      int hi = fromHexChar(str[i + 1]);
      int lo = fromHexChar(str[i + 2]);
      
      if (hi < 0 || lo < 0)
        // Invalid hex characters, so just keep the escaped string.
        result << str[i] << str[i + 1] << str[i + 2];
      else
        result << (unsigned char)(16 * hi + lo);
      
      // Skip ahead past the escaped value.
      i += 2;
    }
    else
      // Just copy through.
      result << str[i];
  }
  
  return result.str();
}

void Name::get(struct ndn_Name &nameStruct) 
{
  if (nameStruct.maxComponents < components_.size())
    throw runtime_error("nameStruct.maxComponents must be >= this name getNComponents()");
  
  nameStruct.nComponents = components_.size();
  for (unsigned int i = 0; i < nameStruct.nComponents; ++i)
    components_[i].get(nameStruct.components[i]);
}
  
void Name::set(struct ndn_Name &nameStruct) 
{
  clear();
  for (unsigned int i = 0; i < nameStruct.nComponents; ++i)
    addComponent(nameStruct.components[i].value, nameStruct.components[i].valueLength);  
}

std::string Name::to_uri()
{
  if (components_.size() == 0)
    return "/";
  
  ostringstream result;
  for (unsigned int i = 0; i < components_.size(); ++i) {
    result << "/";
    toEscapedString(components_[i].getValue(), result);
  }
  
  return result.str();
}

}
