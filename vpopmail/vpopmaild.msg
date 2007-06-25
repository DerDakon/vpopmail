//   Don't translate these   "  You can add, and renumber as long as 
//   they match the order of the array below.  The defines must
//   match the ones in the source code.
//

#define CANT_OPEN_AUTH       1   // Can't open authentication database
#define TOO_MANY_ACTION      2   // Too many actions before login
#define RD_TIMEOUT           3   // Read Timeout
#define INVALID_COMMAND      4   // Invalid Command
#define TOO_MANY_LOGIN       5   // Too many invalid login attempts
#define EMAIL_REQD           6   // Email Address Required
#define PASSWORD_REQD        7   // Password Required
#define INVALID_LOGIN        8   // Invalid Login
#define NOT_AUTHORIZED       9   // Not Authorized
#define INVALID_EMAIL       10   // Invalid Email Address
#define NOT_AUTH_DOMAIN     11   // Not Authorized for domain
#define NO_USER             12   // User does not exist
#define DOMAIN_REQD         13   // Domain Required
#define ALIAS_REQD          14   // Alias Name Required
#define INVALID_ALIAS       15   // Invalid Alias Name Supplied
#define ALIAS_LINE_REQD     16   // Alias Line Required
#define ALIAS_INSERT_FAIL   17   // Alias Insertion Failed
#define ALIAS_REMOVE_FAIL   18   // Alias Removal Failed
#define ALIAS_DELETE_FAIL   19   // Alias Deletion Failed
#define INVALID_DIR_DOTDOT  20   // Invalid Directory.  .. not allowed in path
#define INVALID_DIR_PCT     21   // Invalid Directory.  % not allowed in path
#define INVALID_DIR_SLASH   22   // Invalid Directory.  Do you need a trailing '/'?
#define INVALID_DIR_AT      23   // Invalid Directory. Found / before @
#define INVALID_DIR_PARSE   24   // Invalid Directory. Can't parse email address
#define INVALID_DIR_UNK     25   // Invalid Directory. Unknown email address
#define UNAUTH_DIR          26   // Unauthorized Directory.
#define DIR_REQD            27   // Directory Required.
#define SOURCE_REQD         28   // Source File Name Required
#define DEST_REQD           29   // Destination File Name Required
#define FNAME_REQD          30   // Filename Required
#define NO_OPEN_ASSIGN      31   // Could not open assign file
#define IP_REQD             32   // IP Required
#define NOT_AVAIL           33   // Not Available
#define NO_GET_LIMITS       34   // Could not get limits
#define NO_SET_LIMITS       35   // Could not set limits
#define NOT_IMPLEMENT	    36   // Not implemented yet




//  Translate just this array, but not the comments

const char *ErrorMessages[] = {
   "Can't open authentication database",              //  CANT_OPEN_AUTH       1 
   "Too many actions before login",                   //  TOO_MANY_ACTION      2 
   "Read Timeout",                                    //  RD_TIMEOUT           3 
   "Invalid Command",                                 //  INVALID_COMMAND      4   
   "Too many invalid login attempts",                 //  TOO_MANY_LOGIN       5   
   "Email Address Required",                          //  EMAIL_REQD           6   
   "Password Required",                               //  PASSWORD_REQD        7   
   "Invalid Login",                                   //  INVALID_LOGIN        8   
   "Not Authorized",                                  //  NOT_AUTHORIZED       9   
   "Invalid Email Address",                           //  INVALID_EMAIL       10   
   "Not Authorized for domain",                       //  NOT_AUTH_DOMAIN     11   
   "User does not exist",                             //  NO_USER             12   
   "Domain Required",                                 //  DOMAIN_REQD         13   
   "Alias Name Required",                             //  ALIAS_REQD          14   
   "Invalid Alias Name Supplied",                     //  INVALID_ALIAS       15   
   "Alias Line Required",                             //  ALIAS_LINE_REQD     16   
   "Alias Insertion Failed",                          //  ALIAS_INSERT_FAIL   17   
   "Alias Removal Failed",                            //  ALIAS_REMOVE_FAIL   18   
   "Alias Deletion Failed",                           //  ALIAS_DELETE_FAIL   19   
   "Invalid Directory.  .. not allowed in path",      //  INVALID_DIR_DOTDOT  20   
   "Invalid Directory.  % not allowed in path",       //  INVALID_DIR_PCT     21   
   "Invalid Directory.  Do you need a trailing '/'?", //  INVALID_DIR_SLASH   22   
   "Invalid Directory. Found / before @",             //  INVALID_DIR_AT      23   
   "Invalid Directory. Can't parse email address",    //  INVALID_DIR_PARSE   24   
   "Invalid Directory. Unknown email address",        //  INVALID_DIR_UNK     25   
   "Unauthorized Directory.",                         //  UNAUTH_DIR          26   
   "Directory Required.",                             //  DIR_REQD            27   
   "Source File Name Required",                       //  SOURCE_REQD         28   
   "Destination File Name Required",                  //  DEST_REQD           29   
   "Filename Required",                               //  FNAME_REQD          30   
   "Could not open assign file",                      //  NO_OPEN_ASSIGN      31   
   "IP Required",                                     //  IP_REQD             32   
   "Not Available",                                   //  NOT_AVAIL           33   
   "Could not get limits",                            //  NO_GET_LIMITS       34   
   "Could not set limits",                            //  NO_SET_LIMITS       35   
   "Not Implemented yet",                             //  NOT_IMPLEMENT       36   
};
