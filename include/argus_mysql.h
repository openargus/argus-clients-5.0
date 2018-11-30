#ifndef ARGUS_MYSQL_H
# define ARGUS_MYSQL_H
# ifdef ARGUS_MYSQL
#  ifdef HAVE_STDBOOL_H
#   include <stdbool.h>
#  endif
#  include <mysql.h>
#  if !defined(my_bool)
#   define my_bool bool
#  endif
# endif /* ARGUS_MYSQL*/
#endif /* ARGUS_MYSQL_H */
