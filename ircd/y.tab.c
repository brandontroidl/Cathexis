/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 22 "ircd_parser.y"


#include "config.h"
#include "s_conf.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "ircd_features.h"
#include "fileio.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "motd.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_user.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"
#include "sys.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_STRINGS 80 /* Maximum number of feature params. */
#define USE_IPV4 (1 << 16)
#define USE_IPV6 (1 << 17)

extern int init_lexer_file(char* file);

  extern struct LocalConf   localConf;
  extern struct DenyConf*   denyConfList;
  extern struct CRuleConf*  cruleConfList;
  extern struct ServerConf* serverConfList;
  extern struct s_map*      GlobalServiceMapList;
  extern struct qline*      GlobalQuarantineList;
  extern struct WebIRCConf* webircConfList;
  extern struct SHostConf*  shostConfList;
  extern struct ExceptConf* exceptConfList;

  int yylex(void);
  /* Now all the globals we need :/... */
  unsigned int snomask;
  int fakelagmin;
  int fakelagfactor;
  int tping, tconn, maxlinks, sendq, recvq, port, invert, stringno, flags;
  int maxchans, redirport, hidehostcomps;
  char *name, *pass, *host, *from_host, *ip, *username, *origin, *hub_limit;
  char *spoofhost, *sslfp, *sslciphers, *description, *redirserver;
  char *country, *continent, *ajoinchan, *ajoinnotice, *swhois;
  struct SLink *hosts;
  char *stringlist[MAX_STRINGS];
  struct ListenerFlags listen_flags;
  struct ConnectionClass *c_class;
  struct DenyConf *dconf;
  struct s_map *smap;
  struct Privs privs;
  struct Privs privs_dirty;
  struct WebIRCFlags wflags;
  struct ClassRestrictFlags crestrict;

static void parse_error(char *pattern,...) {
  static char error_buffer[1024];
  va_list vl;
  va_start(vl,pattern);
  ircd_vsnprintf(NULL, error_buffer, sizeof(error_buffer), pattern, vl);
  va_end(vl);
  yyerror(error_buffer);
}

static void free_slist(struct SLink **link) {
  struct SLink *next;
  while (*link != NULL) {
    next = (*link)->next;
    MyFree((*link)->value.cp);
    free_link(*link);
    *link = next;
  }
}


#line 170 "y.tab.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_YY_Y_TAB_H_INCLUDED
# define YY_YY_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    QSTRING = 258,                 /* QSTRING  */
    NUMBER = 259,                  /* NUMBER  */
    GENERAL = 260,                 /* GENERAL  */
    ADMIN = 261,                   /* ADMIN  */
    LOCATION = 262,                /* LOCATION  */
    CONTACT = 263,                 /* CONTACT  */
    CONNECT = 264,                 /* CONNECT  */
    CLASS = 265,                   /* CLASS  */
    CHANNEL = 266,                 /* CHANNEL  */
    PINGFREQ = 267,                /* PINGFREQ  */
    CONNECTFREQ = 268,             /* CONNECTFREQ  */
    MAXLINKS = 269,                /* MAXLINKS  */
    MAXHOPS = 270,                 /* MAXHOPS  */
    SENDQ = 271,                   /* SENDQ  */
    RECVQ = 272,                   /* RECVQ  */
    NAME = 273,                    /* NAME  */
    HOST = 274,                    /* HOST  */
    FROM = 275,                    /* FROM  */
    IP = 276,                      /* IP  */
    USERNAME = 277,                /* USERNAME  */
    PASS = 278,                    /* PASS  */
    LOCAL = 279,                   /* LOCAL  */
    SECONDS = 280,                 /* SECONDS  */
    MINUTES = 281,                 /* MINUTES  */
    HOURS = 282,                   /* HOURS  */
    DAYS = 283,                    /* DAYS  */
    WEEKS = 284,                   /* WEEKS  */
    MONTHS = 285,                  /* MONTHS  */
    YEARS = 286,                   /* YEARS  */
    DECADES = 287,                 /* DECADES  */
    BYTES = 288,                   /* BYTES  */
    KBYTES = 289,                  /* KBYTES  */
    MBYTES = 290,                  /* MBYTES  */
    GBYTES = 291,                  /* GBYTES  */
    TBYTES = 292,                  /* TBYTES  */
    SERVER = 293,                  /* SERVER  */
    PORT = 294,                    /* PORT  */
    MASK = 295,                    /* MASK  */
    HUB = 296,                     /* HUB  */
    LEAF = 297,                    /* LEAF  */
    UWORLD = 298,                  /* UWORLD  */
    YES = 299,                     /* YES  */
    NO = 300,                      /* NO  */
    OPER = 301,                    /* OPER  */
    VHOST = 302,                   /* VHOST  */
    HIDDEN = 303,                  /* HIDDEN  */
    MOTD = 304,                    /* MOTD  */
    JUPE = 305,                    /* JUPE  */
    NICK = 306,                    /* NICK  */
    NUMERIC = 307,                 /* NUMERIC  */
    DESCRIPTION = 308,             /* DESCRIPTION  */
    CLIENT = 309,                  /* CLIENT  */
    KILL = 310,                    /* KILL  */
    CRULE = 311,                   /* CRULE  */
    REAL = 312,                    /* REAL  */
    REASON = 313,                  /* REASON  */
    TFILE = 314,                   /* TFILE  */
    RULE = 315,                    /* RULE  */
    ALL = 316,                     /* ALL  */
    FEATURES = 317,                /* FEATURES  */
    QUARANTINE = 318,              /* QUARANTINE  */
    PSEUDO = 319,                  /* PSEUDO  */
    PREPEND = 320,                 /* PREPEND  */
    USERMODE = 321,                /* USERMODE  */
    IAUTH = 322,                   /* IAUTH  */
    TIMEOUT = 323,                 /* TIMEOUT  */
    FAST = 324,                    /* FAST  */
    AUTOCONNECT = 325,             /* AUTOCONNECT  */
    PROGRAM = 326,                 /* PROGRAM  */
    TOK_IPV4 = 327,                /* TOK_IPV4  */
    TOK_IPV6 = 328,                /* TOK_IPV6  */
    DNS = 329,                     /* DNS  */
    FORWARDS = 330,                /* FORWARDS  */
    WEBIRC = 331,                  /* WEBIRC  */
    IDENT = 332,                   /* IDENT  */
    USERIDENT = 333,               /* USERIDENT  */
    IGNOREIDENT = 334,             /* IGNOREIDENT  */
    STRIPSSLFP = 335,              /* STRIPSSLFP  */
    MAXCHANS = 336,                /* MAXCHANS  */
    COUNTRY = 337,                 /* COUNTRY  */
    CONTINENT = 338,               /* CONTINENT  */
    VERSION = 339,                 /* VERSION  */
    SPOOFHOST = 340,               /* SPOOFHOST  */
    AUTOAPPLY = 341,               /* AUTOAPPLY  */
    SNOMASK = 342,                 /* SNOMASK  */
    EXCEPT = 343,                  /* EXCEPT  */
    SHUN = 344,                    /* SHUN  */
    KLINE = 345,                   /* KLINE  */
    GLINE = 346,                   /* GLINE  */
    ZLINE = 347,                   /* ZLINE  */
    RDNS = 348,                    /* RDNS  */
    IPCHECK = 349,                 /* IPCHECK  */
    TARGETLIMIT = 350,             /* TARGETLIMIT  */
    LISTDELAY = 351,               /* LISTDELAY  */
    NOIDENTTILDE = 352,            /* NOIDENTTILDE  */
    ISMASK = 353,                  /* ISMASK  */
    REDIRECT = 354,                /* REDIRECT  */
    HIDEHOSTCOMPONANTS = 355,      /* HIDEHOSTCOMPONANTS  */
    HIDEHOSTCOMPONENTS = 356,      /* HIDEHOSTCOMPONENTS  */
    AUTOJOINCHANNEL = 357,         /* AUTOJOINCHANNEL  */
    AUTOJOINNOTICE = 358,          /* AUTOJOINNOTICE  */
    AUTHEXEMPT = 359,              /* AUTHEXEMPT  */
    MARK = 360,                    /* MARK  */
    RESTRICT_JOIN = 361,           /* RESTRICT_JOIN  */
    RESTRICT_PRIVMSG = 362,        /* RESTRICT_PRIVMSG  */
    RESTRICT_UMODE = 363,          /* RESTRICT_UMODE  */
    MATCHUSERNAME = 364,           /* MATCHUSERNAME  */
    FAKELAGMINIMUM = 365,          /* FAKELAGMINIMUM  */
    FAKELAGFACTOR = 366,           /* FAKELAGFACTOR  */
    DEFAULTTEXT = 367,             /* DEFAULTTEXT  */
    SSLFP = 368,                   /* SSLFP  */
    SSLCIPHERS = 369,              /* SSLCIPHERS  */
    INCLUDE = 370,                 /* INCLUDE  */
    SSLTOK = 371,                  /* SSLTOK  */
    HMACTOK = 372,                 /* HMACTOK  */
    SWHOIS = 373,                  /* SWHOIS  */
    ENABLEOPTIONS = 374,           /* ENABLEOPTIONS  */
    TRUSTACCOUNT = 375,            /* TRUSTACCOUNT  */
    TPRIV_CHAN_LIMIT = 376,        /* TPRIV_CHAN_LIMIT  */
    TPRIV_MODE_LCHAN = 377,        /* TPRIV_MODE_LCHAN  */
    TPRIV_DEOP_LCHAN = 378,        /* TPRIV_DEOP_LCHAN  */
    TPRIV_WALK_LCHAN = 379,        /* TPRIV_WALK_LCHAN  */
    TPRIV_LOCAL_KILL = 380,        /* TPRIV_LOCAL_KILL  */
    TPRIV_REHASH = 381,            /* TPRIV_REHASH  */
    TPRIV_RESTART = 382,           /* TPRIV_RESTART  */
    TPRIV_DIE = 383,               /* TPRIV_DIE  */
    TPRIV_LOCAL_GLINE = 384,       /* TPRIV_LOCAL_GLINE  */
    TPRIV_LOCAL_JUPE = 385,        /* TPRIV_LOCAL_JUPE  */
    TPRIV_LOCAL_BADCHAN = 386,     /* TPRIV_LOCAL_BADCHAN  */
    TPRIV_LOCAL_OPMODE = 387,      /* TPRIV_LOCAL_OPMODE  */
    TPRIV_OPMODE = 388,            /* TPRIV_OPMODE  */
    TPRIV_SET = 389,               /* TPRIV_SET  */
    TPRIV_WHOX = 390,              /* TPRIV_WHOX  */
    TPRIV_BADCHAN = 391,           /* TPRIV_BADCHAN  */
    TPRIV_SEE_CHAN = 392,          /* TPRIV_SEE_CHAN  */
    TPRIV_SHOW_INVIS = 393,        /* TPRIV_SHOW_INVIS  */
    TPRIV_SHOW_ALL_INVIS = 394,    /* TPRIV_SHOW_ALL_INVIS  */
    TPRIV_PROPAGATE = 395,         /* TPRIV_PROPAGATE  */
    TPRIV_UNLIMIT_QUERY = 396,     /* TPRIV_UNLIMIT_QUERY  */
    TPRIV_DISPLAY = 397,           /* TPRIV_DISPLAY  */
    TPRIV_SEE_OPERS = 398,         /* TPRIV_SEE_OPERS  */
    TPRIV_WIDE_GLINE = 399,        /* TPRIV_WIDE_GLINE  */
    TPRIV_FORCE_OPMODE = 400,      /* TPRIV_FORCE_OPMODE  */
    TPRIV_FORCE_LOCAL_OPMODE = 401, /* TPRIV_FORCE_LOCAL_OPMODE  */
    TPRIV_APASS_OPMODE = 402,      /* TPRIV_APASS_OPMODE  */
    TPRIV_LIST_CHAN = 403,         /* TPRIV_LIST_CHAN  */
    TPRIV_CHECK = 404,             /* TPRIV_CHECK  */
    TPRIV_WHOIS_NOTICE = 405,      /* TPRIV_WHOIS_NOTICE  */
    TPRIV_HIDE_OPER = 406,         /* TPRIV_HIDE_OPER  */
    TPRIV_HIDE_CHANNELS = 407,     /* TPRIV_HIDE_CHANNELS  */
    TPRIV_HIDE_IDLE = 408,         /* TPRIV_HIDE_IDLE  */
    TPRIV_XTRAOP = 409,            /* TPRIV_XTRAOP  */
    TPRIV_SERVICE = 410,           /* TPRIV_SERVICE  */
    TPRIV_REMOTE = 411,            /* TPRIV_REMOTE  */
    TPRIV_LOCAL_SHUN = 412,        /* TPRIV_LOCAL_SHUN  */
    TPRIV_WIDE_SHUN = 413,         /* TPRIV_WIDE_SHUN  */
    TPRIV_FREEFORM = 414,          /* TPRIV_FREEFORM  */
    TPRIV_REMOTEREHASH = 415,      /* TPRIV_REMOTEREHASH  */
    TPRIV_REMOVE = 416,            /* TPRIV_REMOVE  */
    TPRIV_LOCAL_ZLINE = 417,       /* TPRIV_LOCAL_ZLINE  */
    TPRIV_WIDE_ZLINE = 418,        /* TPRIV_WIDE_ZLINE  */
    TPRIV_TEMPSHUN = 419,          /* TPRIV_TEMPSHUN  */
    TPRIV_NETADMIN = 420           /* TPRIV_NETADMIN  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 259 "ircd_parser.y"

 char *text;
 int num;

#line 390 "y.tab.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_Y_TAB_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_QSTRING = 3,                    /* QSTRING  */
  YYSYMBOL_NUMBER = 4,                     /* NUMBER  */
  YYSYMBOL_GENERAL = 5,                    /* GENERAL  */
  YYSYMBOL_ADMIN = 6,                      /* ADMIN  */
  YYSYMBOL_LOCATION = 7,                   /* LOCATION  */
  YYSYMBOL_CONTACT = 8,                    /* CONTACT  */
  YYSYMBOL_CONNECT = 9,                    /* CONNECT  */
  YYSYMBOL_CLASS = 10,                     /* CLASS  */
  YYSYMBOL_CHANNEL = 11,                   /* CHANNEL  */
  YYSYMBOL_PINGFREQ = 12,                  /* PINGFREQ  */
  YYSYMBOL_CONNECTFREQ = 13,               /* CONNECTFREQ  */
  YYSYMBOL_MAXLINKS = 14,                  /* MAXLINKS  */
  YYSYMBOL_MAXHOPS = 15,                   /* MAXHOPS  */
  YYSYMBOL_SENDQ = 16,                     /* SENDQ  */
  YYSYMBOL_RECVQ = 17,                     /* RECVQ  */
  YYSYMBOL_NAME = 18,                      /* NAME  */
  YYSYMBOL_HOST = 19,                      /* HOST  */
  YYSYMBOL_FROM = 20,                      /* FROM  */
  YYSYMBOL_IP = 21,                        /* IP  */
  YYSYMBOL_USERNAME = 22,                  /* USERNAME  */
  YYSYMBOL_PASS = 23,                      /* PASS  */
  YYSYMBOL_LOCAL = 24,                     /* LOCAL  */
  YYSYMBOL_SECONDS = 25,                   /* SECONDS  */
  YYSYMBOL_MINUTES = 26,                   /* MINUTES  */
  YYSYMBOL_HOURS = 27,                     /* HOURS  */
  YYSYMBOL_DAYS = 28,                      /* DAYS  */
  YYSYMBOL_WEEKS = 29,                     /* WEEKS  */
  YYSYMBOL_MONTHS = 30,                    /* MONTHS  */
  YYSYMBOL_YEARS = 31,                     /* YEARS  */
  YYSYMBOL_DECADES = 32,                   /* DECADES  */
  YYSYMBOL_BYTES = 33,                     /* BYTES  */
  YYSYMBOL_KBYTES = 34,                    /* KBYTES  */
  YYSYMBOL_MBYTES = 35,                    /* MBYTES  */
  YYSYMBOL_GBYTES = 36,                    /* GBYTES  */
  YYSYMBOL_TBYTES = 37,                    /* TBYTES  */
  YYSYMBOL_SERVER = 38,                    /* SERVER  */
  YYSYMBOL_PORT = 39,                      /* PORT  */
  YYSYMBOL_MASK = 40,                      /* MASK  */
  YYSYMBOL_HUB = 41,                       /* HUB  */
  YYSYMBOL_LEAF = 42,                      /* LEAF  */
  YYSYMBOL_UWORLD = 43,                    /* UWORLD  */
  YYSYMBOL_YES = 44,                       /* YES  */
  YYSYMBOL_NO = 45,                        /* NO  */
  YYSYMBOL_OPER = 46,                      /* OPER  */
  YYSYMBOL_VHOST = 47,                     /* VHOST  */
  YYSYMBOL_HIDDEN = 48,                    /* HIDDEN  */
  YYSYMBOL_MOTD = 49,                      /* MOTD  */
  YYSYMBOL_JUPE = 50,                      /* JUPE  */
  YYSYMBOL_NICK = 51,                      /* NICK  */
  YYSYMBOL_NUMERIC = 52,                   /* NUMERIC  */
  YYSYMBOL_DESCRIPTION = 53,               /* DESCRIPTION  */
  YYSYMBOL_CLIENT = 54,                    /* CLIENT  */
  YYSYMBOL_KILL = 55,                      /* KILL  */
  YYSYMBOL_CRULE = 56,                     /* CRULE  */
  YYSYMBOL_REAL = 57,                      /* REAL  */
  YYSYMBOL_REASON = 58,                    /* REASON  */
  YYSYMBOL_TFILE = 59,                     /* TFILE  */
  YYSYMBOL_RULE = 60,                      /* RULE  */
  YYSYMBOL_ALL = 61,                       /* ALL  */
  YYSYMBOL_FEATURES = 62,                  /* FEATURES  */
  YYSYMBOL_QUARANTINE = 63,                /* QUARANTINE  */
  YYSYMBOL_PSEUDO = 64,                    /* PSEUDO  */
  YYSYMBOL_PREPEND = 65,                   /* PREPEND  */
  YYSYMBOL_USERMODE = 66,                  /* USERMODE  */
  YYSYMBOL_IAUTH = 67,                     /* IAUTH  */
  YYSYMBOL_TIMEOUT = 68,                   /* TIMEOUT  */
  YYSYMBOL_FAST = 69,                      /* FAST  */
  YYSYMBOL_AUTOCONNECT = 70,               /* AUTOCONNECT  */
  YYSYMBOL_PROGRAM = 71,                   /* PROGRAM  */
  YYSYMBOL_TOK_IPV4 = 72,                  /* TOK_IPV4  */
  YYSYMBOL_TOK_IPV6 = 73,                  /* TOK_IPV6  */
  YYSYMBOL_DNS = 74,                       /* DNS  */
  YYSYMBOL_FORWARDS = 75,                  /* FORWARDS  */
  YYSYMBOL_WEBIRC = 76,                    /* WEBIRC  */
  YYSYMBOL_IDENT = 77,                     /* IDENT  */
  YYSYMBOL_USERIDENT = 78,                 /* USERIDENT  */
  YYSYMBOL_IGNOREIDENT = 79,               /* IGNOREIDENT  */
  YYSYMBOL_STRIPSSLFP = 80,                /* STRIPSSLFP  */
  YYSYMBOL_MAXCHANS = 81,                  /* MAXCHANS  */
  YYSYMBOL_COUNTRY = 82,                   /* COUNTRY  */
  YYSYMBOL_CONTINENT = 83,                 /* CONTINENT  */
  YYSYMBOL_VERSION = 84,                   /* VERSION  */
  YYSYMBOL_SPOOFHOST = 85,                 /* SPOOFHOST  */
  YYSYMBOL_AUTOAPPLY = 86,                 /* AUTOAPPLY  */
  YYSYMBOL_SNOMASK = 87,                   /* SNOMASK  */
  YYSYMBOL_EXCEPT = 88,                    /* EXCEPT  */
  YYSYMBOL_SHUN = 89,                      /* SHUN  */
  YYSYMBOL_KLINE = 90,                     /* KLINE  */
  YYSYMBOL_GLINE = 91,                     /* GLINE  */
  YYSYMBOL_ZLINE = 92,                     /* ZLINE  */
  YYSYMBOL_RDNS = 93,                      /* RDNS  */
  YYSYMBOL_IPCHECK = 94,                   /* IPCHECK  */
  YYSYMBOL_TARGETLIMIT = 95,               /* TARGETLIMIT  */
  YYSYMBOL_LISTDELAY = 96,                 /* LISTDELAY  */
  YYSYMBOL_NOIDENTTILDE = 97,              /* NOIDENTTILDE  */
  YYSYMBOL_ISMASK = 98,                    /* ISMASK  */
  YYSYMBOL_REDIRECT = 99,                  /* REDIRECT  */
  YYSYMBOL_HIDEHOSTCOMPONANTS = 100,       /* HIDEHOSTCOMPONANTS  */
  YYSYMBOL_HIDEHOSTCOMPONENTS = 101,       /* HIDEHOSTCOMPONENTS  */
  YYSYMBOL_AUTOJOINCHANNEL = 102,          /* AUTOJOINCHANNEL  */
  YYSYMBOL_AUTOJOINNOTICE = 103,           /* AUTOJOINNOTICE  */
  YYSYMBOL_AUTHEXEMPT = 104,               /* AUTHEXEMPT  */
  YYSYMBOL_MARK = 105,                     /* MARK  */
  YYSYMBOL_RESTRICT_JOIN = 106,            /* RESTRICT_JOIN  */
  YYSYMBOL_RESTRICT_PRIVMSG = 107,         /* RESTRICT_PRIVMSG  */
  YYSYMBOL_RESTRICT_UMODE = 108,           /* RESTRICT_UMODE  */
  YYSYMBOL_MATCHUSERNAME = 109,            /* MATCHUSERNAME  */
  YYSYMBOL_FAKELAGMINIMUM = 110,           /* FAKELAGMINIMUM  */
  YYSYMBOL_FAKELAGFACTOR = 111,            /* FAKELAGFACTOR  */
  YYSYMBOL_DEFAULTTEXT = 112,              /* DEFAULTTEXT  */
  YYSYMBOL_SSLFP = 113,                    /* SSLFP  */
  YYSYMBOL_SSLCIPHERS = 114,               /* SSLCIPHERS  */
  YYSYMBOL_INCLUDE = 115,                  /* INCLUDE  */
  YYSYMBOL_SSLTOK = 116,                   /* SSLTOK  */
  YYSYMBOL_HMACTOK = 117,                  /* HMACTOK  */
  YYSYMBOL_SWHOIS = 118,                   /* SWHOIS  */
  YYSYMBOL_ENABLEOPTIONS = 119,            /* ENABLEOPTIONS  */
  YYSYMBOL_TRUSTACCOUNT = 120,             /* TRUSTACCOUNT  */
  YYSYMBOL_TPRIV_CHAN_LIMIT = 121,         /* TPRIV_CHAN_LIMIT  */
  YYSYMBOL_TPRIV_MODE_LCHAN = 122,         /* TPRIV_MODE_LCHAN  */
  YYSYMBOL_TPRIV_DEOP_LCHAN = 123,         /* TPRIV_DEOP_LCHAN  */
  YYSYMBOL_TPRIV_WALK_LCHAN = 124,         /* TPRIV_WALK_LCHAN  */
  YYSYMBOL_TPRIV_LOCAL_KILL = 125,         /* TPRIV_LOCAL_KILL  */
  YYSYMBOL_TPRIV_REHASH = 126,             /* TPRIV_REHASH  */
  YYSYMBOL_TPRIV_RESTART = 127,            /* TPRIV_RESTART  */
  YYSYMBOL_TPRIV_DIE = 128,                /* TPRIV_DIE  */
  YYSYMBOL_TPRIV_LOCAL_GLINE = 129,        /* TPRIV_LOCAL_GLINE  */
  YYSYMBOL_TPRIV_LOCAL_JUPE = 130,         /* TPRIV_LOCAL_JUPE  */
  YYSYMBOL_TPRIV_LOCAL_BADCHAN = 131,      /* TPRIV_LOCAL_BADCHAN  */
  YYSYMBOL_TPRIV_LOCAL_OPMODE = 132,       /* TPRIV_LOCAL_OPMODE  */
  YYSYMBOL_TPRIV_OPMODE = 133,             /* TPRIV_OPMODE  */
  YYSYMBOL_TPRIV_SET = 134,                /* TPRIV_SET  */
  YYSYMBOL_TPRIV_WHOX = 135,               /* TPRIV_WHOX  */
  YYSYMBOL_TPRIV_BADCHAN = 136,            /* TPRIV_BADCHAN  */
  YYSYMBOL_TPRIV_SEE_CHAN = 137,           /* TPRIV_SEE_CHAN  */
  YYSYMBOL_TPRIV_SHOW_INVIS = 138,         /* TPRIV_SHOW_INVIS  */
  YYSYMBOL_TPRIV_SHOW_ALL_INVIS = 139,     /* TPRIV_SHOW_ALL_INVIS  */
  YYSYMBOL_TPRIV_PROPAGATE = 140,          /* TPRIV_PROPAGATE  */
  YYSYMBOL_TPRIV_UNLIMIT_QUERY = 141,      /* TPRIV_UNLIMIT_QUERY  */
  YYSYMBOL_TPRIV_DISPLAY = 142,            /* TPRIV_DISPLAY  */
  YYSYMBOL_TPRIV_SEE_OPERS = 143,          /* TPRIV_SEE_OPERS  */
  YYSYMBOL_TPRIV_WIDE_GLINE = 144,         /* TPRIV_WIDE_GLINE  */
  YYSYMBOL_TPRIV_FORCE_OPMODE = 145,       /* TPRIV_FORCE_OPMODE  */
  YYSYMBOL_TPRIV_FORCE_LOCAL_OPMODE = 146, /* TPRIV_FORCE_LOCAL_OPMODE  */
  YYSYMBOL_TPRIV_APASS_OPMODE = 147,       /* TPRIV_APASS_OPMODE  */
  YYSYMBOL_TPRIV_LIST_CHAN = 148,          /* TPRIV_LIST_CHAN  */
  YYSYMBOL_TPRIV_CHECK = 149,              /* TPRIV_CHECK  */
  YYSYMBOL_TPRIV_WHOIS_NOTICE = 150,       /* TPRIV_WHOIS_NOTICE  */
  YYSYMBOL_TPRIV_HIDE_OPER = 151,          /* TPRIV_HIDE_OPER  */
  YYSYMBOL_TPRIV_HIDE_CHANNELS = 152,      /* TPRIV_HIDE_CHANNELS  */
  YYSYMBOL_TPRIV_HIDE_IDLE = 153,          /* TPRIV_HIDE_IDLE  */
  YYSYMBOL_TPRIV_XTRAOP = 154,             /* TPRIV_XTRAOP  */
  YYSYMBOL_TPRIV_SERVICE = 155,            /* TPRIV_SERVICE  */
  YYSYMBOL_TPRIV_REMOTE = 156,             /* TPRIV_REMOTE  */
  YYSYMBOL_TPRIV_LOCAL_SHUN = 157,         /* TPRIV_LOCAL_SHUN  */
  YYSYMBOL_TPRIV_WIDE_SHUN = 158,          /* TPRIV_WIDE_SHUN  */
  YYSYMBOL_TPRIV_FREEFORM = 159,           /* TPRIV_FREEFORM  */
  YYSYMBOL_TPRIV_REMOTEREHASH = 160,       /* TPRIV_REMOTEREHASH  */
  YYSYMBOL_TPRIV_REMOVE = 161,             /* TPRIV_REMOVE  */
  YYSYMBOL_TPRIV_LOCAL_ZLINE = 162,        /* TPRIV_LOCAL_ZLINE  */
  YYSYMBOL_TPRIV_WIDE_ZLINE = 163,         /* TPRIV_WIDE_ZLINE  */
  YYSYMBOL_TPRIV_TEMPSHUN = 164,           /* TPRIV_TEMPSHUN  */
  YYSYMBOL_TPRIV_NETADMIN = 165,           /* TPRIV_NETADMIN  */
  YYSYMBOL_166_ = 166,                     /* '+'  */
  YYSYMBOL_167_ = 167,                     /* '-'  */
  YYSYMBOL_168_ = 168,                     /* '*'  */
  YYSYMBOL_169_ = 169,                     /* '/'  */
  YYSYMBOL_170_ = 170,                     /* ';'  */
  YYSYMBOL_171_ = 171,                     /* '('  */
  YYSYMBOL_172_ = 172,                     /* ')'  */
  YYSYMBOL_173_ = 173,                     /* '{'  */
  YYSYMBOL_174_ = 174,                     /* '}'  */
  YYSYMBOL_175_ = 175,                     /* '='  */
  YYSYMBOL_YYACCEPT = 176,                 /* $accept  */
  YYSYMBOL_blocks = 177,                   /* blocks  */
  YYSYMBOL_block = 178,                    /* block  */
  YYSYMBOL_timespec = 179,                 /* timespec  */
  YYSYMBOL_factoredtimes = 180,            /* factoredtimes  */
  YYSYMBOL_factoredtime = 181,             /* factoredtime  */
  YYSYMBOL_timefactor = 182,               /* timefactor  */
  YYSYMBOL_sizespec = 183,                 /* sizespec  */
  YYSYMBOL_expr = 184,                     /* expr  */
  YYSYMBOL_jupeblock = 185,                /* jupeblock  */
  YYSYMBOL_jupeitems = 186,                /* jupeitems  */
  YYSYMBOL_jupeitem = 187,                 /* jupeitem  */
  YYSYMBOL_jupenick = 188,                 /* jupenick  */
  YYSYMBOL_generalblock = 189,             /* generalblock  */
  YYSYMBOL_190_1 = 190,                    /* $@1  */
  YYSYMBOL_generalitems = 191,             /* generalitems  */
  YYSYMBOL_generalitem = 192,              /* generalitem  */
  YYSYMBOL_generalnumeric = 193,           /* generalnumeric  */
  YYSYMBOL_generalname = 194,              /* generalname  */
  YYSYMBOL_generaldesc = 195,              /* generaldesc  */
  YYSYMBOL_generalvhost = 196,             /* generalvhost  */
  YYSYMBOL_generaldnsvhost = 197,          /* generaldnsvhost  */
  YYSYMBOL_generaldnsserver = 198,         /* generaldnsserver  */
  YYSYMBOL_adminblock = 199,               /* adminblock  */
  YYSYMBOL_200_2 = 200,                    /* $@2  */
  YYSYMBOL_adminitems = 201,               /* adminitems  */
  YYSYMBOL_adminitem = 202,                /* adminitem  */
  YYSYMBOL_adminlocation = 203,            /* adminlocation  */
  YYSYMBOL_admincontact = 204,             /* admincontact  */
  YYSYMBOL_classblock = 205,               /* classblock  */
  YYSYMBOL_206_3 = 206,                    /* $@3  */
  YYSYMBOL_classitems = 207,               /* classitems  */
  YYSYMBOL_classitem = 208,                /* classitem  */
  YYSYMBOL_classname = 209,                /* classname  */
  YYSYMBOL_classpingfreq = 210,            /* classpingfreq  */
  YYSYMBOL_classconnfreq = 211,            /* classconnfreq  */
  YYSYMBOL_classmaxlinks = 212,            /* classmaxlinks  */
  YYSYMBOL_classsendq = 213,               /* classsendq  */
  YYSYMBOL_classrecvq = 214,               /* classrecvq  */
  YYSYMBOL_classusermode = 215,            /* classusermode  */
  YYSYMBOL_classmaxchans = 216,            /* classmaxchans  */
  YYSYMBOL_classsnomask = 217,             /* classsnomask  */
  YYSYMBOL_classfakelagmin = 218,          /* classfakelagmin  */
  YYSYMBOL_classfakelagfactor = 219,       /* classfakelagfactor  */
  YYSYMBOL_classajoinchan = 220,           /* classajoinchan  */
  YYSYMBOL_classajoinnotice = 221,         /* classajoinnotice  */
  YYSYMBOL_classrestrictjoin = 222,        /* classrestrictjoin  */
  YYSYMBOL_classrestrictpm = 223,          /* classrestrictpm  */
  YYSYMBOL_classrestrictumode = 224,       /* classrestrictumode  */
  YYSYMBOL_connectblock = 225,             /* connectblock  */
  YYSYMBOL_226_4 = 226,                    /* $@4  */
  YYSYMBOL_connectitems = 227,             /* connectitems  */
  YYSYMBOL_connectitem = 228,              /* connectitem  */
  YYSYMBOL_connectname = 229,              /* connectname  */
  YYSYMBOL_connectpass = 230,              /* connectpass  */
  YYSYMBOL_connectclass = 231,             /* connectclass  */
  YYSYMBOL_connecthost = 232,              /* connecthost  */
  YYSYMBOL_connectfrom = 233,              /* connectfrom  */
  YYSYMBOL_connectport = 234,              /* connectport  */
  YYSYMBOL_connectvhost = 235,             /* connectvhost  */
  YYSYMBOL_connectleaf = 236,              /* connectleaf  */
  YYSYMBOL_connecthub = 237,               /* connecthub  */
  YYSYMBOL_connecthublimit = 238,          /* connecthublimit  */
  YYSYMBOL_connectmaxhops = 239,           /* connectmaxhops  */
  YYSYMBOL_connectauto = 240,              /* connectauto  */
  YYSYMBOL_connectssl = 241,               /* connectssl  */
  YYSYMBOL_connectsslfp = 242,             /* connectsslfp  */
  YYSYMBOL_connectsslciphers = 243,        /* connectsslciphers  */
  YYSYMBOL_connecthmac = 244,              /* connecthmac  */
  YYSYMBOL_uworldblock = 245,              /* uworldblock  */
  YYSYMBOL_uworlditems = 246,              /* uworlditems  */
  YYSYMBOL_uworlditem = 247,               /* uworlditem  */
  YYSYMBOL_uworldname = 248,               /* uworldname  */
  YYSYMBOL_operblock = 249,                /* operblock  */
  YYSYMBOL_250_5 = 250,                    /* $@5  */
  YYSYMBOL_operitems = 251,                /* operitems  */
  YYSYMBOL_operitem = 252,                 /* operitem  */
  YYSYMBOL_opername = 253,                 /* opername  */
  YYSYMBOL_operpass = 254,                 /* operpass  */
  YYSYMBOL_operhost = 255,                 /* operhost  */
  YYSYMBOL_operclass = 256,                /* operclass  */
  YYSYMBOL_opersslfp = 257,                /* opersslfp  */
  YYSYMBOL_opersnomask = 258,              /* opersnomask  */
  YYSYMBOL_operajoinchan = 259,            /* operajoinchan  */
  YYSYMBOL_operajoinnotice = 260,          /* operajoinnotice  */
  YYSYMBOL_operswhois = 261,               /* operswhois  */
  YYSYMBOL_priv = 262,                     /* priv  */
  YYSYMBOL_privtype = 263,                 /* privtype  */
  YYSYMBOL_yesorno = 264,                  /* yesorno  */
  YYSYMBOL_address_family = 265,           /* address_family  */
  YYSYMBOL_portblock = 266,                /* portblock  */
  YYSYMBOL_portitems = 267,                /* portitems  */
  YYSYMBOL_portitem = 268,                 /* portitem  */
  YYSYMBOL_portnumber = 269,               /* portnumber  */
  YYSYMBOL_portvhost = 270,                /* portvhost  */
  YYSYMBOL_portvhostnumber = 271,          /* portvhostnumber  */
  YYSYMBOL_portmask = 272,                 /* portmask  */
  YYSYMBOL_portserver = 273,               /* portserver  */
  YYSYMBOL_porthidden = 274,               /* porthidden  */
  YYSYMBOL_portssl = 275,                  /* portssl  */
  YYSYMBOL_clientblock = 276,              /* clientblock  */
  YYSYMBOL_277_6 = 277,                    /* $@6  */
  YYSYMBOL_clientitems = 278,              /* clientitems  */
  YYSYMBOL_clientitem = 279,               /* clientitem  */
  YYSYMBOL_clienthost = 280,               /* clienthost  */
  YYSYMBOL_clientip = 281,                 /* clientip  */
  YYSYMBOL_clientusername = 282,           /* clientusername  */
  YYSYMBOL_clientclass = 283,              /* clientclass  */
  YYSYMBOL_clientpass = 284,               /* clientpass  */
  YYSYMBOL_clientmaxlinks = 285,           /* clientmaxlinks  */
  YYSYMBOL_clientport = 286,               /* clientport  */
  YYSYMBOL_clientcountry = 287,            /* clientcountry  */
  YYSYMBOL_clientcontinent = 288,          /* clientcontinent  */
  YYSYMBOL_clientsslfp = 289,              /* clientsslfp  */
  YYSYMBOL_clientnoidenttilde = 290,       /* clientnoidenttilde  */
  YYSYMBOL_clientredir = 291,              /* clientredir  */
  YYSYMBOL_clienthidehostcomps = 292,      /* clienthidehostcomps  */
  YYSYMBOL_clientajoinchan = 293,          /* clientajoinchan  */
  YYSYMBOL_clientajoinnotice = 294,        /* clientajoinnotice  */
  YYSYMBOL_killblock = 295,                /* killblock  */
  YYSYMBOL_296_7 = 296,                    /* $@7  */
  YYSYMBOL_killitems = 297,                /* killitems  */
  YYSYMBOL_killitem = 298,                 /* killitem  */
  YYSYMBOL_killuhost = 299,                /* killuhost  */
  YYSYMBOL_killusername = 300,             /* killusername  */
  YYSYMBOL_killreal = 301,                 /* killreal  */
  YYSYMBOL_killcountry = 302,              /* killcountry  */
  YYSYMBOL_killcontinent = 303,            /* killcontinent  */
  YYSYMBOL_killversion = 304,              /* killversion  */
  YYSYMBOL_killreason = 305,               /* killreason  */
  YYSYMBOL_killreasonfile = 306,           /* killreasonfile  */
  YYSYMBOL_killauthexempt = 307,           /* killauthexempt  */
  YYSYMBOL_killmark = 308,                 /* killmark  */
  YYSYMBOL_cruleblock = 309,               /* cruleblock  */
  YYSYMBOL_310_8 = 310,                    /* $@8  */
  YYSYMBOL_cruleitems = 311,               /* cruleitems  */
  YYSYMBOL_cruleitem = 312,                /* cruleitem  */
  YYSYMBOL_cruleserver = 313,              /* cruleserver  */
  YYSYMBOL_crulerule = 314,                /* crulerule  */
  YYSYMBOL_cruleall = 315,                 /* cruleall  */
  YYSYMBOL_motdblock = 316,                /* motdblock  */
  YYSYMBOL_motditems = 317,                /* motditems  */
  YYSYMBOL_motditem = 318,                 /* motditem  */
  YYSYMBOL_motdhost = 319,                 /* motdhost  */
  YYSYMBOL_motdcountry = 320,              /* motdcountry  */
  YYSYMBOL_motdcontinent = 321,            /* motdcontinent  */
  YYSYMBOL_motdfile = 322,                 /* motdfile  */
  YYSYMBOL_featuresblock = 323,            /* featuresblock  */
  YYSYMBOL_featureitems = 324,             /* featureitems  */
  YYSYMBOL_featureitem = 325,              /* featureitem  */
  YYSYMBOL_326_9 = 326,                    /* $@9  */
  YYSYMBOL_stringlist = 327,               /* stringlist  */
  YYSYMBOL_extrastring = 328,              /* extrastring  */
  YYSYMBOL_quarantineblock = 329,          /* quarantineblock  */
  YYSYMBOL_quarantineitems = 330,          /* quarantineitems  */
  YYSYMBOL_quarantineitem = 331,           /* quarantineitem  */
  YYSYMBOL_pseudoblock = 332,              /* pseudoblock  */
  YYSYMBOL_333_10 = 333,                   /* $@10  */
  YYSYMBOL_pseudoitems = 334,              /* pseudoitems  */
  YYSYMBOL_pseudoitem = 335,               /* pseudoitem  */
  YYSYMBOL_pseudoname = 336,               /* pseudoname  */
  YYSYMBOL_pseudoprepend = 337,            /* pseudoprepend  */
  YYSYMBOL_pseudodefault = 338,            /* pseudodefault  */
  YYSYMBOL_pseudonick = 339,               /* pseudonick  */
  YYSYMBOL_pseudoflags = 340,              /* pseudoflags  */
  YYSYMBOL_iauthblock = 341,               /* iauthblock  */
  YYSYMBOL_iauthitems = 342,               /* iauthitems  */
  YYSYMBOL_iauthitem = 343,                /* iauthitem  */
  YYSYMBOL_iauthprogram = 344,             /* iauthprogram  */
  YYSYMBOL_345_11 = 345,                   /* $@11  */
  YYSYMBOL_forwardsblock = 346,            /* forwardsblock  */
  YYSYMBOL_347_12 = 347,                   /* $@12  */
  YYSYMBOL_forwarditems = 348,             /* forwarditems  */
  YYSYMBOL_forwarditem = 349,              /* forwarditem  */
  YYSYMBOL_webircblock = 350,              /* webircblock  */
  YYSYMBOL_351_13 = 351,                   /* $@13  */
  YYSYMBOL_webircitems = 352,              /* webircitems  */
  YYSYMBOL_webircitem = 353,               /* webircitem  */
  YYSYMBOL_webircuhost = 354,              /* webircuhost  */
  YYSYMBOL_webircpass = 355,               /* webircpass  */
  YYSYMBOL_webircident = 356,              /* webircident  */
  YYSYMBOL_webircuserident = 357,          /* webircuserident  */
  YYSYMBOL_webircignoreident = 358,        /* webircignoreident  */
  YYSYMBOL_webircstripsslfp = 359,         /* webircstripsslfp  */
  YYSYMBOL_webircenableoptions = 360,      /* webircenableoptions  */
  YYSYMBOL_webirctrustaccount = 361,       /* webirctrustaccount  */
  YYSYMBOL_webircdescription = 362,        /* webircdescription  */
  YYSYMBOL_spoofhostblock = 363,           /* spoofhostblock  */
  YYSYMBOL_364_14 = 364,                   /* $@14  */
  YYSYMBOL_spoofhostitems = 365,           /* spoofhostitems  */
  YYSYMBOL_spoofhostitem = 366,            /* spoofhostitem  */
  YYSYMBOL_spoofhosthost = 367,            /* spoofhosthost  */
  YYSYMBOL_spoofhostpass = 368,            /* spoofhostpass  */
  YYSYMBOL_spoofhostautoapply = 369,       /* spoofhostautoapply  */
  YYSYMBOL_spoofhostismask = 370,          /* spoofhostismask  */
  YYSYMBOL_spoofhostmatchuser = 371,       /* spoofhostmatchuser  */
  YYSYMBOL_exceptblock = 372,              /* exceptblock  */
  YYSYMBOL_373_15 = 373,                   /* $@15  */
  YYSYMBOL_exceptitems = 374,              /* exceptitems  */
  YYSYMBOL_exceptitem = 375,               /* exceptitem  */
  YYSYMBOL_exceptuhost = 376,              /* exceptuhost  */
  YYSYMBOL_exceptshun = 377,               /* exceptshun  */
  YYSYMBOL_exceptkline = 378,              /* exceptkline  */
  YYSYMBOL_exceptgline = 379,              /* exceptgline  */
  YYSYMBOL_exceptzline = 380,              /* exceptzline  */
  YYSYMBOL_exceptident = 381,              /* exceptident  */
  YYSYMBOL_exceptrdns = 382,               /* exceptrdns  */
  YYSYMBOL_exceptipcheck = 383,            /* exceptipcheck  */
  YYSYMBOL_excepttarglimit = 384,          /* excepttarglimit  */
  YYSYMBOL_exceptlistdelay = 385,          /* exceptlistdelay  */
  YYSYMBOL_include = 386                   /* include  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int16 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  68
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   993

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  176
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  211
/* YYNRULES -- Number of rules.  */
#define YYNRULES  467
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  962

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   420


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     171,   172,   168,   166,     2,   167,     2,   169,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,   170,
       2,   175,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   173,     2,   174,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   266,   266,   266,   267,   267,   267,   267,   268,   268,
     268,   268,   268,   269,   269,   269,   269,   269,   270,   270,
     270,   270,   270,   271,   271,   271,   275,   275,   277,   280,
     282,   287,   288,   289,   290,   291,   292,   293,   294,   297,
     300,   303,   306,   309,   312,   318,   322,   325,   328,   331,
     338,   343,   344,   344,   345,   346,   353,   352,   363,   363,
     364,   364,   364,   364,   365,   365,   367,   376,   388,   395,
     412,   434,   443,   442,   458,   458,   459,   459,   460,   469,
     475,   475,   519,   519,   520,   520,   520,   520,   521,   521,
     521,   521,   521,   522,   522,   522,   522,   523,   523,   523,
     523,   524,   529,   533,   537,   541,   545,   549,   554,   558,
     562,   567,   571,   575,   580,   585,   588,   592,   595,   599,
     602,   608,   607,   675,   675,   676,   676,   676,   676,   676,
     677,   677,   677,   677,   678,   678,   678,   678,   679,   679,
     679,   680,   685,   690,   697,   702,   707,   711,   716,   720,
     725,   730,   734,   735,   736,   744,   745,   750,   755,   756,
     758,   759,   759,   760,   761,   767,   766,   816,   816,   817,
     817,   817,   817,   817,   817,   818,   818,   818,   818,   819,
     824,   829,   845,   852,   857,   861,   866,   871,   876,   882,
     892,   893,   894,   895,   896,   897,   898,   899,   900,   901,
     902,   903,   904,   905,   906,   907,   908,   909,   910,   911,
     912,   913,   914,   915,   916,   917,   918,   919,   920,   921,
     922,   923,   924,   925,   926,   927,   928,   929,   930,   931,
     932,   933,   934,   935,   936,   937,   938,   939,   940,   941,
     942,   943,   945,   945,   951,   952,   953,   954,   955,   959,
     994,   994,   995,   995,   995,   995,   995,   995,   995,   996,
    1007,  1017,  1031,  1037,  1040,  1045,  1048,  1053,  1061,  1067,
    1066,  1138,  1138,  1139,  1139,  1139,  1139,  1139,  1140,  1140,
    1140,  1140,  1141,  1141,  1141,  1141,  1142,  1142,  1143,  1156,
    1170,  1175,  1182,  1187,  1191,  1195,  1200,  1205,  1210,  1215,
    1219,  1224,  1230,  1235,  1239,  1244,  1251,  1250,  1275,  1275,
    1276,  1276,  1276,  1276,  1276,  1276,  1276,  1277,  1277,  1277,
    1278,  1297,  1303,  1309,  1315,  1321,  1327,  1334,  1341,  1344,
    1349,  1357,  1356,  1389,  1389,  1390,  1390,  1390,  1392,  1401,
    1407,  1410,  1415,  1426,  1426,  1427,  1427,  1427,  1427,  1428,
    1438,  1448,  1458,  1464,  1465,  1465,  1468,  1467,  1478,  1478,
    1479,  1487,  1488,  1488,  1489,  1499,  1498,  1527,  1527,  1528,
    1528,  1528,  1528,  1529,  1530,  1535,  1540,  1545,  1559,  1564,
    1574,  1574,  1575,  1577,  1576,  1585,  1585,  1591,  1591,  1592,
    1601,  1600,  1642,  1642,  1643,  1643,  1643,  1643,  1644,  1644,
    1644,  1645,  1645,  1646,  1662,  1667,  1672,  1675,  1679,  1682,
    1686,  1689,  1693,  1696,  1700,  1703,  1707,  1714,  1713,  1754,
    1754,  1755,  1755,  1755,  1755,  1756,  1758,  1774,  1780,  1783,
    1787,  1790,  1794,  1797,  1803,  1802,  1833,  1833,  1834,  1834,
    1834,  1834,  1835,  1835,  1835,  1835,  1836,  1836,  1837,  1853,
    1856,  1860,  1863,  1867,  1870,  1874,  1877,  1881,  1884,  1888,
    1891,  1895,  1898,  1902,  1905,  1909,  1912,  1917
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "QSTRING", "NUMBER",
  "GENERAL", "ADMIN", "LOCATION", "CONTACT", "CONNECT", "CLASS", "CHANNEL",
  "PINGFREQ", "CONNECTFREQ", "MAXLINKS", "MAXHOPS", "SENDQ", "RECVQ",
  "NAME", "HOST", "FROM", "IP", "USERNAME", "PASS", "LOCAL", "SECONDS",
  "MINUTES", "HOURS", "DAYS", "WEEKS", "MONTHS", "YEARS", "DECADES",
  "BYTES", "KBYTES", "MBYTES", "GBYTES", "TBYTES", "SERVER", "PORT",
  "MASK", "HUB", "LEAF", "UWORLD", "YES", "NO", "OPER", "VHOST", "HIDDEN",
  "MOTD", "JUPE", "NICK", "NUMERIC", "DESCRIPTION", "CLIENT", "KILL",
  "CRULE", "REAL", "REASON", "TFILE", "RULE", "ALL", "FEATURES",
  "QUARANTINE", "PSEUDO", "PREPEND", "USERMODE", "IAUTH", "TIMEOUT",
  "FAST", "AUTOCONNECT", "PROGRAM", "TOK_IPV4", "TOK_IPV6", "DNS",
  "FORWARDS", "WEBIRC", "IDENT", "USERIDENT", "IGNOREIDENT", "STRIPSSLFP",
  "MAXCHANS", "COUNTRY", "CONTINENT", "VERSION", "SPOOFHOST", "AUTOAPPLY",
  "SNOMASK", "EXCEPT", "SHUN", "KLINE", "GLINE", "ZLINE", "RDNS",
  "IPCHECK", "TARGETLIMIT", "LISTDELAY", "NOIDENTTILDE", "ISMASK",
  "REDIRECT", "HIDEHOSTCOMPONANTS", "HIDEHOSTCOMPONENTS",
  "AUTOJOINCHANNEL", "AUTOJOINNOTICE", "AUTHEXEMPT", "MARK",
  "RESTRICT_JOIN", "RESTRICT_PRIVMSG", "RESTRICT_UMODE", "MATCHUSERNAME",
  "FAKELAGMINIMUM", "FAKELAGFACTOR", "DEFAULTTEXT", "SSLFP", "SSLCIPHERS",
  "INCLUDE", "SSLTOK", "HMACTOK", "SWHOIS", "ENABLEOPTIONS",
  "TRUSTACCOUNT", "TPRIV_CHAN_LIMIT", "TPRIV_MODE_LCHAN",
  "TPRIV_DEOP_LCHAN", "TPRIV_WALK_LCHAN", "TPRIV_LOCAL_KILL",
  "TPRIV_REHASH", "TPRIV_RESTART", "TPRIV_DIE", "TPRIV_LOCAL_GLINE",
  "TPRIV_LOCAL_JUPE", "TPRIV_LOCAL_BADCHAN", "TPRIV_LOCAL_OPMODE",
  "TPRIV_OPMODE", "TPRIV_SET", "TPRIV_WHOX", "TPRIV_BADCHAN",
  "TPRIV_SEE_CHAN", "TPRIV_SHOW_INVIS", "TPRIV_SHOW_ALL_INVIS",
  "TPRIV_PROPAGATE", "TPRIV_UNLIMIT_QUERY", "TPRIV_DISPLAY",
  "TPRIV_SEE_OPERS", "TPRIV_WIDE_GLINE", "TPRIV_FORCE_OPMODE",
  "TPRIV_FORCE_LOCAL_OPMODE", "TPRIV_APASS_OPMODE", "TPRIV_LIST_CHAN",
  "TPRIV_CHECK", "TPRIV_WHOIS_NOTICE", "TPRIV_HIDE_OPER",
  "TPRIV_HIDE_CHANNELS", "TPRIV_HIDE_IDLE", "TPRIV_XTRAOP",
  "TPRIV_SERVICE", "TPRIV_REMOTE", "TPRIV_LOCAL_SHUN", "TPRIV_WIDE_SHUN",
  "TPRIV_FREEFORM", "TPRIV_REMOTEREHASH", "TPRIV_REMOVE",
  "TPRIV_LOCAL_ZLINE", "TPRIV_WIDE_ZLINE", "TPRIV_TEMPSHUN",
  "TPRIV_NETADMIN", "'+'", "'-'", "'*'", "'/'", "';'", "'('", "')'", "'{'",
  "'}'", "'='", "$accept", "blocks", "block", "timespec", "factoredtimes",
  "factoredtime", "timefactor", "sizespec", "expr", "jupeblock",
  "jupeitems", "jupeitem", "jupenick", "generalblock", "$@1",
  "generalitems", "generalitem", "generalnumeric", "generalname",
  "generaldesc", "generalvhost", "generaldnsvhost", "generaldnsserver",
  "adminblock", "$@2", "adminitems", "adminitem", "adminlocation",
  "admincontact", "classblock", "$@3", "classitems", "classitem",
  "classname", "classpingfreq", "classconnfreq", "classmaxlinks",
  "classsendq", "classrecvq", "classusermode", "classmaxchans",
  "classsnomask", "classfakelagmin", "classfakelagfactor",
  "classajoinchan", "classajoinnotice", "classrestrictjoin",
  "classrestrictpm", "classrestrictumode", "connectblock", "$@4",
  "connectitems", "connectitem", "connectname", "connectpass",
  "connectclass", "connecthost", "connectfrom", "connectport",
  "connectvhost", "connectleaf", "connecthub", "connecthublimit",
  "connectmaxhops", "connectauto", "connectssl", "connectsslfp",
  "connectsslciphers", "connecthmac", "uworldblock", "uworlditems",
  "uworlditem", "uworldname", "operblock", "$@5", "operitems", "operitem",
  "opername", "operpass", "operhost", "operclass", "opersslfp",
  "opersnomask", "operajoinchan", "operajoinnotice", "operswhois", "priv",
  "privtype", "yesorno", "address_family", "portblock", "portitems",
  "portitem", "portnumber", "portvhost", "portvhostnumber", "portmask",
  "portserver", "porthidden", "portssl", "clientblock", "$@6",
  "clientitems", "clientitem", "clienthost", "clientip", "clientusername",
  "clientclass", "clientpass", "clientmaxlinks", "clientport",
  "clientcountry", "clientcontinent", "clientsslfp", "clientnoidenttilde",
  "clientredir", "clienthidehostcomps", "clientajoinchan",
  "clientajoinnotice", "killblock", "$@7", "killitems", "killitem",
  "killuhost", "killusername", "killreal", "killcountry", "killcontinent",
  "killversion", "killreason", "killreasonfile", "killauthexempt",
  "killmark", "cruleblock", "$@8", "cruleitems", "cruleitem",
  "cruleserver", "crulerule", "cruleall", "motdblock", "motditems",
  "motditem", "motdhost", "motdcountry", "motdcontinent", "motdfile",
  "featuresblock", "featureitems", "featureitem", "$@9", "stringlist",
  "extrastring", "quarantineblock", "quarantineitems", "quarantineitem",
  "pseudoblock", "$@10", "pseudoitems", "pseudoitem", "pseudoname",
  "pseudoprepend", "pseudodefault", "pseudonick", "pseudoflags",
  "iauthblock", "iauthitems", "iauthitem", "iauthprogram", "$@11",
  "forwardsblock", "$@12", "forwarditems", "forwarditem", "webircblock",
  "$@13", "webircitems", "webircitem", "webircuhost", "webircpass",
  "webircident", "webircuserident", "webircignoreident",
  "webircstripsslfp", "webircenableoptions", "webirctrustaccount",
  "webircdescription", "spoofhostblock", "$@14", "spoofhostitems",
  "spoofhostitem", "spoofhosthost", "spoofhostpass", "spoofhostautoapply",
  "spoofhostismask", "spoofhostmatchuser", "exceptblock", "$@15",
  "exceptitems", "exceptitem", "exceptuhost", "exceptshun", "exceptkline",
  "exceptgline", "exceptzline", "exceptident", "exceptrdns",
  "exceptipcheck", "excepttarglimit", "exceptlistdelay", "include", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-687)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     639,  -131,  -687,  -687,  -687,  -687,  -127,  -124,  -687,  -115,
    -100,  -687,  -687,  -687,   -95,   -92,    80,   -88,  -687,  -687,
      90,  -687,    93,   575,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,   -75,   -57,   -46,
     -41,    13,   100,   -21,   -11,    74,    -9,    73,    91,   163,
     169,   125,   124,   143,   164,  -687,   166,   180,  -687,  -687,
      23,    29,   689,   249,   183,   243,   264,   265,   266,   270,
     257,    13,  -687,  -687,  -687,  -687,  -687,  -687,  -687,   271,
     273,   100,  -687,   409,   274,   275,   276,   277,   279,   -11,
    -687,  -687,  -687,  -687,   280,   282,    74,  -687,   573,    65,
     -27,  -687,     0,  -687,   283,     1,  -687,  -687,   285,   288,
     124,  -687,   439,    24,   281,   228,  -687,   286,   290,   291,
     292,   -24,   294,    23,  -687,  -687,  -687,  -687,  -687,  -687,
     295,   296,    -1,  -687,  -687,  -687,   297,   299,   301,   302,
     303,   304,   305,  -120,   278,   306,   307,   308,   310,   311,
     312,   314,   689,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
     315,   316,   317,   318,   319,   320,  -687,  -687,  -687,   327,
     328,   329,  -687,  -687,  -687,   330,   331,   332,   333,   334,
     335,   338,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,   323,   249,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,   339,    22,   -16,   440,
     -16,    44,    46,   293,  -687,   441,   345,  -687,   341,   342,
     343,   344,   346,   348,   349,   350,   351,    76,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,   454,
     466,   470,   472,   358,  -687,   481,   359,  -687,   402,   403,
     404,   407,   411,   413,   414,   415,   416,   418,   422,   423,
     424,   425,   426,   427,   325,   573,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,   428,   429,   430,   431,   432,   433,   434,   435,   436,
     438,   442,    65,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,   444,   445,   447,   443,   -27,  -687,  -687,
    -687,   448,   456,  -687,   486,   457,  -687,    41,  -687,   458,
    -687,   459,     2,  -687,   460,   461,   468,   471,   477,   478,
     479,   482,   483,   467,    24,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,    21,   484,   487,   489,   490,   491,
     492,   493,   494,   496,   502,   473,   228,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,   517,   612,   628,
     630,   504,   505,   511,  -687,   658,   680,   514,  -687,   684,
      12,   688,   693,   694,   695,   696,  -687,   702,  -687,   707,
      64,   708,   710,    97,   101,   522,  -687,    12,    12,    12,
      12,    12,   713,   714,    12,     6,   715,   716,   106,   142,
     147,    12,    12,   550,  -687,   198,   551,   552,   650,   653,
     722,   559,   729,   563,   564,   565,   567,  -687,   568,  -687,
     736,   737,   738,   739,     9,   740,   741,   742,   743,   577,
    -687,   578,   579,   580,   581,  -687,   582,  -687,   750,    12,
     752,   753,   754,   755,    12,   757,   758,   200,   759,    12,
      12,   760,   761,   762,   596,  -687,   764,   765,   766,   767,
     768,   769,   770,   771,   204,   772,   606,  -687,   774,   775,
     207,   609,  -687,   777,  -687,   611,  -687,   607,   608,   610,
     614,   613,   615,    41,  -687,  -687,  -687,  -687,  -687,   777,
    -687,   783,   617,  -687,   787,   788,   789,   790,   209,   213,
     215,   256,   258,   624,  -687,   620,   621,   622,   623,   625,
      19,  -687,  -687,  -687,  -687,  -687,  -687,   796,   267,   269,
     287,   289,   298,   300,   309,   322,   324,   631,  -687,   634,
     637,   638,   640,   806,   -16,  -687,   641,   642,  -687,   643,
    -687,    12,   -55,   644,   645,   646,   647,   648,   649,   651,
     652,   654,   655,   656,   657,   659,   660,   661,  -687,   662,
      12,  -687,   108,   663,   -12,   664,    -7,   665,   666,   667,
     102,   668,   112,   669,   670,   671,   672,   673,   674,   675,
     676,   117,   122,  -687,  -687,  -687,   677,  -687,  -687,  -687,
    -687,   678,  -687,    18,  -687,  -687,  -687,  -687,  -687,   679,
     681,   682,   683,   685,   127,   686,   687,   690,   691,  -687,
    -687,  -687,  -687,  -687,  -687,   692,   140,   697,   698,   699,
     700,   159,   701,   703,   704,   705,    11,   195,   254,   706,
     709,   711,  -687,   712,   717,   718,   719,   720,   721,   723,
     724,   725,   726,   727,  -687,   728,   730,   731,   732,  -687,
    -687,    14,  -687,  -687,   817,   820,   825,  -687,   847,   733,
    -687,    15,   734,  -687,   735,   744,   745,   746,   747,   748,
     749,   751,   756,   763,   773,   776,   778,   779,  -687,   851,
     855,   372,   381,   385,   780,  -687,   781,   782,   784,   785,
     786,   791,   792,   793,   794,   795,   797,   798,   799,   800,
     801,   802,   803,   804,   805,  -687,  -687,  -687,  -687,  -687,
     807,   856,  -687,  -687,  -687,  -104,    12,    12,    12,    12,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,   108,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,   808,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,   268,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,   809,   810,   811,   812,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,   813,   814,   815,   816,   818,   819,   821,   822,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,   823,  -687,   -48,   -48,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int16 yydefact[] =
{
       0,     0,    56,    72,   121,    80,     0,     0,   165,     0,
       0,   269,   306,   331,     0,     0,     0,     0,   385,   390,
       0,   434,     0,     0,     3,    11,     5,     4,     6,     7,
       8,     9,    10,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    21,    22,    23,    24,    25,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   417,     0,     0,     1,     2,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   251,   252,   253,   254,   255,   256,   257,   258,     0,
       0,   162,   163,     0,     0,     0,     0,     0,     0,   344,
     345,   346,   347,   348,     0,     0,    53,    54,     0,     0,
       0,   356,     0,   355,     0,     0,   363,   365,     0,     0,
     381,   382,     0,     0,     0,     0,   467,     0,     0,     0,
       0,     0,     0,    59,    60,    61,    63,    62,    64,    65,
       0,     0,     0,    75,    76,    77,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   124,   125,   126,   127,   128,   129,   130,   131,
     132,   133,   134,   135,   136,   137,   138,   139,   140,   227,
       0,     0,     0,     0,     0,     0,   218,   201,   194,     0,
       0,     0,   231,   199,   237,     0,     0,     0,     0,     0,
       0,     0,   190,   191,   192,   193,   195,   196,   197,   198,
     200,   202,   208,   203,   204,   205,   206,   207,   209,   210,
     211,   212,   213,   214,   215,   216,   219,   220,   221,   217,
     222,   223,   224,   225,   226,   228,   229,   230,   232,   233,
     234,   235,   236,   238,   239,   240,   241,     0,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    93,    99,   100,
      94,    95,    96,    97,    98,    92,     0,     0,   244,     0,
     244,     0,     0,     0,   250,     0,     0,   161,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   167,   169,
     170,   171,   172,   173,   174,   175,   176,   177,   178,     0,
       0,     0,     0,     0,   343,     0,     0,    52,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   272,   273,   274,   275,   276,
     277,   278,   279,   280,   281,   282,   283,   284,   285,   286,
     287,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   309,   310,   312,   311,   313,   314,   317,   316,
     315,   318,   319,     0,     0,     0,     0,   334,   335,   336,
     337,     0,     0,   354,     0,     0,   362,     0,   383,     0,
     380,     0,     0,   388,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   393,   394,   395,   396,   397,   398,
     400,   401,   402,   399,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   437,   438,   439,   440,
     441,   442,   443,   444,   445,   446,   447,     0,     0,     0,
       0,     0,     0,     0,    58,     0,     0,     0,    74,     0,
       0,     0,     0,     0,     0,     0,   149,     0,   148,     0,
       0,     0,     0,     0,     0,     0,   123,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    82,     0,     0,     0,   245,   246,
       0,     0,     0,     0,     0,     0,     0,   249,     0,   160,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     168,     0,     0,     0,     0,   342,     0,    51,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   271,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   308,     0,     0,
       0,     0,   333,     0,   353,     0,   361,     0,     0,     0,
       0,     0,     0,   368,   369,   370,   373,   371,   372,     0,
     379,     0,     0,   387,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   392,     0,     0,     0,     0,     0,
       0,   419,   421,   422,   423,   424,   425,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   436,     0,
       0,     0,     0,     0,   244,    57,     0,     0,    73,     0,
      45,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   122,     0,
      27,    29,    26,     0,     0,     0,    39,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    81,   242,   243,     0,   263,   264,   247,
     248,     0,   262,     0,   265,   266,   267,   268,   164,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   166,
     349,   352,   350,   351,    55,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   270,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   307,     0,     0,     0,     0,   332,
     360,     0,   359,   364,     0,     0,     0,   378,     0,     0,
     367,     0,     0,   386,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   391,     0,
       0,     0,     0,     0,     0,   420,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   435,    67,    69,    66,    68,
       0,     0,    78,    79,   143,     0,     0,     0,     0,     0,
     151,   141,   144,   145,   142,   146,   150,   147,   152,   153,
     156,   157,   154,   155,   158,   159,   102,    28,     0,    31,
      32,    33,    34,    35,    36,    37,    38,    30,   103,   104,
     105,    40,    41,    42,    43,    44,   106,   101,   107,   108,
     110,   109,   113,   114,   115,   116,   117,   118,   119,   120,
     111,   112,   189,   259,     0,   260,   182,   179,   181,   180,
     185,   184,   186,   187,   183,   188,   291,   293,   288,   289,
     290,   292,   294,   295,   296,   298,   299,   301,     0,   302,
     303,   304,   305,   297,   320,   321,   322,   326,   327,   323,
     324,   325,   328,   329,   330,   338,   339,   340,   341,   357,
     358,     0,     0,     0,     0,   366,   384,   389,   403,   404,
     416,   405,   406,   407,   408,   409,   410,   411,   412,   413,
     414,   415,     0,     0,     0,     0,     0,     0,     0,     0,
     418,   448,   457,   458,   449,   450,   451,   452,   453,   454,
     455,   456,   459,   460,   461,   462,   463,   464,   465,   466,
      71,     0,    50,    46,    47,    48,    49,   261,   300,   374,
     377,   375,   376,   426,   427,   428,   429,   430,   431,   432,
     433,    70
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -687,  -687,   840,   406,  -687,   235,  -687,   405,  -440,  -687,
     824,  -687,  -687,  -687,  -687,   826,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,   834,  -687,  -687,  -687,
    -687,   629,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,   828,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
     829,  -687,  -687,  -687,  -687,  -687,   585,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,   -91,  -687,  -687,  -269,
    -687,   827,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,   553,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,   528,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,   516,  -687,  -687,  -687,  -687,
    -687,   830,  -687,  -687,  -687,  -687,  -687,  -687,  -687,   832,
    -687,   326,  -686,  -687,  -687,   838,  -687,  -687,   353,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,   837,  -687,  -687,  -687,
    -687,  -687,  -687,   510,  -687,  -687,   513,  -687,  -687,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
     347,  -687,  -687,  -687,  -687,  -687,  -687,  -687,   495,  -687,
    -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,  -687,
    -687
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
       0,    23,    24,   629,   630,   631,   817,   635,   632,    25,
     105,   106,   107,    26,    47,   132,   133,   134,   135,   136,
     137,   138,   139,    27,    48,   142,   143,   144,   145,    28,
      50,   247,   248,   249,   250,   251,   252,   253,   254,   255,
     256,   257,   258,   259,   260,   261,   262,   263,   264,    29,
      49,   161,   162,   163,   164,   165,   166,   167,   168,   169,
     170,   171,   172,   173,   174,   175,   176,   177,   178,    30,
      90,    91,    92,    31,    53,   287,   288,   289,   290,   291,
     292,   293,   294,   295,   296,   297,   265,   266,   656,   480,
      32,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      33,    56,   324,   325,   326,   327,   328,   329,   330,   331,
     332,   333,   334,   335,   336,   337,   338,   339,   340,    34,
      57,   351,   352,   353,   354,   355,   356,   357,   358,   359,
     360,   361,   362,    35,    58,   366,   367,   368,   369,   370,
      36,    98,    99,   100,   101,   102,   103,    37,   112,   113,
     371,   721,   722,    38,   115,   116,    39,   377,   552,   553,
     554,   555,   556,   557,   558,    40,   119,   120,   121,   559,
      41,    63,   382,   383,    42,    64,   393,   394,   395,   396,
     397,   398,   399,   400,   401,   402,   403,    43,   124,   580,
     581,   582,   583,   584,   585,   586,    44,    66,   415,   416,
     417,   418,   419,   420,   421,   422,   423,   424,   425,   426,
      45
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
     612,   482,   298,   111,   114,   381,   140,   141,    94,   641,
     610,   363,   673,   610,   431,   610,   610,   720,   720,   634,
     636,   636,   844,   432,   640,   642,   821,   822,   823,   824,
     825,   651,   652,   364,   365,   890,   140,   141,   575,    46,
     575,   127,   576,   384,   576,   890,    51,   385,    95,    52,
     446,    74,    75,    76,   674,   447,   478,   479,    54,   547,
      77,    78,   786,   787,   788,   789,   476,   477,   942,   686,
     128,    96,    97,    55,   691,   129,   130,   386,    59,   697,
     698,    60,   179,    61,   341,    62,   278,   342,   483,   484,
     485,   486,   548,    65,   279,   280,    67,   131,    70,   281,
     186,   387,   388,   389,   390,   577,   549,   577,   620,   621,
     550,   786,   787,   788,   789,   790,    71,   578,    89,   578,
     788,   789,   343,   344,   345,   104,   187,    72,   579,    79,
     579,   188,    73,   809,   810,   811,   812,   813,   814,   815,
     816,   624,   625,   391,   392,   626,   627,   346,   347,   348,
     645,   646,    93,   551,   786,   787,   788,   789,   819,   786,
     787,   788,   789,   282,   108,   192,   111,   193,   194,   349,
     350,   785,   114,   437,   372,   375,   562,   611,   283,   284,
     611,   867,   611,   611,   889,   896,   647,   648,   845,   285,
     808,   649,   650,   754,   286,   118,   298,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   234,
     235,   236,   237,   238,   239,   240,   241,   242,   243,   244,
     245,   246,   654,   655,   694,   695,   109,   405,   711,   712,
     499,   717,   718,   738,   739,   179,   868,   740,   741,   742,
     743,   180,   181,   182,   110,   183,   184,   185,   786,   787,
     788,   789,   829,   186,   786,   787,   788,   789,   786,   787,
     788,   789,   831,   786,   787,   788,   789,   840,   786,   787,
     788,   789,   841,   786,   787,   788,   789,   851,   117,   187,
     744,   745,   746,   747,   188,   406,   786,   787,   788,   789,
     857,   757,   758,   759,   760,   189,   122,   407,   408,   409,
     410,   411,   412,   413,   414,   786,   787,   788,   789,   862,
     190,   761,   762,   763,   764,   781,   191,   123,   192,   125,
     193,   194,   765,   766,   767,   768,   943,   944,   945,   946,
     126,   195,   196,   769,   770,   197,   198,   199,   267,   200,
     201,   786,   787,   788,   789,   869,   771,   772,   773,   774,
     202,   203,   204,   205,   206,   207,   208,   209,   210,   211,
     212,   213,   214,   215,   216,   217,   218,   219,   220,   221,
     222,   223,   224,   225,   226,   227,   228,   229,   230,   231,
     232,   233,   234,   235,   236,   237,   238,   239,   240,   241,
     242,   243,   244,   245,   246,   179,   914,   915,   268,   278,
     786,   787,   788,   789,   870,   916,   917,   279,   280,   918,
     919,   273,   281,   186,   786,   787,   788,   789,   948,   269,
     270,   271,   381,   481,   488,   272,   275,   276,   448,   299,
     300,   301,   302,   303,   404,   305,   306,   501,   374,   187,
     378,   427,   379,   487,   188,   428,   429,   430,   433,   502,
     435,   436,   439,   503,   440,   504,   441,   442,   443,   444,
     445,   449,   450,   451,   506,   452,   453,   454,   455,   545,
     457,   458,   459,   460,   461,   462,   282,   473,   192,   524,
     193,   194,   463,   464,   465,   466,   467,   468,   469,   470,
     471,   283,   284,   472,   475,   489,   490,   491,   492,   493,
     599,   494,   285,   495,   496,   497,   498,   286,   505,   507,
     202,   203,   204,   205,   206,   207,   208,   209,   210,   211,
     212,   213,   214,   215,   216,   217,   218,   219,   220,   221,
     222,   223,   224,   225,   226,   227,   228,   229,   230,   231,
     232,   233,   234,   235,   236,   237,   238,   239,   240,   241,
     242,   243,   244,   245,   246,    68,     1,   508,   509,   510,
       2,     3,   511,   308,     4,     5,   512,   309,   513,   514,
     515,   516,   310,   517,   311,   312,   313,   518,   519,   520,
     521,   522,   523,   526,   527,   528,   529,   530,   531,   532,
     533,   534,   314,   535,     6,   600,   536,   541,     7,   538,
     539,     8,   540,   543,     9,    10,   544,   546,   560,    11,
      12,    13,   601,   602,   561,   564,   565,    14,    15,    16,
       1,   573,    17,   566,     2,     3,   567,   597,     4,     5,
      18,    19,   568,   569,   570,   315,   316,   571,   572,   587,
      20,   606,   588,    21,   589,   590,   591,   592,   593,   594,
     317,   595,   318,   319,   320,   321,   322,   596,     6,   603,
     604,   605,     7,   607,   608,     8,   323,   609,     9,    10,
      22,   613,   628,    11,    12,    13,   614,   615,   616,   146,
     617,    14,    15,    16,   147,   618,    17,   148,   149,   150,
     619,   622,   151,   623,    18,    19,   638,   639,   643,   644,
     653,   657,   658,   659,    20,   660,   661,    21,   152,   662,
     153,   154,   663,   664,   665,   666,   155,   667,   668,   669,
     670,   671,   672,   675,   676,   677,   678,   679,   680,   681,
     682,   683,   684,   685,    22,   687,   688,   689,   690,   156,
     692,   693,   696,   699,   700,   701,   702,   703,   704,   705,
     706,   707,   708,   709,   710,   713,   714,   715,   716,   719,
     720,   723,   724,   725,   727,   726,   732,   733,   728,   729,
     734,   735,   736,   737,   748,   749,   750,   751,   752,   756,
     753,   775,   157,   158,   776,   159,   160,   777,   778,   780,
     779,   782,   783,   784,   791,   792,   793,   794,   795,   796,
     891,   797,   798,   892,   799,   800,   801,   802,   893,   803,
     804,   805,   806,   818,   820,   826,   827,   828,   830,   832,
     833,   834,   835,   836,   837,   838,   839,   842,   843,   846,
     894,   847,   848,   849,   912,   850,   852,   853,   913,   941,
     854,   855,   856,    69,   633,   807,   637,   858,   859,   860,
     861,   863,   500,   864,   865,   866,   871,   474,   525,   872,
     537,   873,   874,   542,     0,   731,     0,   875,   876,   877,
     878,   879,   563,   880,   881,   882,   883,   884,   885,     0,
     886,   887,   888,   895,   897,   898,   730,   574,   274,     0,
       0,   598,     0,     0,   899,   900,   901,   902,   903,   904,
     277,   905,     0,     0,     0,     0,   906,   755,     0,   304,
     307,     0,     0,   907,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   908,   373,     0,   909,     0,   910,   911,
     920,   921,   922,   376,   923,   924,   925,   380,     0,   434,
       0,   926,   927,   928,   929,   930,     0,   931,   932,   933,
     934,   935,   936,   937,   938,   939,   438,   940,   947,   949,
     950,   951,   952,   953,   954,   955,   956,     0,   957,   958,
     456,   959,   960,   961
};

static const yytype_int16 yycheck[] =
{
     440,   270,    93,     3,     3,     3,     7,     8,    19,     3,
       4,    38,     3,     4,    38,     4,     4,     3,     3,   459,
     460,   461,     4,    47,   464,   465,    33,    34,    35,    36,
      37,   471,   472,    60,    61,   721,     7,     8,    19,   170,
      19,    18,    23,    19,    23,   731,   173,    23,    59,   173,
     170,    38,    39,    40,   494,   175,    72,    73,   173,    18,
      47,    48,   166,   167,   168,   169,    44,    45,   172,   509,
      47,    82,    83,   173,   514,    52,    53,    53,   173,   519,
     520,   173,     6,     3,    19,   173,    10,    22,    44,    45,
      44,    45,    51,     3,    18,    19,     3,    74,   173,    23,
      24,    77,    78,    79,    80,    86,    65,    86,    44,    45,
      69,   166,   167,   168,   169,   170,   173,    98,    18,    98,
     168,   169,    57,    58,    59,    51,    50,   173,   109,   116,
     109,    55,   173,    25,    26,    27,    28,    29,    30,    31,
      32,    44,    45,   119,   120,    44,    45,    82,    83,    84,
      44,    45,   173,   112,   166,   167,   168,   169,   170,   166,
     167,   168,   169,    87,   173,    89,     3,    91,    92,   104,
     105,   611,     3,   174,   174,   174,   174,   171,   102,   103,
     171,   170,   171,   171,   170,   170,    44,    45,   170,   113,
     630,    44,    45,   174,   118,    71,   287,   121,   122,   123,
     124,   125,   126,   127,   128,   129,   130,   131,   132,   133,
     134,   135,   136,   137,   138,   139,   140,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     154,   155,   156,   157,   158,   159,   160,   161,   162,   163,
     164,   165,    44,    45,    44,    45,   173,    19,    44,    45,
     174,    44,    45,    44,    45,     6,   696,    44,    45,    44,
      45,    12,    13,    14,   173,    16,    17,    18,   166,   167,
     168,   169,   170,    24,   166,   167,   168,   169,   166,   167,
     168,   169,   170,   166,   167,   168,   169,   170,   166,   167,
     168,   169,   170,   166,   167,   168,   169,   170,   173,    50,
      44,    45,    44,    45,    55,    77,   166,   167,   168,   169,
     170,    44,    45,    44,    45,    66,   173,    89,    90,    91,
      92,    93,    94,    95,    96,   166,   167,   168,   169,   170,
      81,    44,    45,    44,    45,   604,    87,   173,    89,   173,
      91,    92,    44,    45,    44,    45,   786,   787,   788,   789,
     170,   102,   103,    44,    45,   106,   107,   108,   175,   110,
     111,   166,   167,   168,   169,   170,    44,    45,    44,    45,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,   154,   155,   156,   157,   158,   159,   160,
     161,   162,   163,   164,   165,     6,    44,    45,   175,    10,
     166,   167,   168,   169,   170,    44,    45,    18,    19,    44,
      45,   174,    23,    24,   166,   167,   168,   169,   170,   175,
     175,   175,     3,     3,     3,   175,   175,   174,   170,   175,
     175,   175,   175,   174,   173,   175,   174,     3,   175,    50,
     175,   175,   174,   170,    55,   175,   175,   175,   174,     3,
     175,   175,   175,     3,   175,     3,   175,   175,   175,   175,
     175,   175,   175,   175,     3,   175,   175,   175,   174,     3,
     175,   175,   175,   175,   175,   175,    87,   174,    89,   174,
      91,    92,   175,   175,   175,   175,   175,   175,   175,   175,
     175,   102,   103,   175,   175,   170,   175,   175,   175,   175,
       3,   175,   113,   175,   175,   175,   175,   118,   170,   170,
     121,   122,   123,   124,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,   144,   145,   146,   147,   148,   149,   150,
     151,   152,   153,   154,   155,   156,   157,   158,   159,   160,
     161,   162,   163,   164,   165,     0,     1,   175,   175,   175,
       5,     6,   175,    10,     9,    10,   175,    14,   175,   175,
     175,   175,    19,   175,    21,    22,    23,   175,   175,   175,
     175,   175,   175,   175,   175,   175,   175,   175,   175,   175,
     175,   175,    39,   175,    39,     3,   174,   174,    43,   175,
     175,    46,   175,   175,    49,    50,   170,   170,   170,    54,
      55,    56,     4,     3,   175,   175,   175,    62,    63,    64,
       1,   174,    67,   175,     5,     6,   175,   174,     9,    10,
      75,    76,   175,   175,   175,    82,    83,   175,   175,   175,
      85,     3,   175,    88,   175,   175,   175,   175,   175,   175,
      97,   175,    99,   100,   101,   102,   103,   175,    39,   175,
     175,   170,    43,     3,   170,    46,   113,     3,    49,    50,
     115,     3,   170,    54,    55,    56,     3,     3,     3,    10,
       4,    62,    63,    64,    15,     3,    67,    18,    19,    20,
       3,     3,    23,     3,    75,    76,     3,     3,     3,     3,
     170,   170,   170,    73,    85,    72,     4,    88,    39,   170,
      41,    42,     3,   170,   170,   170,    47,   170,   170,     3,
       3,     3,     3,     3,     3,     3,     3,   170,   170,   170,
     170,   170,   170,     3,   115,     3,     3,     3,     3,    70,
       3,     3,     3,     3,     3,     3,   170,     3,     3,     3,
       3,     3,     3,     3,     3,     3,   170,     3,     3,   170,
       3,   170,   175,   175,   170,   175,     3,   170,   175,   174,
       3,     3,     3,     3,   170,   175,   175,   175,   175,     3,
     175,   170,   113,   114,   170,   116,   117,   170,   170,     3,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
       3,   170,   170,     3,   170,   170,   170,   170,     3,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
       3,   170,   170,   170,     3,   170,   170,   170,     3,     3,
     170,   170,   170,    23,   458,   630,   461,   170,   170,   170,
     170,   170,   287,   170,   170,   170,   170,   248,   325,   170,
     352,   170,   170,   367,    -1,   559,    -1,   170,   170,   170,
     170,   170,   382,   170,   170,   170,   170,   170,   170,    -1,
     170,   170,   170,   170,   170,   170,   553,   394,    81,    -1,
      -1,   416,    -1,    -1,   170,   170,   170,   170,   170,   170,
      91,   170,    -1,    -1,    -1,    -1,   170,   580,    -1,    99,
     106,    -1,    -1,   170,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   170,   112,    -1,   170,    -1,   170,   170,
     170,   170,   170,   115,   170,   170,   170,   120,    -1,   133,
      -1,   170,   170,   170,   170,   170,    -1,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   142,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,    -1,   170,   170,
     162,   170,   170,   170
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int16 yystos[] =
{
       0,     1,     5,     6,     9,    10,    39,    43,    46,    49,
      50,    54,    55,    56,    62,    63,    64,    67,    75,    76,
      85,    88,   115,   177,   178,   185,   189,   199,   205,   225,
     245,   249,   266,   276,   295,   309,   316,   323,   329,   332,
     341,   346,   350,   363,   372,   386,   170,   190,   200,   226,
     206,   173,   173,   250,   173,   173,   277,   296,   310,   173,
     173,     3,   173,   347,   351,     3,   373,     3,     0,   178,
     173,   173,   173,   173,    38,    39,    40,    47,    48,   116,
     267,   268,   269,   270,   271,   272,   273,   274,   275,    18,
     246,   247,   248,   173,    19,    59,    82,    83,   317,   318,
     319,   320,   321,   322,    51,   186,   187,   188,   173,   173,
     173,     3,   324,   325,     3,   330,   331,   173,    71,   342,
     343,   344,   173,   173,   364,   173,   170,    18,    47,    52,
      53,    74,   191,   192,   193,   194,   195,   196,   197,   198,
       7,     8,   201,   202,   203,   204,    10,    15,    18,    19,
      20,    23,    39,    41,    42,    47,    70,   113,   114,   116,
     117,   227,   228,   229,   230,   231,   232,   233,   234,   235,
     236,   237,   238,   239,   240,   241,   242,   243,   244,     6,
      12,    13,    14,    16,    17,    18,    24,    50,    55,    66,
      81,    87,    89,    91,    92,   102,   103,   106,   107,   108,
     110,   111,   121,   122,   123,   124,   125,   126,   127,   128,
     129,   130,   131,   132,   133,   134,   135,   136,   137,   138,
     139,   140,   141,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   152,   153,   154,   155,   156,   157,   158,
     159,   160,   161,   162,   163,   164,   165,   207,   208,   209,
     210,   211,   212,   213,   214,   215,   216,   217,   218,   219,
     220,   221,   222,   223,   224,   262,   263,   175,   175,   175,
     175,   175,   175,   174,   267,   175,   174,   246,    10,    18,
      19,    23,    87,   102,   103,   113,   118,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   260,   261,   262,   175,
     175,   175,   175,   174,   317,   175,   174,   186,    10,    14,
      19,    21,    22,    23,    39,    82,    83,    97,    99,   100,
     101,   102,   103,   113,   278,   279,   280,   281,   282,   283,
     284,   285,   286,   287,   288,   289,   290,   291,   292,   293,
     294,    19,    22,    57,    58,    59,    82,    83,    84,   104,
     105,   297,   298,   299,   300,   301,   302,   303,   304,   305,
     306,   307,   308,    38,    60,    61,   311,   312,   313,   314,
     315,   326,   174,   325,   175,   174,   331,   333,   175,   174,
     342,     3,   348,   349,    19,    23,    53,    77,    78,    79,
      80,   119,   120,   352,   353,   354,   355,   356,   357,   358,
     359,   360,   361,   362,   173,    19,    77,    89,    90,    91,
      92,    93,    94,    95,    96,   374,   375,   376,   377,   378,
     379,   380,   381,   382,   383,   384,   385,   175,   175,   175,
     175,    38,    47,   174,   191,   175,   175,   174,   202,   175,
     175,   175,   175,   175,   175,   175,   170,   175,   170,   175,
     175,   175,   175,   175,   175,   174,   227,   175,   175,   175,
     175,   175,   175,   175,   175,   175,   175,   175,   175,   175,
     175,   175,   175,   174,   207,   175,    44,    45,    72,    73,
     265,     3,   265,    44,    45,    44,    45,   170,     3,   170,
     175,   175,   175,   175,   175,   175,   175,   175,   175,   174,
     252,     3,     3,     3,     3,   170,     3,   170,   175,   175,
     175,   175,   175,   175,   175,   175,   175,   175,   175,   175,
     175,   175,   175,   175,   174,   278,   175,   175,   175,   175,
     175,   175,   175,   175,   175,   175,   174,   297,   175,   175,
     175,   174,   311,   175,   170,     3,   170,    18,    51,    65,
      69,   112,   334,   335,   336,   337,   338,   339,   340,   345,
     170,   175,   174,   349,   175,   175,   175,   175,   175,   175,
     175,   175,   175,   174,   352,    19,    23,    86,    98,   109,
     365,   366,   367,   368,   369,   370,   371,   175,   175,   175,
     175,   175,   175,   175,   175,   175,   175,   174,   374,     3,
       3,     4,     3,   175,   175,   170,     3,     3,   170,     3,
       4,   171,   184,     3,     3,     3,     3,     4,     3,     3,
      44,    45,     3,     3,    44,    45,    44,    45,   170,   179,
     180,   181,   184,   179,   184,   183,   184,   183,     3,     3,
     184,     3,   184,     3,     3,    44,    45,    44,    45,    44,
      45,   184,   184,   170,    44,    45,   264,   170,   170,    73,
      72,     4,   170,     3,   170,   170,   170,   170,   170,     3,
       3,     3,     3,     3,   184,     3,     3,     3,     3,   170,
     170,   170,   170,   170,   170,     3,   184,     3,     3,     3,
       3,   184,     3,     3,    44,    45,     3,   184,   184,     3,
       3,     3,   170,     3,     3,     3,     3,     3,     3,     3,
       3,    44,    45,     3,   170,     3,     3,    44,    45,   170,
       3,   327,   328,   170,   175,   175,   175,   170,   175,   174,
     334,   327,     3,   170,     3,     3,     3,     3,    44,    45,
      44,    45,    44,    45,    44,    45,    44,    45,   170,   175,
     175,   175,   175,   175,   174,   366,     3,    44,    45,    44,
      45,    44,    45,    44,    45,    44,    45,    44,    45,    44,
      45,    44,    45,    44,    45,   170,   170,   170,   170,   170,
       3,   265,   170,   170,   170,   184,   166,   167,   168,   169,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   181,   184,    25,
      26,    27,    28,    29,    30,    31,    32,   182,   170,   170,
     170,    33,    34,    35,    36,    37,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,     4,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   184,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     328,     3,     3,     3,     3,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,     3,     3,    44,    45,    44,    45,    44,    45,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,     3,   172,   184,   184,   184,   184,   170,   170,   170,
     170,   170,   170,   170,   170,   170,   170,   170,   170,   170,
     170,   170
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int16 yyr1[] =
{
       0,   176,   177,   177,   178,   178,   178,   178,   178,   178,
     178,   178,   178,   178,   178,   178,   178,   178,   178,   178,
     178,   178,   178,   178,   178,   178,   179,   179,   180,   180,
     181,   182,   182,   182,   182,   182,   182,   182,   182,   183,
     183,   183,   183,   183,   183,   184,   184,   184,   184,   184,
     184,   185,   186,   186,   187,   188,   190,   189,   191,   191,
     192,   192,   192,   192,   192,   192,   193,   194,   195,   196,
     197,   198,   200,   199,   201,   201,   202,   202,   203,   204,
     206,   205,   207,   207,   208,   208,   208,   208,   208,   208,
     208,   208,   208,   208,   208,   208,   208,   208,   208,   208,
     208,   209,   210,   211,   212,   213,   214,   215,   216,   217,
     217,   218,   219,   220,   221,   222,   222,   223,   223,   224,
     224,   226,   225,   227,   227,   228,   228,   228,   228,   228,
     228,   228,   228,   228,   228,   228,   228,   228,   228,   228,
     228,   229,   230,   231,   232,   233,   234,   235,   236,   237,
     238,   239,   240,   240,   241,   241,   242,   243,   244,   244,
     245,   246,   246,   247,   248,   250,   249,   251,   251,   252,
     252,   252,   252,   252,   252,   252,   252,   252,   252,   253,
     254,   255,   256,   257,   258,   258,   259,   260,   261,   262,
     263,   263,   263,   263,   263,   263,   263,   263,   263,   263,
     263,   263,   263,   263,   263,   263,   263,   263,   263,   263,
     263,   263,   263,   263,   263,   263,   263,   263,   263,   263,
     263,   263,   263,   263,   263,   263,   263,   263,   263,   263,
     263,   263,   263,   263,   263,   263,   263,   263,   263,   263,
     263,   263,   264,   264,   265,   265,   265,   265,   265,   266,
     267,   267,   268,   268,   268,   268,   268,   268,   268,   269,
     270,   271,   272,   273,   273,   274,   274,   275,   275,   277,
     276,   278,   278,   279,   279,   279,   279,   279,   279,   279,
     279,   279,   279,   279,   279,   279,   279,   279,   280,   281,
     282,   283,   284,   285,   286,   287,   288,   289,   290,   290,
     291,   291,   292,   292,   293,   294,   296,   295,   297,   297,
     298,   298,   298,   298,   298,   298,   298,   298,   298,   298,
     299,   300,   301,   302,   303,   304,   305,   306,   307,   307,
     308,   310,   309,   311,   311,   312,   312,   312,   313,   314,
     315,   315,   316,   317,   317,   318,   318,   318,   318,   319,
     320,   321,   322,   323,   324,   324,   326,   325,   327,   327,
     328,   329,   330,   330,   331,   333,   332,   334,   334,   335,
     335,   335,   335,   335,   336,   337,   338,   339,   340,   341,
     342,   342,   343,   345,   344,   347,   346,   348,   348,   349,
     351,   350,   352,   352,   353,   353,   353,   353,   353,   353,
     353,   353,   353,   354,   355,   356,   357,   357,   358,   358,
     359,   359,   360,   360,   361,   361,   362,   364,   363,   365,
     365,   366,   366,   366,   366,   366,   367,   368,   369,   369,
     370,   370,   371,   371,   373,   372,   374,   374,   375,   375,
     375,   375,   375,   375,   375,   375,   375,   375,   376,   377,
     377,   378,   378,   379,   379,   380,   380,   381,   381,   382,
     382,   383,   383,   384,   384,   385,   385,   386
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     2,     1,     1,     2,     1,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       2,     2,     2,     2,     2,     1,     3,     3,     3,     3,
       3,     5,     2,     1,     1,     4,     0,     6,     2,     1,
       1,     1,     1,     1,     1,     1,     4,     4,     4,     4,
       6,     5,     0,     6,     2,     1,     1,     1,     4,     4,
       0,     6,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     0,     6,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     4,     4,     4,     4,     4,     4,     4,     2,     2,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       5,     2,     1,     1,     4,     0,     6,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     0,     1,     1,     2,     2,     5,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     5,
       5,     6,     4,     4,     4,     4,     4,     4,     4,     0,
       6,     2,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       5,     4,     4,     4,     4,     4,     0,     6,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     0,     6,     2,     1,     1,     1,     1,     4,     4,
       4,     4,     5,     2,     1,     1,     1,     1,     1,     4,
       4,     4,     4,     5,     2,     1,     0,     5,     2,     1,
       1,     5,     2,     1,     4,     0,     7,     2,     1,     1,
       1,     1,     1,     1,     4,     4,     4,     4,     2,     5,
       2,     1,     1,     0,     5,     0,     6,     2,     1,     4,
       0,     6,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     0,     7,     1,
       2,     1,     1,     1,     1,     1,     4,     4,     4,     4,
       4,     4,     4,     4,     0,     6,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     3
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 28: /* factoredtimes: factoredtimes factoredtime  */
#line 278 "ircd_parser.y"
{
  (yyval.num) = (yyvsp[-1].num) + (yyvsp[0].num);
}
#line 2507 "y.tab.c"
    break;

  case 30: /* factoredtime: expr timefactor  */
#line 283 "ircd_parser.y"
{
  (yyval.num) = (yyvsp[-1].num) * (yyvsp[0].num);
}
#line 2515 "y.tab.c"
    break;

  case 31: /* timefactor: SECONDS  */
#line 287 "ircd_parser.y"
                    { (yyval.num) = 1; }
#line 2521 "y.tab.c"
    break;

  case 32: /* timefactor: MINUTES  */
#line 288 "ircd_parser.y"
          { (yyval.num) = 60; }
#line 2527 "y.tab.c"
    break;

  case 33: /* timefactor: HOURS  */
#line 289 "ircd_parser.y"
        { (yyval.num) = 60 * 60; }
#line 2533 "y.tab.c"
    break;

  case 34: /* timefactor: DAYS  */
#line 290 "ircd_parser.y"
       { (yyval.num) = 60 * 60 * 24; }
#line 2539 "y.tab.c"
    break;

  case 35: /* timefactor: WEEKS  */
#line 291 "ircd_parser.y"
        { (yyval.num) = 60 * 60 * 24 * 7; }
#line 2545 "y.tab.c"
    break;

  case 36: /* timefactor: MONTHS  */
#line 292 "ircd_parser.y"
         { (yyval.num) = 60 * 60 * 24 * 7 * 4; }
#line 2551 "y.tab.c"
    break;

  case 37: /* timefactor: YEARS  */
#line 293 "ircd_parser.y"
        { (yyval.num) = 60 * 60 * 24 * 365; }
#line 2557 "y.tab.c"
    break;

  case 38: /* timefactor: DECADES  */
#line 294 "ircd_parser.y"
          { (yyval.num) = 60 * 60 * 24 * 365 * 10; }
#line 2563 "y.tab.c"
    break;

  case 39: /* sizespec: expr  */
#line 297 "ircd_parser.y"
                        {
			(yyval.num) = (yyvsp[0].num);
		}
#line 2571 "y.tab.c"
    break;

  case 40: /* sizespec: expr BYTES  */
#line 300 "ircd_parser.y"
                              { 
			(yyval.num) = (yyvsp[-1].num);
		}
#line 2579 "y.tab.c"
    break;

  case 41: /* sizespec: expr KBYTES  */
#line 303 "ircd_parser.y"
                              {
			(yyval.num) = (yyvsp[-1].num) * 1024;
		}
#line 2587 "y.tab.c"
    break;

  case 42: /* sizespec: expr MBYTES  */
#line 306 "ircd_parser.y"
                              {
			(yyval.num) = (yyvsp[-1].num) * 1024 * 1024;
		}
#line 2595 "y.tab.c"
    break;

  case 43: /* sizespec: expr GBYTES  */
#line 309 "ircd_parser.y"
                              {
			(yyval.num) = (yyvsp[-1].num) * 1024 * 1024 * 1024;
		}
#line 2603 "y.tab.c"
    break;

  case 44: /* sizespec: expr TBYTES  */
#line 312 "ircd_parser.y"
                              {
			(yyval.num) = (yyvsp[-1].num) * 1024 * 1024 * 1024;
		}
#line 2611 "y.tab.c"
    break;

  case 45: /* expr: NUMBER  */
#line 319 "ircd_parser.y"
                { 
			(yyval.num) = (yyvsp[0].num);
		}
#line 2619 "y.tab.c"
    break;

  case 46: /* expr: expr '+' expr  */
#line 322 "ircd_parser.y"
                                { 
			(yyval.num) = (yyvsp[-2].num) + (yyvsp[0].num);
		}
#line 2627 "y.tab.c"
    break;

  case 47: /* expr: expr '-' expr  */
#line 325 "ircd_parser.y"
                                { 
			(yyval.num) = (yyvsp[-2].num) - (yyvsp[0].num);
		}
#line 2635 "y.tab.c"
    break;

  case 48: /* expr: expr '*' expr  */
#line 328 "ircd_parser.y"
                                { 
			(yyval.num) = (yyvsp[-2].num) * (yyvsp[0].num);
		}
#line 2643 "y.tab.c"
    break;

  case 49: /* expr: expr '/' expr  */
#line 331 "ircd_parser.y"
                                { 
			(yyval.num) = (yyvsp[-2].num) / (yyvsp[0].num);
		}
#line 2651 "y.tab.c"
    break;

  case 50: /* expr: '(' expr ')'  */
#line 338 "ircd_parser.y"
                               {
			(yyval.num) = (yyvsp[-1].num);
		}
#line 2659 "y.tab.c"
    break;

  case 55: /* jupenick: NICK '=' QSTRING ';'  */
#line 347 "ircd_parser.y"
{
  addNickJupes((yyvsp[-1].text));
  MyFree((yyvsp[-1].text));
}
#line 2668 "y.tab.c"
    break;

  case 56: /* $@1: %empty  */
#line 353 "ircd_parser.y"
{
    /* Zero out the vhost addresses, in case they were removed. */
    memset(&VirtualHost_v4.addr, 0, sizeof(VirtualHost_v4.addr));
    memset(&VirtualHost_v6.addr, 0, sizeof(VirtualHost_v6.addr));
}
#line 2678 "y.tab.c"
    break;

  case 57: /* generalblock: GENERAL $@1 '{' generalitems '}' ';'  */
#line 357 "ircd_parser.y"
                           {
  if (localConf.name == NULL)
    parse_error("Your General block must contain a name.");
  if (localConf.numeric == 0)
    parse_error("Your General block must contain a numeric (between 1 and 4095).");
}
#line 2689 "y.tab.c"
    break;

  case 66: /* generalnumeric: NUMERIC '=' NUMBER ';'  */
#line 368 "ircd_parser.y"
{
  if (localConf.numeric == 0)
    localConf.numeric = (yyvsp[-1].num);
  else if (localConf.numeric != (yyvsp[-1].num))
    parse_error("Redefinition of server numeric %i (%i)", (yyvsp[-1].num),
    		localConf.numeric);
}
#line 2701 "y.tab.c"
    break;

  case 67: /* generalname: NAME '=' QSTRING ';'  */
#line 377 "ircd_parser.y"
{
  if (localConf.name == NULL)
    localConf.name = (yyvsp[-1].text);
  else {
    if (strcmp(localConf.name, (yyvsp[-1].text)))
      parse_error("Redefinition of server name %s (%s)", (yyvsp[-1].text),
                  localConf.name);
    MyFree((yyvsp[-1].text));
  }
}
#line 2716 "y.tab.c"
    break;

  case 68: /* generaldesc: DESCRIPTION '=' QSTRING ';'  */
#line 389 "ircd_parser.y"
{
  MyFree(localConf.description);
  localConf.description = (yyvsp[-1].text);
  ircd_strncpy(cli_info(&me), (yyvsp[-1].text), REALLEN + 1);
}
#line 2726 "y.tab.c"
    break;

  case 69: /* generalvhost: VHOST '=' QSTRING ';'  */
#line 396 "ircd_parser.y"
{
  struct irc_in_addr addr;
  char *vhost = (yyvsp[-1].text);

  if (!strcmp(vhost, "*")) {
    /* This traditionally meant bind to all interfaces and connect
     * from the default. */
  } else if (!ircd_aton(&addr, vhost))
    parse_error("Invalid virtual host '%s'.", vhost);
  else if (irc_in_addr_is_ipv4(&addr))
    memcpy(&VirtualHost_v4.addr, &addr, sizeof(addr));
  else
    memcpy(&VirtualHost_v6.addr, &addr, sizeof(addr));
  MyFree(vhost);
}
#line 2746 "y.tab.c"
    break;

  case 70: /* generaldnsvhost: DNS VHOST '=' address_family QSTRING ';'  */
#line 413 "ircd_parser.y"
{
  struct irc_in_addr addr;
  int families = (yyvsp[-2].num);
  char *vhost = (yyvsp[-1].text);

  if (!strcmp(vhost, "*")) {
    /* Let the operating system assign the default. */
  } else if (!ircd_aton(&addr, vhost))
    parse_error("Invalid DNS virtual host '%s'.", vhost);
  else
  {
    if ((families & USE_IPV4)
        || (!families && irc_in_addr_is_ipv4(&addr)))
      memcpy(&VirtualHost_dns_v4.addr, &addr, sizeof(addr));
    if ((families & USE_IPV6)
        || (!families && !irc_in_addr_is_ipv4(&addr)))
      memcpy(&VirtualHost_dns_v6.addr, &addr, sizeof(addr));
  }
  MyFree(vhost);
}
#line 2771 "y.tab.c"
    break;

  case 71: /* generaldnsserver: DNS SERVER '=' QSTRING ';'  */
#line 435 "ircd_parser.y"
{
  char *server = (yyvsp[-1].text);

  add_nameserver(server);
  MyFree(server);
}
#line 2782 "y.tab.c"
    break;

  case 72: /* $@2: %empty  */
#line 443 "ircd_parser.y"
{
  MyFree(localConf.location1);
  MyFree(localConf.location2);
  MyFree(localConf.contact);
  localConf.location1 = localConf.location2 = localConf.contact = NULL;
}
#line 2793 "y.tab.c"
    break;

  case 73: /* adminblock: ADMIN $@2 '{' adminitems '}' ';'  */
#line 450 "ircd_parser.y"
{
  if (localConf.location1 == NULL)
    DupString(localConf.location1, "");
  if (localConf.location2 == NULL)
    DupString(localConf.location2, "");
  if (localConf.contact == NULL)
    DupString(localConf.contact, "");
}
#line 2806 "y.tab.c"
    break;

  case 78: /* adminlocation: LOCATION '=' QSTRING ';'  */
#line 461 "ircd_parser.y"
{
  if (localConf.location1 == NULL)
    localConf.location1 = (yyvsp[-1].text);
  else if (localConf.location2 == NULL)
    localConf.location2 = (yyvsp[-1].text);
  else /* Otherwise just drop it. -A1kmm */
    MyFree((yyvsp[-1].text));
}
#line 2819 "y.tab.c"
    break;

  case 79: /* admincontact: CONTACT '=' QSTRING ';'  */
#line 470 "ircd_parser.y"
{
 MyFree(localConf.contact);
 localConf.contact = (yyvsp[-1].text);
}
#line 2828 "y.tab.c"
    break;

  case 80: /* $@3: %empty  */
#line 475 "ircd_parser.y"
                  {
  tping = 90;
  snomask = 0;
  fakelagmin = -1;
  fakelagfactor = -1;
  memset(&crestrict, 0, sizeof(crestrict));
}
#line 2840 "y.tab.c"
    break;

  case 81: /* classblock: CLASS $@3 '{' classitems '}' ';'  */
#line 482 "ircd_parser.y"
{
  if (name != NULL)
  {
    struct ConnectionClass *c_class;
    add_class(name, tping, tconn, maxlinks, sendq, recvq);
    c_class = find_class(name);
    MyFree(c_class->default_umode);
    c_class->default_umode = pass;
    MyFree(c_class->autojoinchan);
    c_class->autojoinchan = ajoinchan;
    MyFree(c_class->autojoinnotice);
    c_class->autojoinnotice = ajoinnotice;
    c_class->snomask = snomask;
    c_class->lag_min = fakelagmin;
    c_class->lag_factor = fakelagfactor;
    c_class->max_chans = maxchans;
    memcpy(&c_class->privs, &privs, sizeof(c_class->privs));
    memcpy(&c_class->privs_dirty, &privs_dirty, sizeof(c_class->privs_dirty));
    memcpy(&c_class->restrictflags, &crestrict, sizeof(c_class->restrictflags));
  }
  else {
   parse_error("Missing name in class block");
  }
  name = NULL;
  pass = NULL;
  ajoinchan = NULL;
  ajoinnotice = NULL;
  tconn = 0;
  maxlinks = 0;
  sendq = 0;
  recvq = 0;
  maxchans = 0;
  snomask = 0;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
  memset(&crestrict, 0, sizeof(crestrict));
}
#line 2882 "y.tab.c"
    break;

  case 101: /* classname: NAME '=' QSTRING ';'  */
#line 525 "ircd_parser.y"
{
  MyFree(name);
  name = (yyvsp[-1].text);
}
#line 2891 "y.tab.c"
    break;

  case 102: /* classpingfreq: PINGFREQ '=' timespec ';'  */
#line 530 "ircd_parser.y"
{
  tping = (yyvsp[-1].num);
}
#line 2899 "y.tab.c"
    break;

  case 103: /* classconnfreq: CONNECTFREQ '=' timespec ';'  */
#line 534 "ircd_parser.y"
{
  tconn = (yyvsp[-1].num);
}
#line 2907 "y.tab.c"
    break;

  case 104: /* classmaxlinks: MAXLINKS '=' expr ';'  */
#line 538 "ircd_parser.y"
{
  maxlinks = (yyvsp[-1].num);
}
#line 2915 "y.tab.c"
    break;

  case 105: /* classsendq: SENDQ '=' sizespec ';'  */
#line 542 "ircd_parser.y"
{
  sendq = (yyvsp[-1].num);
}
#line 2923 "y.tab.c"
    break;

  case 106: /* classrecvq: RECVQ '=' sizespec ';'  */
#line 546 "ircd_parser.y"
{
  recvq = (yyvsp[-1].num);
}
#line 2931 "y.tab.c"
    break;

  case 107: /* classusermode: USERMODE '=' QSTRING ';'  */
#line 550 "ircd_parser.y"
{
  MyFree(pass);
  pass = (yyvsp[-1].text);
}
#line 2940 "y.tab.c"
    break;

  case 108: /* classmaxchans: MAXCHANS '=' expr ';'  */
#line 555 "ircd_parser.y"
{
  maxchans = (yyvsp[-1].num);
}
#line 2948 "y.tab.c"
    break;

  case 109: /* classsnomask: SNOMASK '=' expr ';'  */
#line 559 "ircd_parser.y"
{
  snomask = (yyvsp[-1].num);
}
#line 2956 "y.tab.c"
    break;

  case 110: /* classsnomask: SNOMASK '=' QSTRING ';'  */
#line 563 "ircd_parser.y"
{
  snomask = snomask_str_to_mask((yyvsp[-1].text));
  MyFree((yyvsp[-1].text));
}
#line 2965 "y.tab.c"
    break;

  case 111: /* classfakelagmin: FAKELAGMINIMUM '=' expr ';'  */
#line 568 "ircd_parser.y"
{
  fakelagmin = (yyvsp[-1].num);
}
#line 2973 "y.tab.c"
    break;

  case 112: /* classfakelagfactor: FAKELAGFACTOR '=' expr ';'  */
#line 572 "ircd_parser.y"
{
  fakelagfactor = (yyvsp[-1].num);
}
#line 2981 "y.tab.c"
    break;

  case 113: /* classajoinchan: AUTOJOINCHANNEL '=' QSTRING ';'  */
#line 576 "ircd_parser.y"
{
  MyFree(ajoinchan);
  ajoinchan = (yyvsp[-1].text);
}
#line 2990 "y.tab.c"
    break;

  case 114: /* classajoinnotice: AUTOJOINNOTICE '=' QSTRING ';'  */
#line 581 "ircd_parser.y"
{
  MyFree(ajoinnotice);
  ajoinnotice = (yyvsp[-1].text);
}
#line 2999 "y.tab.c"
    break;

  case 115: /* classrestrictjoin: RESTRICT_JOIN '=' YES ';'  */
#line 586 "ircd_parser.y"
{
  FlagSet(&crestrict, CRFLAG_JOIN);
}
#line 3007 "y.tab.c"
    break;

  case 116: /* classrestrictjoin: RESTRICT_JOIN '=' NO ';'  */
#line 589 "ircd_parser.y"
{
  FlagClr(&crestrict, CRFLAG_JOIN);
}
#line 3015 "y.tab.c"
    break;

  case 117: /* classrestrictpm: RESTRICT_PRIVMSG '=' YES ';'  */
#line 593 "ircd_parser.y"
{
  FlagSet(&crestrict, CRFLAG_PRIVMSG);
}
#line 3023 "y.tab.c"
    break;

  case 118: /* classrestrictpm: RESTRICT_PRIVMSG '=' NO ';'  */
#line 596 "ircd_parser.y"
{
  FlagClr(&crestrict, CRFLAG_PRIVMSG);
}
#line 3031 "y.tab.c"
    break;

  case 119: /* classrestrictumode: RESTRICT_UMODE '=' YES ';'  */
#line 600 "ircd_parser.y"
{
  FlagSet(&crestrict, CRFLAG_UMODE);
}
#line 3039 "y.tab.c"
    break;

  case 120: /* classrestrictumode: RESTRICT_UMODE '=' NO ';'  */
#line 603 "ircd_parser.y"
{
  FlagClr(&crestrict, CRFLAG_UMODE);
}
#line 3047 "y.tab.c"
    break;

  case 121: /* $@4: %empty  */
#line 608 "ircd_parser.y"
{
 flags = CONF_AUTOCONNECT;
}
#line 3055 "y.tab.c"
    break;

  case 122: /* connectblock: CONNECT $@4 '{' connectitems '}' ';'  */
#line 611 "ircd_parser.y"
{
 struct ConfItem *aconf = NULL;
 if (name == NULL)
  parse_error("Missing name in connect block");
 else if (pass == NULL)
  parse_error("Missing password in connect block");
 else if (strlen(pass) > PASSWDLEN)
  parse_error("Password too long in connect block");
 else if (host == NULL)
  parse_error("Missing host in connect block");
 else if (strchr(host, '*') || strchr(host, '?'))
  parse_error("Invalid host '%s' in connect block (use 'from' field for wildcard patterns)", host);
 else if (c_class == NULL)
  parse_error("Missing or non-existent class in connect block");
 else {
   aconf = make_conf(CONF_SERVER);
   aconf->name = name;
   aconf->origin_name = origin;
   aconf->passwd = pass;
   aconf->sslfp = sslfp;
   aconf->sslciphers = sslciphers;
   aconf->conn_class = c_class;
   aconf->address.port = port;
   aconf->host = host;
   /* Set from_host for incoming connection validation.
    * If not specified, default to host value for backward compatibility.
    */
   if (from_host) {
     unsigned char addrbits;
     aconf->from_host = from_host;
     /* Try to parse as IP mask */
     if (ipmask_parse(from_host, &aconf->from_address, &addrbits)) {
       aconf->from_addrbits = addrbits;
     } else {
       aconf->from_addrbits = -1;
     }
   } else {
     /* Default: use host for both outbound and inbound */
     DupString(aconf->from_host, host);
     aconf->from_addrbits = -1;
   }
   /* If the user specified a hub allowance, but not maximum links,
    * allow an effectively unlimited number of hops.
    */
   aconf->maximum = (hub_limit != NULL && maxlinks == 0) ? 65535 : maxlinks;
   aconf->hub_limit = hub_limit;
   aconf->flags = flags;
   lookup_confhost(aconf);
 }
 if (!aconf) {
   MyFree(name);
   MyFree(pass);
   MyFree(sslfp);
   MyFree(sslciphers);
   MyFree(host);
   MyFree(from_host);
   MyFree(origin);
   MyFree(hub_limit);
 }
 name = pass = host = from_host = origin = hub_limit = NULL;
 c_class = NULL;
 sslfp = sslciphers = NULL;
 port = flags = maxlinks = 0;
}
#line 3124 "y.tab.c"
    break;

  case 141: /* connectname: NAME '=' QSTRING ';'  */
#line 681 "ircd_parser.y"
{
 MyFree(name);
 name = (yyvsp[-1].text);
}
#line 3133 "y.tab.c"
    break;

  case 142: /* connectpass: PASS '=' QSTRING ';'  */
#line 686 "ircd_parser.y"
{
 MyFree(pass);
 pass = (yyvsp[-1].text);
}
#line 3142 "y.tab.c"
    break;

  case 143: /* connectclass: CLASS '=' QSTRING ';'  */
#line 691 "ircd_parser.y"
{
 c_class = find_class((yyvsp[-1].text));
 if (!c_class)
  parse_error("No such connection class '%s' for Connect block", (yyvsp[-1].text));
 MyFree((yyvsp[-1].text));
}
#line 3153 "y.tab.c"
    break;

  case 144: /* connecthost: HOST '=' QSTRING ';'  */
#line 698 "ircd_parser.y"
{
 MyFree(host);
 host = (yyvsp[-1].text);
}
#line 3162 "y.tab.c"
    break;

  case 145: /* connectfrom: FROM '=' QSTRING ';'  */
#line 703 "ircd_parser.y"
{
 MyFree(from_host);
 from_host = (yyvsp[-1].text);
}
#line 3171 "y.tab.c"
    break;

  case 146: /* connectport: PORT '=' NUMBER ';'  */
#line 708 "ircd_parser.y"
{
 port = (yyvsp[-1].num);
}
#line 3179 "y.tab.c"
    break;

  case 147: /* connectvhost: VHOST '=' QSTRING ';'  */
#line 712 "ircd_parser.y"
{
 MyFree(origin);
 origin = (yyvsp[-1].text);
}
#line 3188 "y.tab.c"
    break;

  case 148: /* connectleaf: LEAF ';'  */
#line 717 "ircd_parser.y"
{
 maxlinks = 0;
}
#line 3196 "y.tab.c"
    break;

  case 149: /* connecthub: HUB ';'  */
#line 721 "ircd_parser.y"
{
 MyFree(hub_limit);
 DupString(hub_limit, "*");
}
#line 3205 "y.tab.c"
    break;

  case 150: /* connecthublimit: HUB '=' QSTRING ';'  */
#line 726 "ircd_parser.y"
{
 MyFree(hub_limit);
 hub_limit = (yyvsp[-1].text);
}
#line 3214 "y.tab.c"
    break;

  case 151: /* connectmaxhops: MAXHOPS '=' expr ';'  */
#line 731 "ircd_parser.y"
{
  maxlinks = (yyvsp[-1].num);
}
#line 3222 "y.tab.c"
    break;

  case 152: /* connectauto: AUTOCONNECT '=' YES ';'  */
#line 734 "ircd_parser.y"
                                     { flags |= CONF_AUTOCONNECT; }
#line 3228 "y.tab.c"
    break;

  case 153: /* connectauto: AUTOCONNECT '=' NO ';'  */
#line 735 "ircd_parser.y"
                          { flags &= ~CONF_AUTOCONNECT; }
#line 3234 "y.tab.c"
    break;

  case 154: /* connectssl: SSLTOK '=' YES ';'  */
#line 737 "ircd_parser.y"
{
#ifdef USE_SSL
  flags |= CONF_SSL;
#else
  parse_error("Connect block has SSL enabled but I'm not built with SSL.  Check ./configure syntax/output.");
  flags &= ~CONF_SSL;
#endif /* USE_SSL */
}
#line 3247 "y.tab.c"
    break;

  case 155: /* connectssl: SSLTOK '=' NO ';'  */
#line 744 "ircd_parser.y"
                      { flags &= ~CONF_SSL; }
#line 3253 "y.tab.c"
    break;

  case 156: /* connectsslfp: SSLFP '=' QSTRING ';'  */
#line 746 "ircd_parser.y"
{
  MyFree(sslfp);
  sslfp = (yyvsp[-1].text);
}
#line 3262 "y.tab.c"
    break;

  case 157: /* connectsslciphers: SSLCIPHERS '=' QSTRING ';'  */
#line 751 "ircd_parser.y"
{
  MyFree(sslciphers);
  sslciphers = (yyvsp[-1].text);
}
#line 3271 "y.tab.c"
    break;

  case 158: /* connecthmac: HMACTOK '=' YES ';'  */
#line 755 "ircd_parser.y"
                                 { flags |= CONF_HMAC; }
#line 3277 "y.tab.c"
    break;

  case 159: /* connecthmac: HMACTOK '=' NO ';'  */
#line 756 "ircd_parser.y"
                      { flags &= ~CONF_HMAC; }
#line 3283 "y.tab.c"
    break;

  case 164: /* uworldname: NAME '=' QSTRING ';'  */
#line 762 "ircd_parser.y"
{
  make_conf(CONF_UWORLD)->host = (yyvsp[-1].text);
}
#line 3291 "y.tab.c"
    break;

  case 165: /* $@5: %empty  */
#line 767 "ircd_parser.y"
{
  snomask = 0;
}
#line 3299 "y.tab.c"
    break;

  case 166: /* operblock: OPER $@5 '{' operitems '}' ';'  */
#line 770 "ircd_parser.y"
{
  struct ConfItem *aconf = NULL;
  struct SLink *link;

  if (name == NULL)
    parse_error("Missing name in operator block");
  else if (pass == NULL)
    parse_error("Missing password in operator block");
  /* Do not check password length because it may be crypted. */
  else if (hosts == NULL)
    parse_error("Missing host(s) in operator block");
  else if (c_class == NULL)
    parse_error("Invalid or missing class in operator block");
  else if (!FlagHas(&privs_dirty, PRIV_PROPAGATE)
           && !FlagHas(&c_class->privs_dirty, PRIV_PROPAGATE))
    parse_error("Operator block for %s and class %s have no LOCAL setting", name, c_class->cc_name);
  else for (link = hosts; link != NULL; link = link->next) {
    aconf = make_conf(CONF_OPERATOR);
    DupString(aconf->name, name);
    DupString(aconf->passwd, pass);
    if (sslfp)
      DupString(aconf->sslfp, sslfp);
    if (ajoinchan)
      DupString(aconf->autojoinchan, ajoinchan);
    if (ajoinnotice)
      DupString(aconf->autojoinnotice, ajoinnotice);
    if (swhois)
      DupString(aconf->swhois, swhois);
    conf_parse_userhost(aconf, link->value.cp);
    aconf->conn_class = c_class;
    aconf->snomask = snomask;
    memcpy(&aconf->privs, &privs, sizeof(aconf->privs));
    memcpy(&aconf->privs_dirty, &privs_dirty, sizeof(aconf->privs_dirty));
  }
  MyFree(name);
  MyFree(pass);
  MyFree(sslfp);
  MyFree(ajoinchan);
  MyFree(ajoinnotice);
  MyFree(swhois);
  free_slist(&hosts);
  name = pass = NULL;
  c_class = NULL;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
}
#line 3350 "y.tab.c"
    break;

  case 179: /* opername: NAME '=' QSTRING ';'  */
#line 820 "ircd_parser.y"
{
  MyFree(name);
  name = (yyvsp[-1].text);
}
#line 3359 "y.tab.c"
    break;

  case 180: /* operpass: PASS '=' QSTRING ';'  */
#line 825 "ircd_parser.y"
{
  MyFree(pass);
  pass = (yyvsp[-1].text);
}
#line 3368 "y.tab.c"
    break;

  case 181: /* operhost: HOST '=' QSTRING ';'  */
#line 830 "ircd_parser.y"
{
 struct SLink *link;
 link = make_link();
 if (!strchr((yyvsp[-1].text), '@'))
 {
   int uh_len;
   link->value.cp = (char*) MyMalloc((uh_len = strlen((yyvsp[-1].text))+3));
   ircd_snprintf(0, link->value.cp, uh_len, "*@%s", (yyvsp[-1].text));
 }
 else
   DupString(link->value.cp, (yyvsp[-1].text));
 MyFree((yyvsp[-1].text));
 link->next = hosts;
 hosts = link;
}
#line 3388 "y.tab.c"
    break;

  case 182: /* operclass: CLASS '=' QSTRING ';'  */
#line 846 "ircd_parser.y"
{
 c_class = find_class((yyvsp[-1].text));
 if (!c_class)
  parse_error("No such connection class '%s' for Operator block", (yyvsp[-1].text));
 MyFree((yyvsp[-1].text));
}
#line 3399 "y.tab.c"
    break;

  case 183: /* opersslfp: SSLFP '=' QSTRING ';'  */
#line 853 "ircd_parser.y"
{
  MyFree(sslfp);
  sslfp = (yyvsp[-1].text);
}
#line 3408 "y.tab.c"
    break;

  case 184: /* opersnomask: SNOMASK '=' expr ';'  */
#line 858 "ircd_parser.y"
{
  snomask = (yyvsp[-1].num);
}
#line 3416 "y.tab.c"
    break;

  case 185: /* opersnomask: SNOMASK '=' QSTRING ';'  */
#line 862 "ircd_parser.y"
{
  snomask = snomask_str_to_mask((yyvsp[-1].text));
  MyFree((yyvsp[-1].text));
}
#line 3425 "y.tab.c"
    break;

  case 186: /* operajoinchan: AUTOJOINCHANNEL '=' QSTRING ';'  */
#line 867 "ircd_parser.y"
{
  MyFree(ajoinchan);
  ajoinchan = (yyvsp[-1].text);
}
#line 3434 "y.tab.c"
    break;

  case 187: /* operajoinnotice: AUTOJOINNOTICE '=' QSTRING ';'  */
#line 872 "ircd_parser.y"
{
  MyFree(ajoinnotice);
  ajoinnotice = (yyvsp[-1].text);
}
#line 3443 "y.tab.c"
    break;

  case 188: /* operswhois: SWHOIS '=' QSTRING ';'  */
#line 877 "ircd_parser.y"
{
  MyFree(swhois);
  swhois = (yyvsp[-1].text);
}
#line 3452 "y.tab.c"
    break;

  case 189: /* priv: privtype '=' yesorno ';'  */
#line 883 "ircd_parser.y"
{
  FlagSet(&privs_dirty, (yyvsp[-3].num));
  if (((yyvsp[-1].num) == 1) ^ invert)
    FlagSet(&privs, (yyvsp[-3].num));
  else
    FlagClr(&privs, (yyvsp[-3].num));
  invert = 0;
}
#line 3465 "y.tab.c"
    break;

  case 190: /* privtype: TPRIV_CHAN_LIMIT  */
#line 892 "ircd_parser.y"
                           { (yyval.num) = PRIV_CHAN_LIMIT; }
#line 3471 "y.tab.c"
    break;

  case 191: /* privtype: TPRIV_MODE_LCHAN  */
#line 893 "ircd_parser.y"
                           { (yyval.num) = PRIV_MODE_LCHAN; }
#line 3477 "y.tab.c"
    break;

  case 192: /* privtype: TPRIV_DEOP_LCHAN  */
#line 894 "ircd_parser.y"
                           { (yyval.num) = PRIV_DEOP_LCHAN; }
#line 3483 "y.tab.c"
    break;

  case 193: /* privtype: TPRIV_WALK_LCHAN  */
#line 895 "ircd_parser.y"
                           { (yyval.num) = PRIV_WALK_LCHAN; }
#line 3489 "y.tab.c"
    break;

  case 194: /* privtype: KILL  */
#line 896 "ircd_parser.y"
               { (yyval.num) = PRIV_KILL; }
#line 3495 "y.tab.c"
    break;

  case 195: /* privtype: TPRIV_LOCAL_KILL  */
#line 897 "ircd_parser.y"
                           { (yyval.num) = PRIV_LOCAL_KILL; }
#line 3501 "y.tab.c"
    break;

  case 196: /* privtype: TPRIV_REHASH  */
#line 898 "ircd_parser.y"
                       { (yyval.num) = PRIV_REHASH; }
#line 3507 "y.tab.c"
    break;

  case 197: /* privtype: TPRIV_RESTART  */
#line 899 "ircd_parser.y"
                        { (yyval.num) = PRIV_RESTART; }
#line 3513 "y.tab.c"
    break;

  case 198: /* privtype: TPRIV_DIE  */
#line 900 "ircd_parser.y"
                    { (yyval.num) = PRIV_DIE; }
#line 3519 "y.tab.c"
    break;

  case 199: /* privtype: GLINE  */
#line 901 "ircd_parser.y"
                { (yyval.num) = PRIV_GLINE; }
#line 3525 "y.tab.c"
    break;

  case 200: /* privtype: TPRIV_LOCAL_GLINE  */
#line 902 "ircd_parser.y"
                            { (yyval.num) = PRIV_LOCAL_GLINE; }
#line 3531 "y.tab.c"
    break;

  case 201: /* privtype: JUPE  */
#line 903 "ircd_parser.y"
               { (yyval.num) = PRIV_JUPE; }
#line 3537 "y.tab.c"
    break;

  case 202: /* privtype: TPRIV_LOCAL_JUPE  */
#line 904 "ircd_parser.y"
                           { (yyval.num) = PRIV_LOCAL_JUPE; }
#line 3543 "y.tab.c"
    break;

  case 203: /* privtype: TPRIV_LOCAL_OPMODE  */
#line 905 "ircd_parser.y"
                             { (yyval.num) = PRIV_LOCAL_OPMODE; }
#line 3549 "y.tab.c"
    break;

  case 204: /* privtype: TPRIV_OPMODE  */
#line 906 "ircd_parser.y"
                       { (yyval.num) = PRIV_OPMODE; }
#line 3555 "y.tab.c"
    break;

  case 205: /* privtype: TPRIV_SET  */
#line 907 "ircd_parser.y"
                    { (yyval.num) = PRIV_SET; }
#line 3561 "y.tab.c"
    break;

  case 206: /* privtype: TPRIV_WHOX  */
#line 908 "ircd_parser.y"
                     { (yyval.num) = PRIV_WHOX; }
#line 3567 "y.tab.c"
    break;

  case 207: /* privtype: TPRIV_BADCHAN  */
#line 909 "ircd_parser.y"
                        { (yyval.num) = PRIV_BADCHAN; }
#line 3573 "y.tab.c"
    break;

  case 208: /* privtype: TPRIV_LOCAL_BADCHAN  */
#line 910 "ircd_parser.y"
                              { (yyval.num) = PRIV_LOCAL_BADCHAN; }
#line 3579 "y.tab.c"
    break;

  case 209: /* privtype: TPRIV_SEE_CHAN  */
#line 911 "ircd_parser.y"
                         { (yyval.num) = PRIV_SEE_CHAN; }
#line 3585 "y.tab.c"
    break;

  case 210: /* privtype: TPRIV_SHOW_INVIS  */
#line 912 "ircd_parser.y"
                           { (yyval.num) = PRIV_SHOW_INVIS; }
#line 3591 "y.tab.c"
    break;

  case 211: /* privtype: TPRIV_SHOW_ALL_INVIS  */
#line 913 "ircd_parser.y"
                               { (yyval.num) = PRIV_SHOW_ALL_INVIS; }
#line 3597 "y.tab.c"
    break;

  case 212: /* privtype: TPRIV_PROPAGATE  */
#line 914 "ircd_parser.y"
                          { (yyval.num) = PRIV_PROPAGATE; }
#line 3603 "y.tab.c"
    break;

  case 213: /* privtype: TPRIV_UNLIMIT_QUERY  */
#line 915 "ircd_parser.y"
                              { (yyval.num) = PRIV_UNLIMIT_QUERY; }
#line 3609 "y.tab.c"
    break;

  case 214: /* privtype: TPRIV_DISPLAY  */
#line 916 "ircd_parser.y"
                        { (yyval.num) = PRIV_DISPLAY; }
#line 3615 "y.tab.c"
    break;

  case 215: /* privtype: TPRIV_SEE_OPERS  */
#line 917 "ircd_parser.y"
                          { (yyval.num) = PRIV_SEE_OPERS; }
#line 3621 "y.tab.c"
    break;

  case 216: /* privtype: TPRIV_WIDE_GLINE  */
#line 918 "ircd_parser.y"
                           { (yyval.num) = PRIV_WIDE_GLINE; }
#line 3627 "y.tab.c"
    break;

  case 217: /* privtype: TPRIV_LIST_CHAN  */
#line 919 "ircd_parser.y"
                          { (yyval.num) = PRIV_LIST_CHAN; }
#line 3633 "y.tab.c"
    break;

  case 218: /* privtype: LOCAL  */
#line 920 "ircd_parser.y"
                { (yyval.num) = PRIV_PROPAGATE; invert = 1; }
#line 3639 "y.tab.c"
    break;

  case 219: /* privtype: TPRIV_FORCE_OPMODE  */
#line 921 "ircd_parser.y"
                             { (yyval.num) = PRIV_FORCE_OPMODE; }
#line 3645 "y.tab.c"
    break;

  case 220: /* privtype: TPRIV_FORCE_LOCAL_OPMODE  */
#line 922 "ircd_parser.y"
                                   { (yyval.num) = PRIV_FORCE_LOCAL_OPMODE; }
#line 3651 "y.tab.c"
    break;

  case 221: /* privtype: TPRIV_APASS_OPMODE  */
#line 923 "ircd_parser.y"
                             { (yyval.num) = PRIV_APASS_OPMODE; }
#line 3657 "y.tab.c"
    break;

  case 222: /* privtype: TPRIV_CHECK  */
#line 924 "ircd_parser.y"
                      { (yyval.num) = PRIV_CHECK; }
#line 3663 "y.tab.c"
    break;

  case 223: /* privtype: TPRIV_WHOIS_NOTICE  */
#line 925 "ircd_parser.y"
                             { (yyval.num) = PRIV_WHOIS_NOTICE; }
#line 3669 "y.tab.c"
    break;

  case 224: /* privtype: TPRIV_HIDE_OPER  */
#line 926 "ircd_parser.y"
                          { (yyval.num) = PRIV_HIDE_OPER; }
#line 3675 "y.tab.c"
    break;

  case 225: /* privtype: TPRIV_HIDE_CHANNELS  */
#line 927 "ircd_parser.y"
                              { (yyval.num) = PRIV_HIDE_CHANNELS; }
#line 3681 "y.tab.c"
    break;

  case 226: /* privtype: TPRIV_HIDE_IDLE  */
#line 928 "ircd_parser.y"
                          { (yyval.num) = PRIV_HIDE_IDLE; }
#line 3687 "y.tab.c"
    break;

  case 227: /* privtype: ADMIN  */
#line 929 "ircd_parser.y"
                { (yyval.num) = PRIV_ADMIN; }
#line 3693 "y.tab.c"
    break;

  case 228: /* privtype: TPRIV_XTRAOP  */
#line 930 "ircd_parser.y"
                       { (yyval.num) = PRIV_XTRAOP; }
#line 3699 "y.tab.c"
    break;

  case 229: /* privtype: TPRIV_SERVICE  */
#line 931 "ircd_parser.y"
                        { (yyval.num) = PRIV_SERVICE; }
#line 3705 "y.tab.c"
    break;

  case 230: /* privtype: TPRIV_REMOTE  */
#line 932 "ircd_parser.y"
                       { (yyval.num) = PRIV_REMOTE; }
#line 3711 "y.tab.c"
    break;

  case 231: /* privtype: SHUN  */
#line 933 "ircd_parser.y"
               { (yyval.num) = PRIV_SHUN; }
#line 3717 "y.tab.c"
    break;

  case 232: /* privtype: TPRIV_LOCAL_SHUN  */
#line 934 "ircd_parser.y"
                           { (yyval.num) = PRIV_LOCAL_SHUN; }
#line 3723 "y.tab.c"
    break;

  case 233: /* privtype: TPRIV_WIDE_SHUN  */
#line 935 "ircd_parser.y"
                          { (yyval.num) = PRIV_WIDE_SHUN; }
#line 3729 "y.tab.c"
    break;

  case 234: /* privtype: TPRIV_FREEFORM  */
#line 936 "ircd_parser.y"
                         { (yyval.num) = PRIV_FREEFORM; }
#line 3735 "y.tab.c"
    break;

  case 235: /* privtype: TPRIV_REMOTEREHASH  */
#line 937 "ircd_parser.y"
                             { (yyval.num) = PRIV_REMOTEREHASH; }
#line 3741 "y.tab.c"
    break;

  case 236: /* privtype: TPRIV_REMOVE  */
#line 938 "ircd_parser.y"
                       { (yyval.num) = PRIV_REMOVE; }
#line 3747 "y.tab.c"
    break;

  case 237: /* privtype: ZLINE  */
#line 939 "ircd_parser.y"
                { (yyval.num) = PRIV_ZLINE; }
#line 3753 "y.tab.c"
    break;

  case 238: /* privtype: TPRIV_LOCAL_ZLINE  */
#line 940 "ircd_parser.y"
                            { (yyval.num) = PRIV_LOCAL_ZLINE; }
#line 3759 "y.tab.c"
    break;

  case 239: /* privtype: TPRIV_WIDE_ZLINE  */
#line 941 "ircd_parser.y"
                           { (yyval.num) = PRIV_WIDE_ZLINE; }
#line 3765 "y.tab.c"
    break;

  case 240: /* privtype: TPRIV_TEMPSHUN  */
#line 942 "ircd_parser.y"
                         { (yyval.num) = PRIV_TEMPSHUN; }
#line 3771 "y.tab.c"
    break;

  case 241: /* privtype: TPRIV_NETADMIN  */
#line 943 "ircd_parser.y"
                         { (yyval.num) = PRIV_NETADMIN; }
#line 3777 "y.tab.c"
    break;

  case 242: /* yesorno: YES  */
#line 945 "ircd_parser.y"
             { (yyval.num) = 1; }
#line 3783 "y.tab.c"
    break;

  case 243: /* yesorno: NO  */
#line 945 "ircd_parser.y"
                              { (yyval.num) = 0; }
#line 3789 "y.tab.c"
    break;

  case 244: /* address_family: %empty  */
#line 951 "ircd_parser.y"
               { (yyval.num) = 0; }
#line 3795 "y.tab.c"
    break;

  case 245: /* address_family: TOK_IPV4  */
#line 952 "ircd_parser.y"
               { (yyval.num) = USE_IPV4; }
#line 3801 "y.tab.c"
    break;

  case 246: /* address_family: TOK_IPV6  */
#line 953 "ircd_parser.y"
               { (yyval.num) = USE_IPV6; }
#line 3807 "y.tab.c"
    break;

  case 247: /* address_family: TOK_IPV4 TOK_IPV6  */
#line 954 "ircd_parser.y"
                        { (yyval.num) = USE_IPV4 | USE_IPV6; }
#line 3813 "y.tab.c"
    break;

  case 248: /* address_family: TOK_IPV6 TOK_IPV4  */
#line 955 "ircd_parser.y"
                        { (yyval.num) = USE_IPV6 | USE_IPV4; }
#line 3819 "y.tab.c"
    break;

  case 249: /* portblock: PORT '{' portitems '}' ';'  */
#line 959 "ircd_parser.y"
                                      {
  struct ListenerFlags flags_here;
  struct SLink *link;
  if (hosts == NULL) {
    struct SLink *link;
    link = make_link();
    DupString(link->value.cp, "*");
    link->flags = 0;
    link->next = hosts;
    hosts = link;
  }
  for (link = hosts; link != NULL; link = link->next) {
    memcpy(&flags_here, &listen_flags, sizeof(flags_here));
    switch (link->flags & (USE_IPV4 | USE_IPV6)) {
    case USE_IPV4:
      FlagSet(&flags_here, LISTEN_IPV4);
      break;
    case USE_IPV6:
      FlagSet(&flags_here, LISTEN_IPV6);
      break;
    default: /* 0 or USE_IPV4|USE_IPV6 */
      FlagSet(&flags_here, LISTEN_IPV4);
      FlagSet(&flags_here, LISTEN_IPV6);
      break;
    }
    if (link->flags & 65535)
      port = link->flags & 65535;
    add_listener(port, link->value.cp, pass, &flags_here);
  }
  free_slist(&hosts);
  MyFree(pass);
  memset(&listen_flags, 0, sizeof(listen_flags));
  pass = NULL;
  port = 0;
}
#line 3859 "y.tab.c"
    break;

  case 259: /* portnumber: PORT '=' address_family NUMBER ';'  */
#line 997 "ircd_parser.y"
{
  if ((yyvsp[-1].num) < 1 || (yyvsp[-1].num) > 65535) {
    parse_error("Port %d is out of range", port);
  } else {
    port = (yyvsp[-2].num) | (yyvsp[-1].num);
    if (hosts && (0 == (hosts->flags & 65535)))
      hosts->flags = (hosts->flags & ~65535) | port;
  }
}
#line 3873 "y.tab.c"
    break;

  case 260: /* portvhost: VHOST '=' address_family QSTRING ';'  */
#line 1008 "ircd_parser.y"
{
  struct SLink *link;
  link = make_link();
  link->value.cp = (yyvsp[-1].text);
  link->flags = (yyvsp[-2].num) | port;
  link->next = hosts;
  hosts = link;
}
#line 3886 "y.tab.c"
    break;

  case 261: /* portvhostnumber: VHOST '=' address_family QSTRING NUMBER ';'  */
#line 1018 "ircd_parser.y"
{
  if ((yyvsp[-1].num) < 1 || (yyvsp[-1].num) > 65535) {
    parse_error("Port %d is out of range", port);
  } else {
    struct SLink *link;
    link = make_link();
    link->value.cp = (yyvsp[-2].text);
    link->flags = (yyvsp[-3].num) | (yyvsp[-1].num);
    link->next = hosts;
    hosts = link;
  }
}
#line 3903 "y.tab.c"
    break;

  case 262: /* portmask: MASK '=' QSTRING ';'  */
#line 1032 "ircd_parser.y"
{
  MyFree(pass);
  pass = (yyvsp[-1].text);
}
#line 3912 "y.tab.c"
    break;

  case 263: /* portserver: SERVER '=' YES ';'  */
#line 1038 "ircd_parser.y"
{
  FlagSet(&listen_flags, LISTEN_SERVER);
}
#line 3920 "y.tab.c"
    break;

  case 264: /* portserver: SERVER '=' NO ';'  */
#line 1041 "ircd_parser.y"
{
  FlagClr(&listen_flags, LISTEN_SERVER);
}
#line 3928 "y.tab.c"
    break;

  case 265: /* porthidden: HIDDEN '=' YES ';'  */
#line 1046 "ircd_parser.y"
{
  FlagSet(&listen_flags, LISTEN_HIDDEN);
}
#line 3936 "y.tab.c"
    break;

  case 266: /* porthidden: HIDDEN '=' NO ';'  */
#line 1049 "ircd_parser.y"
{
  FlagClr(&listen_flags, LISTEN_HIDDEN);
}
#line 3944 "y.tab.c"
    break;

  case 267: /* portssl: SSLTOK '=' YES ';'  */
#line 1054 "ircd_parser.y"
{
#ifdef USE_SSL
  FlagSet(&listen_flags, LISTEN_SSL);
#else
  parse_error("Port block has SSL enabled but I'm not built with SSL.  Check ./configure syntax/output.");
  FlagClr(&listen_flags, LISTEN_SSL);
#endif /* USE_SSL */
}
#line 3957 "y.tab.c"
    break;

  case 268: /* portssl: SSLTOK '=' NO ';'  */
#line 1062 "ircd_parser.y"
{
  FlagClr(&listen_flags, LISTEN_SSL);
}
#line 3965 "y.tab.c"
    break;

  case 269: /* $@6: %empty  */
#line 1067 "ircd_parser.y"
{
  maxlinks = 65535;
  port = 0;
  flags = CONF_NOIDENTTILDE;
  redirport = 0;
  hidehostcomps = -1;
}
#line 3977 "y.tab.c"
    break;

  case 270: /* clientblock: CLIENT $@6 '{' clientitems '}' ';'  */
#line 1075 "ircd_parser.y"
{
  struct ConfItem *aconf = 0;
  struct irc_in_addr addr;
  unsigned char addrbits = 0;

  if (!c_class)
    parse_error("Invalid or missing class in Client block");
  else if (pass && strlen(pass) > PASSWDLEN)
    parse_error("Password too long in connect block");
  else if (ip && !ipmask_parse(ip, &addr, &addrbits))
    parse_error("Invalid IP address %s in Client block", ip);
  else {
    aconf = make_conf(CONF_CLIENT);
    aconf->username = username;
    aconf->host = host;
    if (ip)
      memcpy(&aconf->address.addr, &addr, sizeof(aconf->address.addr));
    else
      memset(&aconf->address.addr, 0, sizeof(aconf->address.addr));
    aconf->address.port = port;
    aconf->addrbits = addrbits;
    aconf->name = ip;
    aconf->conn_class = c_class;
    aconf->maximum = maxlinks;
    aconf->passwd = pass;
    aconf->sslfp = sslfp;
    aconf->countrymask = country;
    aconf->continentmask = continent;
    aconf->redirserver = redirserver;
    aconf->redirport = redirport;
    aconf->flags = flags;
    aconf->hidehostcomps = hidehostcomps;
    aconf->autojoinchan = ajoinchan;
    aconf->autojoinnotice = ajoinnotice;
  }
  if (!aconf) {
    MyFree(username);
    MyFree(host);
    MyFree(ip);
    MyFree(pass);
    MyFree(country);
    MyFree(continent);
    MyFree(sslfp);
    MyFree(redirserver);
    MyFree(ajoinchan);
    MyFree(ajoinnotice);
  }
  host = NULL;
  username = NULL;
  c_class = NULL;
  maxlinks = 0;
  ip = NULL;
  pass = NULL;
  sslfp = NULL;
  port = 0;
  country = NULL;
  continent = NULL;
  redirport = 0;
  redirserver = NULL;
  hidehostcomps = 0;
  ajoinchan = NULL;
  ajoinnotice = NULL;
}
#line 4045 "y.tab.c"
    break;

  case 288: /* clienthost: HOST '=' QSTRING ';'  */
#line 1144 "ircd_parser.y"
{
  char *sep = strchr((yyvsp[-1].text), '@');
  MyFree(host);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(host, sep);
    username = (yyvsp[-1].text);
  } else {
    host = (yyvsp[-1].text);
  }
}
#line 4062 "y.tab.c"
    break;

  case 289: /* clientip: IP '=' QSTRING ';'  */
#line 1157 "ircd_parser.y"
{
  char *sep;
  sep = strchr((yyvsp[-1].text), '@');
  MyFree(ip);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(ip, sep);
    username = (yyvsp[-1].text);
  } else {
    ip = (yyvsp[-1].text);
  }
}
#line 4080 "y.tab.c"
    break;

  case 290: /* clientusername: USERNAME '=' QSTRING ';'  */
#line 1171 "ircd_parser.y"
{
  MyFree(username);
  username = (yyvsp[-1].text);
}
#line 4089 "y.tab.c"
    break;

  case 291: /* clientclass: CLASS '=' QSTRING ';'  */
#line 1176 "ircd_parser.y"
{
  c_class = find_class((yyvsp[-1].text));
  if (!c_class)
    parse_error("No such connection class '%s' for Client block", (yyvsp[-1].text));
  MyFree((yyvsp[-1].text));
}
#line 4100 "y.tab.c"
    break;

  case 292: /* clientpass: PASS '=' QSTRING ';'  */
#line 1183 "ircd_parser.y"
{
  MyFree(pass);
  pass = (yyvsp[-1].text);
}
#line 4109 "y.tab.c"
    break;

  case 293: /* clientmaxlinks: MAXLINKS '=' expr ';'  */
#line 1188 "ircd_parser.y"
{
  maxlinks = (yyvsp[-1].num);
}
#line 4117 "y.tab.c"
    break;

  case 294: /* clientport: PORT '=' expr ';'  */
#line 1192 "ircd_parser.y"
{
  port = (yyvsp[-1].num);
}
#line 4125 "y.tab.c"
    break;

  case 295: /* clientcountry: COUNTRY '=' QSTRING ';'  */
#line 1196 "ircd_parser.y"
{
  MyFree(country);
  country = (yyvsp[-1].text);
}
#line 4134 "y.tab.c"
    break;

  case 296: /* clientcontinent: CONTINENT '=' QSTRING ';'  */
#line 1201 "ircd_parser.y"
{
  MyFree(continent);
  continent = (yyvsp[-1].text);
}
#line 4143 "y.tab.c"
    break;

  case 297: /* clientsslfp: SSLFP '=' QSTRING ';'  */
#line 1206 "ircd_parser.y"
{
  MyFree(sslfp);
  sslfp = (yyvsp[-1].text);
}
#line 4152 "y.tab.c"
    break;

  case 298: /* clientnoidenttilde: NOIDENTTILDE '=' YES ';'  */
#line 1211 "ircd_parser.y"
{
  if (!username)
    DupString(username, "*");
  flags |= CONF_NOIDENTTILDE;
}
#line 4162 "y.tab.c"
    break;

  case 299: /* clientnoidenttilde: NOIDENTTILDE '=' NO ';'  */
#line 1216 "ircd_parser.y"
{
  flags &= ~CONF_NOIDENTTILDE;
}
#line 4170 "y.tab.c"
    break;

  case 300: /* clientredir: REDIRECT '=' QSTRING expr ';'  */
#line 1220 "ircd_parser.y"
{
  redirport = (yyvsp[-1].num);
  MyFree(redirserver);
  redirserver = (yyvsp[-2].text);
}
#line 4180 "y.tab.c"
    break;

  case 301: /* clientredir: REDIRECT '=' QSTRING ';'  */
#line 1225 "ircd_parser.y"
{
  redirport = 6667;
  MyFree(redirserver);
  redirserver = (yyvsp[-1].text);
}
#line 4190 "y.tab.c"
    break;

  case 302: /* clienthidehostcomps: HIDEHOSTCOMPONANTS '=' expr ';'  */
#line 1231 "ircd_parser.y"
{
  log_write(LS_CONFIG, L_WARNING, 0, "Field \"hidehostcomponants\" deprecated, "
            "use \"hosthidecomponents\"");
  hidehostcomps = (yyvsp[-1].num);
}
#line 4200 "y.tab.c"
    break;

  case 303: /* clienthidehostcomps: HIDEHOSTCOMPONENTS '=' expr ';'  */
#line 1236 "ircd_parser.y"
{
  hidehostcomps = (yyvsp[-1].num);
}
#line 4208 "y.tab.c"
    break;

  case 304: /* clientajoinchan: AUTOJOINCHANNEL '=' QSTRING ';'  */
#line 1240 "ircd_parser.y"
{
  MyFree(ajoinchan);
  ajoinchan = (yyvsp[-1].text);
}
#line 4217 "y.tab.c"
    break;

  case 305: /* clientajoinnotice: AUTOJOINNOTICE '=' QSTRING ';'  */
#line 1245 "ircd_parser.y"
{
  MyFree(ajoinnotice);
  ajoinnotice = (yyvsp[-1].text);
}
#line 4226 "y.tab.c"
    break;

  case 306: /* $@7: %empty  */
#line 1251 "ircd_parser.y"
{
  dconf = (struct DenyConf*) MyCalloc(1, sizeof(*dconf));
}
#line 4234 "y.tab.c"
    break;

  case 307: /* killblock: KILL $@7 '{' killitems '}' ';'  */
#line 1254 "ircd_parser.y"
{
  if (dconf->usermask || dconf->hostmask || dconf->realmask ||
      dconf->countrymask || dconf->continentmask || dconf->version) {
    dconf->next = denyConfList;
    denyConfList = dconf;
  }
  else
  {
    MyFree(dconf->usermask);
    MyFree(dconf->hostmask);
    MyFree(dconf->realmask);
    MyFree(dconf->message);
    MyFree(dconf->countrymask);
    MyFree(dconf->continentmask);
    MyFree(dconf->version);
    MyFree(dconf->mark);
    MyFree(dconf);
    parse_error("Kill block must match on at least one of username, host, country, continent or realname");
  }
  dconf = NULL;
}
#line 4260 "y.tab.c"
    break;

  case 320: /* killuhost: HOST '=' QSTRING ';'  */
#line 1279 "ircd_parser.y"
{
  char *h;
  MyFree(dconf->hostmask);
  MyFree(dconf->usermask);
  if ((h = strchr((yyvsp[-1].text), '@')) == NULL)
  {
    DupString(dconf->usermask, "*");
    dconf->hostmask = (yyvsp[-1].text);
  }
  else
  {
    *h++ = '\0';
    DupString(dconf->hostmask, h);
    dconf->usermask = (yyvsp[-1].text);
  }
  ipmask_parse(dconf->hostmask, &dconf->address, &dconf->bits);
}
#line 4282 "y.tab.c"
    break;

  case 321: /* killusername: USERNAME '=' QSTRING ';'  */
#line 1298 "ircd_parser.y"
{
  MyFree(dconf->usermask);
  dconf->usermask = (yyvsp[-1].text);
}
#line 4291 "y.tab.c"
    break;

  case 322: /* killreal: REAL '=' QSTRING ';'  */
#line 1304 "ircd_parser.y"
{
 MyFree(dconf->realmask);
 dconf->realmask = (yyvsp[-1].text);
}
#line 4300 "y.tab.c"
    break;

  case 323: /* killcountry: COUNTRY '=' QSTRING ';'  */
#line 1310 "ircd_parser.y"
{
  MyFree(dconf->countrymask);
  dconf->countrymask = (yyvsp[-1].text);
}
#line 4309 "y.tab.c"
    break;

  case 324: /* killcontinent: CONTINENT '=' QSTRING ';'  */
#line 1316 "ircd_parser.y"
{
  MyFree(dconf->continentmask);
  dconf->continentmask = (yyvsp[-1].text);
}
#line 4318 "y.tab.c"
    break;

  case 325: /* killversion: VERSION '=' QSTRING ';'  */
#line 1322 "ircd_parser.y"
{
  MyFree(dconf->version);
  dconf->version = (yyvsp[-1].text);
}
#line 4327 "y.tab.c"
    break;

  case 326: /* killreason: REASON '=' QSTRING ';'  */
#line 1328 "ircd_parser.y"
{
 dconf->flags &= ~DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = (yyvsp[-1].text);
}
#line 4337 "y.tab.c"
    break;

  case 327: /* killreasonfile: TFILE '=' QSTRING ';'  */
#line 1335 "ircd_parser.y"
{
 dconf->flags |= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = (yyvsp[-1].text);
}
#line 4347 "y.tab.c"
    break;

  case 328: /* killauthexempt: AUTHEXEMPT '=' YES ';'  */
#line 1342 "ircd_parser.y"
{
  dconf->flags |= DENY_FLAGS_AUTHEX;
}
#line 4355 "y.tab.c"
    break;

  case 329: /* killauthexempt: AUTHEXEMPT '=' NO ';'  */
#line 1345 "ircd_parser.y"
{
  dconf->flags &= ~DENY_FLAGS_AUTHEX;
}
#line 4363 "y.tab.c"
    break;

  case 330: /* killmark: MARK '=' QSTRING ';'  */
#line 1350 "ircd_parser.y"
{
 MyFree(dconf->mark);
 dconf->mark = (yyvsp[-1].text);
}
#line 4372 "y.tab.c"
    break;

  case 331: /* $@8: %empty  */
#line 1357 "ircd_parser.y"
{
  tconn = CRULE_AUTO;
}
#line 4380 "y.tab.c"
    break;

  case 332: /* cruleblock: CRULE $@8 '{' cruleitems '}' ';'  */
#line 1360 "ircd_parser.y"
{
  struct CRuleNode *node = NULL;
  struct SLink *link;

  if (hosts == NULL)
    parse_error("Missing server(s) in crule block");
  else if (pass == NULL)
    parse_error("Missing rule in crule block");
  else if ((node = crule_parse(pass)) == NULL)
    parse_error("Invalid rule '%s' in crule block", pass);
  else for (link = hosts; link != NULL; link = link->next)
  {
    struct CRuleConf *p = (struct CRuleConf*) MyMalloc(sizeof(*p));
    if (node == NULL)
      node = crule_parse(pass);
    DupString(p->hostmask, link->value.cp);
    DupString(p->rule, pass);
    p->type = tconn;
    p->node = node;
    node = NULL;
    p->next = cruleConfList;
    cruleConfList = p;
  }
  free_slist(&hosts);
  MyFree(pass);
  pass = NULL;
  tconn = 0;
}
#line 4413 "y.tab.c"
    break;

  case 338: /* cruleserver: SERVER '=' QSTRING ';'  */
#line 1393 "ircd_parser.y"
{
  struct SLink *link;
  link = make_link();
  link->value.cp = (yyvsp[-1].text);
  link->next = hosts;
  hosts = link;
}
#line 4425 "y.tab.c"
    break;

  case 339: /* crulerule: RULE '=' QSTRING ';'  */
#line 1402 "ircd_parser.y"
{
 MyFree(pass);
 pass = (yyvsp[-1].text);
}
#line 4434 "y.tab.c"
    break;

  case 340: /* cruleall: ALL '=' YES ';'  */
#line 1408 "ircd_parser.y"
{
 tconn = CRULE_ALL;
}
#line 4442 "y.tab.c"
    break;

  case 341: /* cruleall: ALL '=' NO ';'  */
#line 1411 "ircd_parser.y"
{
 tconn = CRULE_AUTO;
}
#line 4450 "y.tab.c"
    break;

  case 342: /* motdblock: MOTD '{' motditems '}' ';'  */
#line 1416 "ircd_parser.y"
{
  struct SLink *link;
  if (pass != NULL)
    for (link = hosts; link != NULL; link = link->next)
      motd_add(link->value.cp, pass, link->flags);
  free_slist(&hosts);
  MyFree(pass);
  pass = NULL;
}
#line 4464 "y.tab.c"
    break;

  case 349: /* motdhost: HOST '=' QSTRING ';'  */
#line 1429 "ircd_parser.y"
{
  struct SLink *link;
  link = make_link();
  link->value.cp = (yyvsp[-1].text);
  link->flags = 0;
  link->next = hosts;
  hosts = link;
}
#line 4477 "y.tab.c"
    break;

  case 350: /* motdcountry: COUNTRY '=' QSTRING ';'  */
#line 1439 "ircd_parser.y"
{
  struct SLink *link;
  link = make_link();
  link->value.cp = (yyvsp[-1].text);
  link->flags = MOTD_COUNTRY;
  link->next = hosts;
  hosts = link;
}
#line 4490 "y.tab.c"
    break;

  case 351: /* motdcontinent: CONTINENT '=' QSTRING ';'  */
#line 1449 "ircd_parser.y"
{
  struct SLink *link;
  link = make_link();
  link->value.cp = (yyvsp[-1].text);
  link->flags = MOTD_CONTINENT;
  link->next = hosts;
  hosts = link;
}
#line 4503 "y.tab.c"
    break;

  case 352: /* motdfile: TFILE '=' QSTRING ';'  */
#line 1459 "ircd_parser.y"
{
  MyFree(pass);
  pass = (yyvsp[-1].text);
}
#line 4512 "y.tab.c"
    break;

  case 356: /* $@9: %empty  */
#line 1468 "ircd_parser.y"
{
  stringlist[0] = (yyvsp[0].text);
  stringno = 1;
}
#line 4521 "y.tab.c"
    break;

  case 357: /* featureitem: QSTRING $@9 '=' stringlist ';'  */
#line 1471 "ircd_parser.y"
                     {
  unsigned int ii;
  feature_set(NULL, (const char * const *)stringlist, stringno);
  for (ii = 0; ii < stringno; ++ii)
    MyFree(stringlist[ii]);
}
#line 4532 "y.tab.c"
    break;

  case 360: /* extrastring: QSTRING  */
#line 1480 "ircd_parser.y"
{
  if (stringno < MAX_STRINGS)
    stringlist[stringno++] = (yyvsp[0].text);
  else
    MyFree((yyvsp[0].text));
}
#line 4543 "y.tab.c"
    break;

  case 364: /* quarantineitem: QSTRING '=' QSTRING ';'  */
#line 1490 "ircd_parser.y"
{
  struct qline *qconf = MyCalloc(1, sizeof(*qconf));
  qconf->chname = (yyvsp[-3].text);
  qconf->reason = (yyvsp[-1].text);
  qconf->next = GlobalQuarantineList;
  GlobalQuarantineList = qconf;
}
#line 4555 "y.tab.c"
    break;

  case 365: /* $@10: %empty  */
#line 1499 "ircd_parser.y"
{
  smap = MyCalloc(1, sizeof(struct s_map));
  smap->command = (yyvsp[-1].text);
}
#line 4564 "y.tab.c"
    break;

  case 366: /* pseudoblock: PSEUDO QSTRING '{' $@10 pseudoitems '}' ';'  */
#line 1504 "ircd_parser.y"
{
  int valid = 0;

  if (!smap->name)
    parse_error("Missing name in pseudo %s block", smap->command);
  else if (!smap->services)
    parse_error("Missing nick in pseudo %s block", smap->command);
  else if (!strIsIrcNk(smap->command))
    parse_error("Pseudo command %s invalid: must all be letters, numbers or any of {|}~[\\]^-_`", smap->command);
  else
    valid = 1;
  if (valid && register_mapping(smap))
  {
    smap->next = GlobalServiceMapList;
    GlobalServiceMapList = smap;
  }
  else
  {
    free_mapping(smap);
  }
  smap = NULL;
}
#line 4591 "y.tab.c"
    break;

  case 374: /* pseudoname: NAME '=' QSTRING ';'  */
#line 1531 "ircd_parser.y"
{
  MyFree(smap->name);
  smap->name = (yyvsp[-1].text);
}
#line 4600 "y.tab.c"
    break;

  case 375: /* pseudoprepend: PREPEND '=' QSTRING ';'  */
#line 1536 "ircd_parser.y"
{
  MyFree(smap->prepend);
  smap->prepend = (yyvsp[-1].text);
}
#line 4609 "y.tab.c"
    break;

  case 376: /* pseudodefault: DEFAULTTEXT '=' QSTRING ';'  */
#line 1541 "ircd_parser.y"
{
  MyFree(smap->defaulttext);
  smap->defaulttext = (yyvsp[-1].text);
}
#line 4618 "y.tab.c"
    break;

  case 377: /* pseudonick: NICK '=' QSTRING ';'  */
#line 1546 "ircd_parser.y"
{
  char *sep = strchr((yyvsp[-1].text), '@');

  if (sep != NULL) {
    size_t slen = strlen((yyvsp[-1].text));
    struct nick_host *nh = MyMalloc(sizeof(*nh) + slen);
    memcpy(nh->nick, (yyvsp[-1].text), slen + 1);
    nh->nicklen = sep - (yyvsp[-1].text);
    nh->next = smap->services;
    smap->services = nh;
  }
  MyFree((yyvsp[-1].text));
}
#line 4636 "y.tab.c"
    break;

  case 378: /* pseudoflags: FAST ';'  */
#line 1560 "ircd_parser.y"
{
  smap->flags |= SMAP_FAST;
}
#line 4644 "y.tab.c"
    break;

  case 379: /* iauthblock: IAUTH '{' iauthitems '}' ';'  */
#line 1565 "ircd_parser.y"
{
  auth_spawn(stringno, stringlist);
  while (stringno > 0)
  {
    --stringno;
    MyFree(stringlist[stringno]);
  }
}
#line 4657 "y.tab.c"
    break;

  case 383: /* $@11: %empty  */
#line 1577 "ircd_parser.y"
{
  while (stringno > 0)
  {
    --stringno;
    MyFree(stringlist[stringno]);
  }
}
#line 4669 "y.tab.c"
    break;

  case 385: /* $@12: %empty  */
#line 1585 "ircd_parser.y"
                        {
  unsigned int ii;
  for(ii = 0; ii < 256; ++ii) {
    MyFree(GlobalForwards[ii]);
  }
}
#line 4680 "y.tab.c"
    break;

  case 389: /* forwarditem: QSTRING '=' QSTRING ';'  */
#line 1593 "ircd_parser.y"
{
  unsigned char ch = (yyvsp[-3].text)[0];
  MyFree(GlobalForwards[ch]);
  GlobalForwards[ch] = (yyvsp[-1].text);
  MyFree((yyvsp[-3].text));
}
#line 4691 "y.tab.c"
    break;

  case 390: /* $@13: %empty  */
#line 1601 "ircd_parser.y"
{
  memset(&wflags, 0, sizeof(struct WebIRCFlags));
}
#line 4699 "y.tab.c"
    break;

  case 391: /* webircblock: WEBIRC $@13 '{' webircitems '}' ';'  */
#line 1604 "ircd_parser.y"
{
  struct WebIRCConf *wconf;
  struct SLink *link;
  char *h;

  if (pass == NULL)
    parse_error("Missing password in webirc block");
  else for (link = hosts; link != NULL; link = link->next) {
    wconf = (struct WebIRCConf*) MyCalloc(1, sizeof(*wconf));
    if ((h = strchr(link->value.cp, '@')) == NULL) {
      DupString(wconf->usermask, "*");
      DupString(wconf->hostmask, link->value.cp);
    } else {
      *h++ = '\0';
      DupString(wconf->hostmask, h);
      DupString(wconf->usermask, link->value.cp);
    }
    ipmask_parse(wconf->hostmask, &wconf->address, &wconf->bits);

    memcpy(&wconf->flags, &wflags, sizeof(struct WebIRCFlags));
    DupString(wconf->passwd, pass);
    if (username != NULL)
      DupString(wconf->ident, username);
    if (description != NULL)
      DupString(wconf->description, description);

    wconf->next = webircConfList;
    webircConfList = wconf;
  }

  free_slist(&hosts);
  MyFree(pass);
  MyFree(username);
  MyFree(description);
  pass = username = description = NULL;
  memset(&wflags, 0, sizeof(struct WebIRCFlags));
  wconf = NULL;
}
#line 4742 "y.tab.c"
    break;

  case 403: /* webircuhost: HOST '=' QSTRING ';'  */
#line 1647 "ircd_parser.y"
{
 struct SLink *link;
 link = make_link();
 if (!strchr((yyvsp[-1].text), '@'))
 {
   int uh_len;
   link->value.cp = (char*) MyMalloc((uh_len = strlen((yyvsp[-1].text))+3));
   ircd_snprintf(0, link->value.cp, uh_len, "*@%s", (yyvsp[-1].text));
 }
 else
   DupString(link->value.cp, (yyvsp[-1].text));
 MyFree((yyvsp[-1].text));
 link->next = hosts;
 hosts = link;
}
#line 4762 "y.tab.c"
    break;

  case 404: /* webircpass: PASS '=' QSTRING ';'  */
#line 1663 "ircd_parser.y"
{
  MyFree(pass);
  pass = (yyvsp[-1].text);
}
#line 4771 "y.tab.c"
    break;

  case 405: /* webircident: IDENT '=' QSTRING ';'  */
#line 1668 "ircd_parser.y"
{
  MyFree(username);
  username = (yyvsp[-1].text);
}
#line 4780 "y.tab.c"
    break;

  case 406: /* webircuserident: USERIDENT '=' YES ';'  */
#line 1673 "ircd_parser.y"
{
  FlagSet(&wflags, WFLAG_USERIDENT);
}
#line 4788 "y.tab.c"
    break;

  case 407: /* webircuserident: USERIDENT '=' NO ';'  */
#line 1676 "ircd_parser.y"
{
  FlagClr(&wflags, WFLAG_USERIDENT);
}
#line 4796 "y.tab.c"
    break;

  case 408: /* webircignoreident: IGNOREIDENT '=' YES ';'  */
#line 1680 "ircd_parser.y"
{
  FlagSet(&wflags, WFLAG_NOIDENT);
}
#line 4804 "y.tab.c"
    break;

  case 409: /* webircignoreident: IGNOREIDENT '=' NO ';'  */
#line 1683 "ircd_parser.y"
{
  FlagClr(&wflags, WFLAG_NOIDENT);
}
#line 4812 "y.tab.c"
    break;

  case 410: /* webircstripsslfp: STRIPSSLFP '=' YES ';'  */
#line 1687 "ircd_parser.y"
{
  FlagSet(&wflags, WFLAG_STRIPSSLFP);
}
#line 4820 "y.tab.c"
    break;

  case 411: /* webircstripsslfp: STRIPSSLFP '=' NO ';'  */
#line 1690 "ircd_parser.y"
{
  FlagClr(&wflags, WFLAG_STRIPSSLFP);
}
#line 4828 "y.tab.c"
    break;

  case 412: /* webircenableoptions: ENABLEOPTIONS '=' YES ';'  */
#line 1694 "ircd_parser.y"
{
  FlagSet(&wflags, WFLAG_USEOPTIONS);
}
#line 4836 "y.tab.c"
    break;

  case 413: /* webircenableoptions: ENABLEOPTIONS '=' NO ';'  */
#line 1697 "ircd_parser.y"
{
  FlagClr(&wflags, WFLAG_USEOPTIONS);
}
#line 4844 "y.tab.c"
    break;

  case 414: /* webirctrustaccount: TRUSTACCOUNT '=' YES ';'  */
#line 1701 "ircd_parser.y"
{
  FlagSet(&wflags, WFLAG_TRUSTACCOUNT);
}
#line 4852 "y.tab.c"
    break;

  case 415: /* webirctrustaccount: TRUSTACCOUNT '=' NO ';'  */
#line 1704 "ircd_parser.y"
{
  FlagClr(&wflags, WFLAG_TRUSTACCOUNT);
}
#line 4860 "y.tab.c"
    break;

  case 416: /* webircdescription: DESCRIPTION '=' QSTRING ';'  */
#line 1708 "ircd_parser.y"
{
  MyFree(description);
  description = (yyvsp[-1].text);
}
#line 4869 "y.tab.c"
    break;

  case 417: /* $@14: %empty  */
#line 1714 "ircd_parser.y"
{
  flags = SHFLAG_NOPASS | SHFLAG_MATCHUSER;
  spoofhost = (yyvsp[0].text);
}
#line 4878 "y.tab.c"
    break;

  case 418: /* spoofhostblock: SPOOFHOST QSTRING $@14 '{' spoofhostitems '}' ';'  */
#line 1718 "ircd_parser.y"
{
  struct SLink *link;
  struct SHostConf* sconf;
  char *h;

  if (flags & SHFLAG_ISMASK)
    flags &= ~SHFLAG_AUTOAPPLY;

  if (hosts == NULL)
    parse_error("Missing host(s) in spoofhost block");
  else if (spoofhost == NULL)
    parse_error("Missing spoofhost in spoofhost block");
  else for (link = hosts; link != NULL; link = link->next) {
    sconf = (struct SHostConf*) MyCalloc(1, sizeof(*sconf));
    if (!(flags & SHFLAG_NOPASS))
      DupString(sconf->passwd, pass);
    if ((h = strchr(link->value.cp, '@')) == NULL) {
      DupString(sconf->usermask, "*");
      DupString(sconf->hostmask, link->value.cp);
    } else {
      *h++ = '\0';
      DupString(sconf->hostmask, h);
      DupString(sconf->usermask, link->value.cp);
    }
    ipmask_parse(sconf->hostmask, &sconf->address, &sconf->bits);
    DupString(sconf->spoofhost, spoofhost);
    sconf->flags = flags;

    sconf->next = shostConfList;
    shostConfList = sconf;
  }
  MyFree(spoofhost);
  MyFree(pass);
  free_slist(&hosts);
  flags = 0;
}
#line 4919 "y.tab.c"
    break;

  case 426: /* spoofhosthost: HOST '=' QSTRING ';'  */
#line 1759 "ircd_parser.y"
{
  struct SLink *link;
  link = make_link();
  if (!strchr((yyvsp[-1].text), '@'))
  {
    int uh_len;
    link->value.cp = (char*) MyMalloc((uh_len = strlen((yyvsp[-1].text))+3));
    ircd_snprintf(0, link->value.cp, uh_len, "*@%s", (yyvsp[-1].text));
  }
  else
    DupString(link->value.cp, (yyvsp[-1].text));
  MyFree((yyvsp[-1].text));
  link->next = hosts;
  hosts = link;
}
#line 4939 "y.tab.c"
    break;

  case 427: /* spoofhostpass: PASS '=' QSTRING ';'  */
#line 1775 "ircd_parser.y"
{
  MyFree(pass);
  pass = (yyvsp[-1].text);
  flags &= ~SHFLAG_NOPASS;
}
#line 4949 "y.tab.c"
    break;

  case 428: /* spoofhostautoapply: AUTOAPPLY '=' YES ';'  */
#line 1781 "ircd_parser.y"
{
  flags |= SHFLAG_AUTOAPPLY;
}
#line 4957 "y.tab.c"
    break;

  case 429: /* spoofhostautoapply: AUTOAPPLY '=' NO ';'  */
#line 1784 "ircd_parser.y"
{
  flags &= ~SHFLAG_AUTOAPPLY;
}
#line 4965 "y.tab.c"
    break;

  case 430: /* spoofhostismask: ISMASK '=' YES ';'  */
#line 1788 "ircd_parser.y"
{
  flags |= SHFLAG_ISMASK;
}
#line 4973 "y.tab.c"
    break;

  case 431: /* spoofhostismask: ISMASK '=' NO ';'  */
#line 1791 "ircd_parser.y"
{
  flags &= ~SHFLAG_ISMASK;
}
#line 4981 "y.tab.c"
    break;

  case 432: /* spoofhostmatchuser: MATCHUSERNAME '=' YES ';'  */
#line 1795 "ircd_parser.y"
{
  flags |= SHFLAG_MATCHUSER;
}
#line 4989 "y.tab.c"
    break;

  case 433: /* spoofhostmatchuser: MATCHUSERNAME '=' NO ';'  */
#line 1798 "ircd_parser.y"
{
  flags &= ~SHFLAG_MATCHUSER;
}
#line 4997 "y.tab.c"
    break;

  case 434: /* $@15: %empty  */
#line 1803 "ircd_parser.y"
{
  flags = 0;
}
#line 5005 "y.tab.c"
    break;

  case 435: /* exceptblock: EXCEPT $@15 '{' exceptitems '}' ';'  */
#line 1806 "ircd_parser.y"
{
  struct ExceptConf *econf;
  struct SLink *link;
  char *h;

  if (flags == 0)
    parse_error("Missing exemption type(s)");
  else for (link = hosts; link != NULL; link = link->next) {
    econf = (struct ExceptConf*) MyCalloc(1, sizeof(*econf));
    econf->flags = flags;

    if ((h = strchr(link->value.cp, '@')) == NULL) {
      econf->usermask = NULL;
      DupString(econf->hostmask, link->value.cp);
    } else {
      *h++ = '\0';
      DupString(econf->hostmask, h);
      DupString(econf->usermask, link->value.cp);
    }
    ipmask_parse(econf->hostmask, &econf->address, &econf->bits);

    econf->next = exceptConfList;
    exceptConfList = econf;
  }
  free_slist(&hosts);
  flags = 0;
}
#line 5037 "y.tab.c"
    break;

  case 448: /* exceptuhost: HOST '=' QSTRING ';'  */
#line 1838 "ircd_parser.y"
{
 struct SLink *link;
 link = make_link();
 if (!strchr((yyvsp[-1].text), '@'))
 {
   int uh_len;
   link->value.cp = (char*) MyMalloc((uh_len = strlen((yyvsp[-1].text))+3));
   ircd_snprintf(0, link->value.cp, uh_len, "*@%s", (yyvsp[-1].text));
 }
 else
   DupString(link->value.cp, (yyvsp[-1].text));
 MyFree((yyvsp[-1].text));
 link->next = hosts;
 hosts = link;
}
#line 5057 "y.tab.c"
    break;

  case 449: /* exceptshun: SHUN '=' YES ';'  */
#line 1854 "ircd_parser.y"
{
  flags |= EFLAG_SHUN;
}
#line 5065 "y.tab.c"
    break;

  case 450: /* exceptshun: SHUN '=' NO ';'  */
#line 1857 "ircd_parser.y"
{
  flags &= ~EFLAG_SHUN;
}
#line 5073 "y.tab.c"
    break;

  case 451: /* exceptkline: KLINE '=' YES ';'  */
#line 1861 "ircd_parser.y"
{
  flags |= EFLAG_KLINE;
}
#line 5081 "y.tab.c"
    break;

  case 452: /* exceptkline: KLINE '=' NO ';'  */
#line 1864 "ircd_parser.y"
{
  flags &= ~EFLAG_KLINE;
}
#line 5089 "y.tab.c"
    break;

  case 453: /* exceptgline: GLINE '=' YES ';'  */
#line 1868 "ircd_parser.y"
{
  flags |= EFLAG_GLINE;
}
#line 5097 "y.tab.c"
    break;

  case 454: /* exceptgline: GLINE '=' NO ';'  */
#line 1871 "ircd_parser.y"
{
  flags &= ~EFLAG_GLINE;
}
#line 5105 "y.tab.c"
    break;

  case 455: /* exceptzline: ZLINE '=' YES ';'  */
#line 1875 "ircd_parser.y"
{
  flags |= EFLAG_ZLINE;
}
#line 5113 "y.tab.c"
    break;

  case 456: /* exceptzline: ZLINE '=' NO ';'  */
#line 1878 "ircd_parser.y"
{
  flags &= ~EFLAG_ZLINE;
}
#line 5121 "y.tab.c"
    break;

  case 457: /* exceptident: IDENT '=' YES ';'  */
#line 1882 "ircd_parser.y"
{
  flags |= EFLAG_IDENT;
}
#line 5129 "y.tab.c"
    break;

  case 458: /* exceptident: IDENT '=' NO ';'  */
#line 1885 "ircd_parser.y"
{
  flags &= ~EFLAG_IDENT;
}
#line 5137 "y.tab.c"
    break;

  case 459: /* exceptrdns: RDNS '=' YES ';'  */
#line 1889 "ircd_parser.y"
{
  flags |= EFLAG_RDNS;
}
#line 5145 "y.tab.c"
    break;

  case 460: /* exceptrdns: RDNS '=' NO ';'  */
#line 1892 "ircd_parser.y"
{
  flags &= ~EFLAG_RDNS;
}
#line 5153 "y.tab.c"
    break;

  case 461: /* exceptipcheck: IPCHECK '=' YES ';'  */
#line 1896 "ircd_parser.y"
{
  flags |= EFLAG_IPCHECK;
}
#line 5161 "y.tab.c"
    break;

  case 462: /* exceptipcheck: IPCHECK '=' NO ';'  */
#line 1899 "ircd_parser.y"
{
  flags &= ~EFLAG_IPCHECK;
}
#line 5169 "y.tab.c"
    break;

  case 463: /* excepttarglimit: TARGETLIMIT '=' YES ';'  */
#line 1903 "ircd_parser.y"
{
  flags |= EFLAG_TARGLIMIT;
}
#line 5177 "y.tab.c"
    break;

  case 464: /* excepttarglimit: TARGETLIMIT '=' NO ';'  */
#line 1906 "ircd_parser.y"
{
  flags &= ~EFLAG_TARGLIMIT;
}
#line 5185 "y.tab.c"
    break;

  case 465: /* exceptlistdelay: LISTDELAY '=' YES ';'  */
#line 1910 "ircd_parser.y"
{
  flags |= EFLAG_LISTDELAY;
}
#line 5193 "y.tab.c"
    break;

  case 466: /* exceptlistdelay: LISTDELAY '=' NO ';'  */
#line 1913 "ircd_parser.y"
{
  flags &= ~EFLAG_LISTDELAY;
}
#line 5201 "y.tab.c"
    break;

  case 467: /* include: INCLUDE QSTRING ';'  */
#line 1918 "ircd_parser.y"
{
  init_lexer_file((yyvsp[-1].text));
}
#line 5209 "y.tab.c"
    break;


#line 5213 "y.tab.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

