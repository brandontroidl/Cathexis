/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

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

#line 234 "y.tab.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_Y_TAB_H_INCLUDED  */
