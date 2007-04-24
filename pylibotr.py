from ctypes import *

STRING = c_char_p
_libraries = {}
_libraries['libotr.so.2'] = CDLL('libotr.so.2')


GCRY_AC_ELG_E = 16
ITIMER_PROF = 2
# def gcry_md_putc(h,c): return do { gcry_md_hd_t h__ = (h); if( (h__)->bufpos == (h__)->bufsize ) gcry_md_write( (h__), NULL, 0 ); (h__)->buf[(h__)->bufpos++] = (c) & 0xff; } while(0) # macro
SOCK_RDM = 4
SOCK_RDM = SOCK_RDM # alias
GCRYCTL_GET_ASNOID = 10
def gcry_cipher_cts(h,on): return gcry_cipher_ctl( (h), GCRYCTL_SET_CBC_CTS, NULL, on ) # macro
GPG_ERR_IDENTIFIER_NOT_FOUND = 137
OTRL_MSGTYPE_NOTOTR = 0
_POSIX_PIPE_BUF = 512 # Variable c_int
_POSIX_HIWAT = _POSIX_PIPE_BUF # alias
OTRL_FRAGMENT_COMPLETE = 2
GPG_ERR_SOURCE_SCD = 6
GPG_ERR_ELIBBAD = 32826
GCRYCTL_DROP_PRIVS = 30
GPG_ERR_EUSERS = 32905
# def __FD_ZERO(fdsp): return do { int __d0, __d1; __asm__ __volatile__ ("cld; rep; stosl" : "=c" (__d0), "=D" (__d1) : "a" (0), "0" (sizeof (fd_set) / sizeof (__fd_mask)), "1" (&__FDS_BITS (fdsp)[0]) : "memory"); } while (0) # macro
GCRY_THREAD_OPTION_PTH = 2
GPG_ERR_EAUTH = 32776
def CMSG_NXTHDR(mhdr,cmsg): return __cmsg_nxthdr (mhdr, cmsg) # macro
GPG_ERR_SOURCE_KEYBOX = 8
GCRY_MD_CRC32_RFC1510 = 303
GPG_ERR_NO_ENCODING_METHOD = 22
OTRL_MSGSTATE_PLAINTEXT = 0
GPG_ERR_EISCONN = 32818
GPG_ERR_DIGEST_ALGO = 5
# def __REDIRECT_NTH(name,proto,alias): return name proto __THROW __asm__ (__ASMNAME (#alias)) # macro
OTRL_MSGSTATE_FINISHED = 2
# def __FD_ISSET(fd,fdsp): return (__extension__ ({register char __result; __asm__ __volatile__ ("btl %1,%2 ; setcb %b0" : "=q" (__result) : "r" (((int) (fd)) % __NFDBITS), "m" (__FDS_BITS (fdsp)[__FDELT (fd)]) : "cc"); __result; })) # macro
# __MODE_T_TYPE = __U32_TYPE # alias
GPG_ERR_NO_PKCS15_APP = 113
def va_copy(d,s): return __builtin_va_copy(d,s) # macro
GPG_ERR_INV_RESPONSE = 76
GPG_ERR_CANCELED = 99
GCRYCTL_DUMP_MEMORY_STATS = 23
GPG_ERR_EILSEQ = 32813
PF_WANPIPE = 25 # Variable c_int
AF_WANPIPE = PF_WANPIPE # alias
GPG_ERR_BAD_CERT = 36
def __GNUC_PREREQ(maj,min): return ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min)) # macro
GPG_ERR_WRONG_BLOB_TYPE = 127
SOCK_DGRAM = 2
# BC_SCALE_MAX = _POSIX2_BC_SCALE_MAX # alias
GCRY_LOG_WARN = 20
OFFER_REJECTED = 2
GPG_ERR_INV_CRL_OBJ = 162
OTRL_MSGTYPE_V1_KEYEXCH = 7
GPG_ERR_EROFS = 32890
SCM_CREDENTIALS = 2
SCM_CREDENTIALS = SCM_CREDENTIALS # alias
GPG_ERR_ENOSPC = 32859
GPG_ERR_ENETDOWN = 32840
OTRL_AUTHSTATE_AWAITING_REVEALSIG = 2
GCRY_AC_DSA = 17
GPG_ERR_USER_13 = 1036
GPG_ERR_UNUSABLE_SECKEY = 54
GPG_ERR_ERANGE = 32885
GPG_ERR_BAD_PIN_METHOD = 122
OFFER_SENT = 1
# def __u_intN_t(N,MODE): return typedef unsigned int u_int ##N ##_t __attribute__ ((__mode__ (MODE))) # macro
GPG_ERR_PIN_ENTRY = 86
GPG_ERR_SIG_EXPIRED = 154
GPG_ERR_ELEMENT_NOT_FOUND = 136
GPG_ERR_UNSUPPORTED_CERT = 103
GPG_ERR_EEXIST = 32803
GPG_ERR_INV_REQUEST = 170
# NULL = __null # alias
# __SUSECONDS_T_TYPE = __SLONGWORD_TYPE # alias
def mpi_set_bit(a,b): return gcry_mpi_set_bit ((a),(b)) # macro
GCRYCTL_IS_ALGO_ENABLED = 35
GPG_ERR_EXDEV = 32907
GCRY_CIPHER_ENABLE_SYNC = 2
OTRL_AUTHSTATE_AWAITING_DHKEY = 1
GPG_ERR_EBACKGROUND = 32777
# def __ASMNAME2(prefix,cname): return __STRING (prefix) cname # macro
GCRYCTL_START_DUMP = 32
MSG_DONTROUTE = 4
GCRY_CIPHER_BLOWFISH = 4
GPG_ERR_USER_7 = 1030
PF_IRDA = 23 # Variable c_int
AF_IRDA = PF_IRDA # alias
GPG_ERR_SOURCE_USER_4 = 35
PF_ASH = 18 # Variable c_int
AF_ASH = PF_ASH # alias
# __FSBLKCNT_T_TYPE = __ULONGWORD_TYPE # alias
ITIMER_PROF = ITIMER_PROF # alias
PF_NETLINK = 16 # Variable c_int
PF_ROUTE = PF_NETLINK # alias
AF_ROUTE = PF_ROUTE # alias
GPG_ERR_ETIMEDOUT = 32900
# __OFF_T_TYPE = __SLONGWORD_TYPE # alias
GPG_ERR_EBADMSG = 32781
GCRY_CIPHER_TWOFISH = 10
OTRL_NOTIFY_ERROR = 0
GCRYCTL_CLEAR_DEBUG_FLAGS = 21
def mpi_get_nbits(a): return gcry_mpi_get_nbits ((a)) # macro
def __ASMNAME(cname): return __ASMNAME2 (__USER_LABEL_PREFIX__, cname) # macro
GPG_ERR_SIG_CLASS = 32
OTRL_NOTIFY_INFO = 2
GPG_ERR_SOURCE_USER_2 = 33
GPG_ERR_ENOSR = 32860
GCRY_CIPHER_MODE_CBC = 3
PF_IPX = 4 # Variable c_int
AF_IPX = PF_IPX # alias
GPG_ERR_EL2NSYNC = 32822
GPG_ERR_EFBIG = 32805
GCRYCTL_GET_ALGO_NPKEY = 15
GPG_ERR_TOO_SHORT = 66
GCRY_LOG_BUG = 50
GPG_ERR_ECHRNG = 32790
GCRY_MD_FLAG_HMAC = 2
OTRL_MSGTYPE_REVEALSIG = 5
GPG_ERR_ESHUTDOWN = 32892
GPG_ERR_ENETUNREACH = 32842
GPG_ERR_SOURCE_GPG = 2
GPG_ERR_BAD_BER = 134
GCRYCTL_INITIALIZATION_FINISHED = 38
GCRYCTL_GET_KEYLEN = 6
GPG_ERR_EMEDIUMTYPE = 32832
__quad_t = c_longlong
__SQUAD_TYPE = __quad_t # alias
__OFF64_T_TYPE = __SQUAD_TYPE # alias
# __BLKSIZE_T_TYPE = __SLONGWORD_TYPE # alias
GPG_ERR_USER_9 = 1032
GPG_ERR_COMPR_ALGO = 20
def makedev(maj,min): return gnu_dev_makedev (maj, min) # macro
def mpi_mulm(w,u,v,m): return gcry_mpi_mulm ((w),(u),(v),(m)) # macro
GPG_ERR_SOURCE_PINENTRY = 5
def minor(dev): return gnu_dev_minor (dev) # macro
def mpi_mul_ui(w,u,v): return gcry_mpi_mul_ui ((w),(u),(v)) # macro
GCRY_CIPHER_SECURE = 1
GPG_ERR_SEXP_NESTED_DH = 208
GCRY_THREAD_OPTION_PTHREAD = 3
GPG_ERR_ENOMEM = 32854
GPG_ERR_CODE_DIM = 65536
GCRY_CIPHER_CBC_CTS = 4
# def write_int(x): return do { bufp[0] = ((x) >> 24) & 0xff; bufp[1] = ((x) >> 16) & 0xff; bufp[2] = ((x) >> 8) & 0xff; bufp[3] = (x) & 0xff; bufp += 4; lenp -= 4; } while(0) # macro
GPG_ERR_NO_SIGNATURE_SCHEME = 24
GCRYMPI_FMT_PGP = 2
GPG_ERR_UNKNOWN_ERRNO = 16382
GPG_ERR_CRL_TOO_OLD = 96
__u_quad_t = c_ulonglong
__UQUAD_TYPE = __u_quad_t # alias
__DEV_T_TYPE = __UQUAD_TYPE # alias
_POSIX_THREAD_DESTRUCTOR_ITERATIONS = 4 # Variable c_int
PTHREAD_DESTRUCTOR_ITERATIONS = _POSIX_THREAD_DESTRUCTOR_ITERATIONS # alias
GPG_ERR_SOURCE_GPGSM = 3
# def __REDIRECT(name,proto,alias): return name proto __asm__ (__ASMNAME (#alias)) # macro
GPG_ERR_USER_14 = 1037
GCRYCTL_INIT_SECMEM = 24
GCRY_CIPHER_SAFER_SK128 = 5
GPG_ERR_UNSUPPORTED_OPERATION = 124
GPG_ERR_UNKNOWN_HOST = 49
GPG_ERR_EUCLEAN = 32903
GPG_ERR_ED = 32795
GCRY_PK_DSA = 17
GPG_ERR_INV_CERT_OBJ = 164
OTRL_SESSIONID_SECOND_HALF_BOLD = 1
GPG_ERR_NOT_ENCRYPTED = 51
GPG_ERR_SOURCE_GPGAGENT = 4
GCRYCTL_GET_ALGO_NSKEY = 16
def mpi_cmp(u,v): return gcry_mpi_cmp( (u), (v) ) # macro
__RLIM64_T_TYPE = __UQUAD_TYPE # alias
def __CONCAT(x,y): return x ## y # macro
OTRL_POLICY_OPPORTUNISTIC = 27 # Variable c_int
OTRL_POLICY_DEFAULT = OTRL_POLICY_OPPORTUNISTIC # alias
GCRY_CIPHER_AES = 7
GCRY_CIPHER_RIJNDAEL = GCRY_CIPHER_AES # alias
GPG_ERR_BAD_PUBKEY = 6
GCRYMPI_FLAG_OPAQUE = 2
GCRY_CIPHER_AES192 = 8
GCRY_CIPHER_RIJNDAEL192 = GCRY_CIPHER_AES192 # alias
OTRL_MSGTYPE_DH_COMMIT = 3
# __USECONDS_T_TYPE = __U32_TYPE # alias
# def timeradd(a,b,result): return do { (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; if ((result)->tv_usec >= 1000000) { ++(result)->tv_sec; (result)->tv_usec -= 1000000; } } while (0) # macro
# AF_AX25 = PF_AX25 # alias
GPG_ERR_EALREADY = 32775
GPG_ERR_ELIBACC = 32825
# __UID_T_TYPE = __U32_TYPE # alias
GPG_ERR_SOURCE_USER_3 = 34
# LONG_LONG_MAX = __LONG_LONG_MAX__ # alias
GPG_ERR_SEXP_UNMATCHED_DH = 209
def mpi_sub(w,u,v): return gcry_mpi_sub ((w),(u),(v)) # macro
GPG_ERR_UNEXPECTED_TAG = 141
GCRYCTL_DISABLE_INTERNAL_LOCKING = 36
ITIMER_VIRTUAL = 1
ITIMER_VIRTUAL = ITIMER_VIRTUAL # alias
MSG_WAITALL = 256
GPG_ERR_INV_VALUE = 55
# def __FD_SET(fd,fdsp): return __asm__ __volatile__ ("btsl %1,%0" : "=m" (__FDS_BITS (fdsp)[__FDELT (fd)]) : "r" (((int) (fd)) % __NFDBITS) : "cc","memory") # macro
GPG_ERR_EPROCUNAVAIL = 32879
GPG_ERR_ELIBMAX = 32828
def mpi_addm(w,u,v,m): return gcry_mpi_addm ((w),(u),(v),(m)) # macro
def mpi_mod(r,a,m): return gcry_mpi_mod ((r), (a), (m)) # macro
# def __FD_CLR(fd,fdsp): return __asm__ __volatile__ ("btrl %1,%0" : "=m" (__FDS_BITS (fdsp)[__FDELT (fd)]) : "r" (((int) (fd)) % __NFDBITS) : "cc","memory") # macro
SHUT_RD = 0
GCRYCTL_TERM_SECMEM = 25
def __attribute_format_arg__(x): return __attribute__ ((__format_arg__ (x))) # macro
GPG_ERR_ENOTUNIQ = 32871
MSG_PROXY = 16
MSG_PROXY = MSG_PROXY # alias
GPG_ERR_INV_INDEX = 117
GPG_ERR_SOURCE_GSTI = 11
GPG_ERR_UNKNOWN_NAME = 165
MSG_SYN = 1024
MSG_SYN = MSG_SYN # alias
GCRY_MD_TIGER = 6
GCRY_AC_KEY_PUBLIC = 1
GPG_ERR_KEYRING_OPEN = 13
GPG_ERR_ECONNRESET = 32794
def gcry_md_get_asnoid(a,b,n): return gcry_md_algo_info((a), GCRYCTL_GET_ASNOID, (b), (n)) # macro
GPG_ERR_SELFTEST_FAILED = 50
GPG_ERR_UNUSABLE_PUBKEY = 53
GCRYCTL_ENABLE_ALGO = 11
GPG_ERR_ESTRPIPE = 32898
GPG_ERR_ESRMNT = 32896
GPG_ERR_NO_SECKEY = 17
GPG_ERR_WRONG_CARD = 91
GPG_ERR_SEXP_UNEXPECTED_PUNC = 210
def mpi_cmp_ui(u,v): return gcry_mpi_cmp_ui( (u), (v) ) # macro
GPG_ERR_EAGAIN = 32774
MSG_PEEK = 2
MSG_PEEK = MSG_PEEK # alias
GPG_ERR_UNSUPPORTED_CMS_OBJ = 146
GPG_ERR_AMBIGUOUS_NAME = 107
GCRY_THREAD_OPTION_USER = 1
def mpi_sub_ui(w,u,v): return gcry_mpi_sub_ui ((w),(u),(v)) # macro
GPG_ERR_TOO_LARGE = 67
GPG_ERR_DIRMNGR = 93
GPG_ERR_EBADRPC = 32783
GCRY_CIPHER_AES256 = 9
GPG_ERR_CHECKSUM = 10
GPG_ERR_ENOMSG = 32855
GCRYCTL_DISABLE_SECMEM = 37
GCRY_CIPHER_MODE_NONE = 0
# def __FDMASK(d): return ((__fd_mask) 1 << ((d) % __NFDBITS)) # macro
def mpi_powm(w,b,e,m): return gcry_mpi_powm ( (w), (b), (e), (m) ) # macro
GPG_ERR_ENOCSI = 32846
GCRYCTL_DISABLE_SECMEM_WARN = 27
def mpi_mul(w,u,v): return gcry_mpi_mul ((w),(u),(v)) # macro
GPG_ERR_EBADF = 32779
def va_end(v): return __builtin_va_end(v) # macro
GPG_ERR_ENOMEDIUM = 32853
GCRY_MD_HAVAL = 7
GPG_ERR_EOPNOTSUPP = 32873
MSG_OOB = 1
MSG_OOB = MSG_OOB # alias
GPG_ERR_USER_2 = 1025
GPG_ERR_ENOLCK = 32851
_POSIX2_LINE_MAX = 2048 # Variable c_int
NL_LANGMAX = _POSIX2_LINE_MAX # alias
GPG_ERR_ELNRNG = 32830
# BC_STRING_MAX = _POSIX2_BC_STRING_MAX # alias
GPG_ERR_ESRCH = 32895
GCRY_CIPHER_RFC2268_128 = 308
# def strdupa(s): return (__extension__ ({ __const char *__old = (s); size_t __len = strlen (__old) + 1; char *__new = (char *) __builtin_alloca (__len); (char *) memcpy (__new, __old, __len); })) # macro
def mpi_add(w,u,v): return gcry_mpi_add ((w),(u),(v)) # macro
GPG_ERR_EMFILE = 32833
GPG_ERR_BAD_DATA = 89
GCRY_CIPHER_AES128 = GCRY_CIPHER_AES # alias
GCRY_CIPHER_RIJNDAEL128 = GCRY_CIPHER_AES128 # alias
OTRL_AUTHSTATE_V1_SETUP = 4
# def __intN_t(N,MODE): return typedef int int ##N ##_t __attribute__ ((__mode__ (MODE))) # macro
GPG_ERR_EBADE = 32778
__uint32_t = c_uint
__ss_aligntype = __uint32_t # alias
SHUT_RDWR = 2
SHUT_RDWR = SHUT_RDWR # alias
ITIMER_REAL = 0
GCRY_CIPHER_IDEA = 1
SOCK_PACKET = 10
GPG_ERR_ESPIPE = 32894
GCRYCTL_SET_IV = 2
__INO64_T_TYPE = __UQUAD_TYPE # alias
def FD_ZERO(fdsetp): return __FD_ZERO (fdsetp) # macro
GPG_ERR_SEXP_ZERO_PREFIX = 207
GCRY_CIPHER_SERPENT192 = 305
GCRYCTL_INITIALIZATION_FINISHED_P = 39
PF_UNSPEC = 0 # Variable c_int
AF_UNSPEC = PF_UNSPEC # alias
def __bos0(ptr): return __builtin_object_size (ptr, 0) # macro
GPG_ERR_UNKNOWN_ALGORITHM = 149
GPG_ERR_EDEADLK = 32796
GPG_ERR_SOURCE_UNKNOWN = 0
GPG_ERR_SOURCE_KSBA = 9
GPG_ERR_USER_6 = 1029
GPG_ERR_NO_ENCRYPTION_SCHEME = 23
GCRY_CIPHER_CBC_MAC = 8
# INT_MAX = __INT_MAX__ # alias
# NL_SETMAX = INT_MAX # alias
GCRY_STRONG_RANDOM = 1
# __S32_TYPE = int # alias
# __DADDR_T_TYPE = __S32_TYPE # alias
AF_NETLINK = PF_NETLINK # alias
GPG_ERR_ENONET = 32856
GCRYCTL_FINALIZE = 5
PF_INET = 2 # Variable c_int
AF_INET = PF_INET # alias
GPG_ERR_EUNATCH = 32904
GPG_ERR_NOT_CONFIRMED = 114
GPG_ERR_BAD_CA_CERT = 100
def va_start(v,l): return __builtin_va_start(v,l) # macro
GPG_ERR_EPERM = 32875
MSG_ERRQUEUE = 8192
GPG_ERR_EPROTONOSUPPORT = 32883
MSG_EOR = 128
MSG_EOR = MSG_EOR # alias
PF_LOCAL = 1 # Variable c_int
PF_FILE = PF_LOCAL # alias
AF_FILE = PF_FILE # alias
GPG_ERR_MISSING_VALUE = 128
GPG_ERR_SCDAEMON = 120
# LONG_MAX = __LONG_MAX__ # alias
# SSIZE_MAX = LONG_MAX # alias
GPG_ERR_SEXP_BAD_HEX_CHAR = 211
GPG_ERR_EACCES = 32769
GPG_ERR_TRUSTDB = 35
SCM_RIGHTS = 1
SCM_RIGHTS = SCM_RIGHTS # alias
GCRYCTL_DISABLE_ALGO = 12
GCRYMPI_FMT_SSH = 3
GCRY_MD_FLAG_SECURE = 1
GPG_ERR_BUFFER_TOO_SHORT = 200
def gcry_cipher_sync(h): return gcry_cipher_ctl( (h), GCRYCTL_CFB_SYNC, NULL, 0 ) # macro
SOCK_STREAM = 1
__socklen_t = c_uint
socklen_t = __socklen_t
_GCRY_PTH_SOCKLEN_T = socklen_t # alias
GPG_ERR_SOURCE_DEFAULT = GPG_ERR_SOURCE_UNKNOWN # alias
GPG_ERR_ENOANO = 32844
GPG_ERR_BAD_URI = 46
# def read_int(x): return do { require_len(4); (x) = (bufp[0] << 24) | (bufp[1] << 16) | (bufp[2] << 8) | bufp[3]; bufp += 4; lenp -= 4; } while(0) # macro
GCRY_CIPHER_DES_SK = 6
GPG_ERR_ENOTTY = 32870
__LITTLE_ENDIAN = 1234 # Variable c_int
LITTLE_ENDIAN = __LITTLE_ENDIAN # alias
GPG_ERR_ENFILE = 32843
# def read_mpi(x): return do { size_t mpilen; read_int(mpilen); if (mpilen) { require_len(mpilen); gcry_mpi_scan(&(x), GCRYMPI_FMT_USG, bufp, mpilen, NULL); } else { (x) = gcry_mpi_set_ui(NULL, 0); } bufp += mpilen; lenp -= mpilen; } while(0) # macro
def FD_SET(fd,fdsetp): return __FD_SET (fd, fdsetp) # macro
PF_ROSE = 11 # Variable c_int
AF_ROSE = PF_ROSE # alias
# __TIMER_T_TYPE = __S32_TYPE # alias
GPG_ERR_UNKNOWN_SEXP = 104
GCRY_LOG_DEBUG = 100
def gcry_cipher_reset(h): return gcry_cipher_ctl ((h), GCRYCTL_RESET, NULL, 0) # macro
GPG_ERR_INV_PARAMETER = 90
GPG_ERR_USER_8 = 1031
GPG_ERR_ENODATA = 32847
OTRL_NOTIFY_WARNING = 1
# def __SOCKADDR_COMMON(sa_prefix): return sa_family_t sa_prefix ##family # macro
GPG_ERR_EBADSLT = 32785
PF_SECURITY = 14 # Variable c_int
AF_SECURITY = PF_SECURITY # alias
MSG_CTRUNC = 8
GPG_ERR_SOURCE_GPGME = 7
GPG_ERR_EBADRQC = 32784
GPG_ERR_UNSUPPORTED_ALGORITHM = 84
def mpi_rshift(a,b,c): return gcry_mpi_rshift ((a),(b),(c)) # macro
GCRY_LOG_CONT = 0
MSG_CONFIRM = 2048
GCRY_AC_KEY_SECRET = 0
def va_arg(v,l): return __builtin_va_arg(v,l) # macro
GPG_ERR_EPIPE = 32877
def mpi_fdiv(q,r,a,m): return gcry_mpi_div ( (q), (r), (a), (m), -1) # macro
MSG_MORE = 32768
_POSIX_ARG_MAX = 4096 # Variable c_int
NL_ARGMAX = _POSIX_ARG_MAX # alias
__BIG_ENDIAN = 4321 # Variable c_int
BIG_ENDIAN = __BIG_ENDIAN # alias
GPG_ERR_UNSUPPORTED_PROTOCOL = 121
GPG_ERR_EISNAM = 32820
GPG_ERR_INV_ARG = 45
GPG_ERR_INV_ARMOR = 15
GPG_ERR_EINVAL = 32816
GCRYCTL_DUMP_RANDOM_STATS = 13
def gcry_fast_random_poll(): return gcry_control (GCRYCTL_FAST_POLL, NULL) # macro
def mpi_set_opaque(a,b,c): return gcry_mpi_set_opaque( (a), (b), (c) ) # macro
GPG_ERR_ENOBUFS = 32845
PF_DECnet = 12 # Variable c_int
AF_DECnet = PF_DECnet # alias
# def CMSG_FIRSTHDR(mhdr): return ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr) ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) NULL) # macro
# def timerisset(tvp): return ((tvp)->tv_sec || (tvp)->tv_usec) # macro
GPG_ERR_EADV = 32772
# def gcry_cipher_setiv(h,k,l): return gcry_cipher_ctl( (h), GCRYCTL_SET_IV, (char*)(k), (l) ) # macro
GPG_ERR_ASSUAN = 81
GCRY_CIPHER_3DES = 2
GPG_ERR_INV_BER = 135
GPG_ERR_INV_SESSION_KEY = 82
GCRYCTL_CFB_SYNC = 3
GPG_ERR_INV_FLAG = 72
def gcry_md_stop_debug(a,b): return gcry_md_ctl( (a), GCRYCTL_STOP_DUMP, (b), 0 ) # macro
GPG_ERR_NO_DATA = 58
GPG_ERR_BAD_SECKEY = 7
GPG_ERR_ENCODING_PROBLEM = 155
GPG_ERR_KEYSERVER = 40
GPG_ERR_ETXTBSY = 32902
GPG_ERR_EREMCHG = 32886
GPG_ERR_EIO = 32817
def __PMT(args): return args # macro
# __CLOCK_T_TYPE = __SLONGWORD_TYPE # alias
PF_NETROM = 6 # Variable c_int
AF_NETROM = PF_NETROM # alias
GPG_ERR_EMLINK = 32834
GPG_ERR_INV_CARD = 111
# NL_MSGMAX = INT_MAX # alias
GPG_ERR_SEXP_ODD_HEX_NUMBERS = 212
MSG_TRUNC = 32
GPG_ERR_LINE_TOO_LONG = 97
__BYTE_ORDER = __LITTLE_ENDIAN # alias
__FLOAT_WORD_ORDER = __BYTE_ORDER # alias
PF_X25 = 9 # Variable c_int
AF_X25 = PF_X25 # alias
def mpi_copy(a): return gcry_mpi_copy( (a) ) # macro
# def write_mpi(x,nx,dx): return do { write_int(nx); gcry_mpi_print(format, bufp, lenp, NULL, (x)); debug_data((dx), bufp, (nx)); bufp += (nx); lenp -= (nx); } while(0) # macro
GCRYCTL_USE_SECURE_RNDPOOL = 22
GCRY_CIPHER_TWOFISH128 = 303
GPG_ERR_UNSUPPORTED_CRL_VERSION = 163
GCRY_MD_SHA1 = 2
GPG_ERR_EREMOTE = 32887
# SCHAR_MAX = __SCHAR_MAX__ # alias
GPG_ERR_BAD_PASSPHRASE = 11
GPG_ERR_INV_DATA = 79
# AF_ATMSVC = PF_ATMSVC # alias
GPG_ERR_USER_12 = 1035
def __bos(ptr): return __builtin_object_size (ptr, __USE_FORTIFY_LEVEL > 1) # macro
GCRY_CIPHER_RIJNDAEL256 = GCRY_CIPHER_AES256 # alias
GCRY_AC_ELG = 20
OTRL_SESSIONID_FIRST_HALF_BOLD = 0
MSG_NOSIGNAL = 16384
MSG_NOSIGNAL = MSG_NOSIGNAL # alias
# GPG_ERR_INLINE = __inline__ # alias
PF_KEY = 15 # Variable c_int
AF_KEY = PF_KEY # alias
GPG_ERR_NOTHING_FOUND = 126
GPG_ERR_INV_SEXP = 83
GCRYCTL_SET_CBC_CTS = 41
GPG_ERR_BAD_PIN = 87
GCRYCTL_ENABLE_M_GUARD = 31
GPG_ERR_NO_SCDAEMON = 119
GPG_ERR_ELOOP = 32831
GPG_ERR_NOT_DER_ENCODED = 142
GCRYCTL_GET_ALGO_USAGE = 34
GCRY_MD_MD5 = 1
GPG_ERR_NO_AGENT = 77
def __P(args): return args # macro
PF_NETBEUI = 13 # Variable c_int
AF_NETBEUI = PF_NETBEUI # alias
GPG_ERR_NOT_LOCKED = 167
GPG_ERR_INCOMPLETE_LINE = 75
GPG_ERR_UNKNOWN_PACKET = 2
GCRY_VERY_STRONG_RANDOM = 2
GCRY_MD_SHA256 = 8
GPG_ERR_CIPHER_ALGO = 12
def mpi_invm(g,a,b): return gcry_mpi_invm ( (g), (a), (b) ) # macro
GPG_ERR_EPROGUNAVAIL = 32881
GPG_ERR_SOURCE_GCRYPT = 1
GPG_ERR_INV_PACKET = 14
def mpi_gcd(g,a,b): return gcry_mpi_gcd ( (g), (a), (b) ) # macro
GPG_ERR_NO_VALUE = 26
# def timersub(a,b,result): return do { (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; if ((result)->tv_usec < 0) { --(result)->tv_sec; (result)->tv_usec += 1000000; } } while (0) # macro
GPG_ERR_PROTOCOL_VIOLATION = 168
GCRY_MD_NONE = 0
GPG_ERR_ERESTART = 32889
GPG_ERR_EISDIR = 32819
GPG_ERR_USER_10 = 1033
# def CMSG_DATA(cmsg): return ((cmsg)->__cmsg_data) # macro
SCHAR_MIN = -128 # Variable c_int
CHAR_MIN = SCHAR_MIN # alias
GPG_ERR_EADDRINUSE = 32770
AF_LOCAL = PF_LOCAL # alias
OTRL_AUTHSTATE_AWAITING_SIG = 3
GPG_ERR_EBFONT = 32786
PF_BLUETOOTH = 31 # Variable c_int
AF_BLUETOOTH = PF_BLUETOOTH # alias
GPG_ERR_PIN_NOT_SYNCED = 132
GCRYCTL_UPDATE_RANDOM_SEED_FILE = 46
def major(dev): return gnu_dev_major (dev) # macro
# def timerclear(tvp): return ((tvp)->tv_sec = (tvp)->tv_usec = 0) # macro
GPG_ERR_ECOMM = 32791
GCRY_CIPHER_MODE_STREAM = 4
GCRYSEXP_FMT_ADVANCED = 3
def __va_copy(d,s): return __builtin_va_copy(d,s) # macro
GPG_ERR_NO_PIN_ENTRY = 85
GPG_ERR_ENOTSUP = 32869
GCRYMPI_FMT_STD = 1
GPG_ERR_UNSUPPORTED_ENCODING = 147
GPG_ERR_EWOULDBLOCK = 32906
GPG_ERR_ENOTNAM = 32867
GPG_ERR_TRUNCATED = 74
GCRYCTL_ENABLE_QUICK_RANDOM = 44
def mpi_subm(w,u,v,m): return gcry_mpi_subm ((w),(u),(v),(m)) # macro
GPG_ERR_CARD = 108
def mpi_set_ui(w,u): return gcry_mpi_set_ui( (w), (u) ) # macro
GCRYCTL_IS_SECURE = 9
GCRYSEXP_FMT_CANON = 1
# def __FDS_BITS(set): return ((set)->fds_bits) # macro
# def __NTH(fct): return fct throw () # macro
GPG_ERR_SEXP_BAD_OCT_CHAR = 213
GPG_ERR_INV_HANDLE = 73
MSG_WAITALL = MSG_WAITALL # alias
GPG_ERR_EDQUOT = 32802
GPG_ERR_USER_16 = 1039
MSG_FIN = 512
def mpi_get_opaque(a,b): return gcry_mpi_get_opaque( (a), (b) ) # macro
GCRYCTL_SET_KEY = 1
GPG_ERR_EDOTDOT = 32801
GCRY_CIPHER_RFC2268_40 = 307
OFFER_ACCEPTED = 3
GPG_ERR_INV_MAC = 169
GCRY_PK_ELG = 20
GCRY_CIPHER_SERPENT256 = 306
GPG_ERR_INV_ENGINE = 150
GCRY_MD_MD2 = 5
# __INO_T_TYPE = __ULONGWORD_TYPE # alias
GCRY_CIPHER_MODE_CTR = 6
GPG_ERR_WRONG_PUBKEY_ALGO = 41
GCRY_AC_RSA = 1
GPG_ERR_ERPCMISMATCH = 32891
MSG_ERRQUEUE = MSG_ERRQUEUE # alias
# __SWORD_TYPE = int # alias
# def timercmp(a,b,CMP): return (((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec CMP (b)->tv_usec) : ((a)->tv_sec CMP (b)->tv_sec)) # macro
GPG_ERR_GENERAL = 1
MSG_FIN = MSG_FIN # alias
def gcry_pk_test_algo(a): return gcry_pk_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL ) # macro
GCRY_MD_SHA512 = 10
GCRYCTL_SET_CBC_MAC = 42
GPG_ERR_EHOSTUNREACH = 32810
# def __nonnull(params): return __attribute__ ((__nonnull__ params)) # macro
GPG_ERR_INV_LENGTH = 139
GPG_ERR_DECRYPT_FAILED = 152
# __TIME_T_TYPE = __SLONGWORD_TYPE # alias
GPG_ERR_ENOTSOCK = 32868
GPG_ERR_BAD_KEY = 19
# NL_TEXTMAX = INT_MAX # alias
GPG_ERR_INV_ID = 118
def mpi_test_bit(a,b): return gcry_mpi_test_bit ((a),(b)) # macro
GPG_ERR_EXFULL = 32908
GCRY_CIPHER_NONE = 0
GPG_ERR_EL3RST = 32824
GPG_ERR_EFTYPE = 32806
GCRYCTL_GET_BLKLEN = 7
GCRY_WEAK_RANDOM = 0
GPG_ERR_USER_1 = 1024
GPG_ERR_NO_PUBKEY = 9
GPG_ERR_EDEADLOCK = 32797
def __GLIBC_PREREQ(maj,min): return ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min)) # macro
def __FDELT(d): return ((d) / __NFDBITS) # macro
GPG_ERR_NOT_PROCESSED = 52
GPG_ERR_NOT_IMPLEMENTED = 69
GPG_ERR_ECANCELED = 32788
GCRY_CIPHER_MODE_ECB = 1
GPG_ERR_CONFIGURATION = 115
MSG_CONFIRM = MSG_CONFIRM # alias
GCRYCTL_SET_DEBUG_FLAGS = 20
GPG_ERR_E2BIG = 32768
GCRYMPI_FMT_USG = 5
GPG_ERR_INV_TAG = 138
__NFDBITS = 32 # Variable c_uint
NFDBITS = __NFDBITS # alias
GPG_ERR_INV_ATTR = 25
GCRY_PK_RSA_S = 3
GPG_ERR_HARDWARE = 129
OTRL_MSGTYPE_DATA = 8
GCRYCTL_SET_RANDOM_SEED_FILE = 45
__FD_SETSIZE = 1024 # Variable c_int
FD_SETSIZE = __FD_SETSIZE # alias
PF_BRIDGE = 7 # Variable c_int
AF_BRIDGE = PF_BRIDGE # alias
GPG_ERR_ESOCKTNOSUPPORT = 32893
SOCK_PACKET = SOCK_PACKET # alias
PF_ATMPVC = 8 # Variable c_int
AF_ATMPVC = PF_ATMPVC # alias
GPG_ERR_WRONG_SECKEY = 18
GPG_ERR_USER_11 = 1034
GCRYCTL_SET_CTR = 43
SOCK_STREAM = SOCK_STREAM # alias
GCRYCTL_RESET = 4
GPG_ERR_RESOURCE_LIMIT = 33
MSG_DONTROUTE = MSG_DONTROUTE # alias
GPG_ERR_EDOM = 32800
def mpi_tdiv(q,r,a,m): return gcry_mpi_div ( (q), (r), (a), (m), 0) # macro
GPG_ERR_UNSUPPORTED_PROTECTION = 105
GPG_ERR_INV_CMS_OBJ = 144
GCRY_MD_CRC24_RFC2440 = 304
GPG_ERR_EINPROGRESS = 32814
GCRYCTL_STOP_DUMP = 33
GPG_ERR_EOF = 16383
GPG_ERR_DUP_VALUE = 157
GPG_ERR_INV_KEYLEN = 44
PF_PACKET = 17 # Variable c_int
AF_PACKET = PF_PACKET # alias
GCRY_MD_CRC32 = 302
GCRYCTL_DUMP_SECMEM_STATS = 14
GPG_ERR_BUG = 59
GPG_ERR_ENOSTR = 32861
# __SSIZE_T_TYPE = __SWORD_TYPE # alias
GPG_ERR_WEAK_KEY = 43
GPG_ERR_EGRATUITOUS = 32807
GPG_ERR_EL2HLT = 32821
# def CMSG_SPACE(len): return (CMSG_ALIGN (len) + CMSG_ALIGN (sizeof (struct cmsghdr))) # macro
GPG_ERR_INV_PASSPHRASE = 31
PF_UNIX = PF_LOCAL # alias
AF_UNIX = PF_UNIX # alias
def mpi_clear_highbit(a,b): return gcry_mpi_clear_highbit ((a),(b)) # macro
GPG_ERR_CERT_REVOKED = 94
GCRY_PK_ELG_E = 16
PF_INET6 = 10 # Variable c_int
AF_INET6 = PF_INET6 # alias
SOCK_RAW = 3
GCRY_CIPHER_MODE_OFB = 5
_POSIX_UIO_MAXIOV = 16 # Variable c_int
_XOPEN_IOV_MAX = _POSIX_UIO_MAXIOV # alias
GPG_ERR_ENOEXEC = 32850
GCRYMPI_FLAG_SECURE = 1
GPG_ERR_BAD_CERT_CHAIN = 56
# def CMSG_ALIGN(len): return (((len) + sizeof (size_t) - 1) & (size_t) ~(sizeof (size_t) - 1)) # macro
# __SWBLK_T_TYPE = __SLONGWORD_TYPE # alias
class fd_set(Structure):
    pass
__fd_mask = c_long
fd_set._fields_ = [
    ('fds_bits', __fd_mask * 32),
]
_GCRY_PTH_FD_SET = fd_set # alias
GPG_ERR_INV_OBJ = 65
# __NLINK_T_TYPE = __UWORD_TYPE # alias
GPG_ERR_ENOLINK = 32852
GPG_ERR_INV_USER_ID = 37
LINE_MAX = _POSIX2_LINE_MAX # alias
GPG_ERR_KEY_EXPIRED = 153
_POSIX_OPEN_MAX = 20 # Variable c_int
_POSIX_FD_SETSIZE = _POSIX_OPEN_MAX # alias
PF_APPLETALK = 5 # Variable c_int
AF_APPLETALK = PF_APPLETALK # alias
GPG_ERR_USER_3 = 1026
GPG_ERR_NOT_FOUND = 27
MSG_TRYHARD = 4
GCRYCTL_SET_VERBOSITY = 19
GPG_ERR_CARD_NOT_PRESENT = 112
GPG_ERR_USER_15 = 1038
GPG_ERR_NOT_TRUSTED = 98
GCRY_MD_SHA384 = 9
# __GID_T_TYPE = __U32_TYPE # alias
GPG_ERR_ENAMETOOLONG = 32837
GPG_ERR_ENXIO = 32872
GPG_ERR_SEXP_INV_LEN_SPEC = 201
GCRYMPI_FMT_HEX = 4
GCRYCTL_TEST_ALGO = 8
GPG_ERR_CARD_REMOVED = 110
def mpi_set_highbit(a,b): return gcry_mpi_set_highbit ((a),(b)) # macro
GPG_ERR_EBADFD = 32780
GCRYMPI_FMT_NONE = 0
GPG_ERR_ESTALE = 32897
_POSIX2_BC_DIM_MAX = 2048 # Variable c_int
BC_DIM_MAX = _POSIX2_BC_DIM_MAX # alias
# __ID_T_TYPE = __U32_TYPE # alias
GPG_ERR_SOURCE_DIM = 256
GPG_ERR_INV_KEYRING = 34
OTRL_MSGTYPE_UNKNOWN = 10
SOCK_SEQPACKET = 5
def mpi_add_ui(w,u,v): return gcry_mpi_add_ui((w),(u),(v)) # macro
# EXPR_NEST_MAX = _POSIX2_EXPR_NEST_MAX # alias
GPG_ERR_EINTR = 32815
GPG_ERR_MISSING_CERT = 57
OTRL_MSGTYPE_DH_KEY = 4
GCRY_CIPHER_ARCFOUR = 301
GPG_ERR_INV_CIPHER_MODE = 71
OTRL_AUTHSTATE_NONE = 0
__U64_TYPE = __u_quad_t # alias
_GCRY_ERR_SOURCE_DEFAULT = GPG_ERR_SOURCE_GCRYPT # alias
GPG_ERR_INV_STATE = 156
GPG_ERR_CERT_TOO_YOUNG = 102
# def TIMESPEC_TO_TIMEVAL(tv,ts): return { (tv)->tv_sec = (ts)->tv_sec; (tv)->tv_usec = (ts)->tv_nsec / 1000; } # macro
GPG_ERR_ENETRESET = 32841
GPG_ERR_INV_NAME = 88
GCRY_LOG_INFO = 10
GCRYCTL_FAST_POLL = 48
GPG_ERR_SOURCE_DIRMNGR = 10
GPG_ERR_ENOTCONN = 32864
GPG_ERR_LOCALE_PROBLEM = 166
__S64_TYPE = __quad_t # alias
GPG_ERR_PUBKEY_ALGO = 4
GPG_ERR_USER_4 = 1027
SOCK_RAW = SOCK_RAW # alias
GPG_ERR_NO_CMS_OBJ = 143
GPG_ERR_ENOTDIR = 32865
GPG_ERR_INV_TIME = 161
GPG_ERR_NO_OBJ = 68
def mpi_new(n): return gcry_mpi_new( (n) ) # macro
GPG_ERR_ENOPKG = 32857
GCRY_THREAD_OPTION_DEFAULT = 0
GPG_ERR_USE_CONDITIONS = 131
OTRL_MSGSTATE_ENCRYPTED = 1
GPG_ERR_SEXP_STRING_TOO_LONG = 202
# def TIMEVAL_TO_TIMESPEC(tv,ts): return { (ts)->tv_sec = (tv)->tv_sec; (ts)->tv_nsec = (tv)->tv_usec * 1000; } # macro
def __LONG_LONG_PAIR(HI,LO): return LO, HI # macro
# def mpi_release(a): return do { gcry_mpi_release ((a)); (a) = NULL; } while (0) # macro
GCRY_MD_MD4 = 301
PF_PPPOX = 24 # Variable c_int
AF_PPPOX = PF_PPPOX # alias
GPG_ERR_EOVERFLOW = 32874
GPG_ERR_ENOENT = 32849
GPG_ERR_EPROTO = 32882
GPG_ERR_EFAULT = 32804
GCRY_CIPHER_DES = 302
GPG_ERR_ENAVAIL = 32838
GCRY_CIPHER_CAST5 = 3
GPG_ERR_ECHILD = 32789
GPG_ERR_EBADR = 32782
GCRY_MD_RMD160 = 3
MSG_RST = 4096
MSG_RST = MSG_RST # alias
# CHAR_MAX = SCHAR_MAX # alias
GPG_ERR_CERT_EXPIRED = 101
GPG_ERR_EGREGIOUS = 32808
SHUT_RD = SHUT_RD # alias
OTRL_MSGTYPE_SIGNATURE = 6
GPG_ERR_INV_URI = 47
GPG_ERR_SEXP_BAD_CHARACTER = 205
# __KEY_T_TYPE = __S32_TYPE # alias
GPG_ERR_SOURCE_USER_1 = 32
GCRY_ERR_SOURCE_DEFAULT = GPG_ERR_SOURCE_USER_1 # alias
GPG_ERR_ENEEDAUTH = 32839
def gcry_cipher_test_algo(a): return gcry_cipher_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL ) # macro
GPG_ERR_AGENT = 78
GPG_ERR_EBUSY = 32787
GPG_ERR_INV_CRL = 133
GCRY_LOG_ERROR = 30
SHUT_WR = 1
SHUT_WR = SHUT_WR # alias
ITIMER_REAL = ITIMER_REAL # alias
OTRL_MSGTYPE_ERROR = 9
GPG_ERR_MISSING_ACTION = 158
GPG_ERR_ETIME = 32899
GPG_ERR_EIDRM = 32811
# def require_len(l): return do { if (lenp < (l)) goto invval; } while(0) # macro
GPG_ERR_EMSGSIZE = 32835
# __RLIM_T_TYPE = __ULONGWORD_TYPE # alias
GPG_ERR_USER_5 = 1028
GPG_ERR_TRIBUTE_TO_D_A = 42
SO_TIMESTAMP = 29 # Variable c_int
SCM_TIMESTAMP = SO_TIMESTAMP # alias
GCRYCTL_SET_THREAD_CBS = 47
GPG_ERR_NO_ERROR = 0
GPG_ERR_ENOTEMPTY = 32866
GPG_ERR_CARD_RESET = 109
GPG_ERR_CONFLICT = 70
GPG_ERR_NO_CRL_KNOWN = 95
GCRYCTL_GET_ALGO_NSIGN = 17
GPG_ERR_SEXP_UNMATCHED_PAREN = 203
GPG_ERR_INV_OP = 61
def mpi_secure_new(n): return gcry_mpi_snew( (n) ) # macro
# __FSFILCNT_T_TYPE = __ULONGWORD_TYPE # alias
GPG_ERR_UNKNOWN_VERSION = 3
MSG_CTRUNC = MSG_CTRUNC # alias
GPG_ERR_EMULTIHOP = 32836
GPG_ERR_ECONNABORTED = 32792
GPG_ERR_EAFNOSUPPORT = 32773
GCRY_LOG_FATAL = 40
GPG_ERR_EPFNOSUPPORT = 32876
GPG_ERR_VALUE_NOT_FOUND = 28
GPG_ERR_EPROTOTYPE = 32884
MSG_TRYHARD = MSG_DONTROUTE # alias
_POSIX2_BC_BASE_MAX = 99 # Variable c_int
BC_BASE_MAX = _POSIX2_BC_BASE_MAX # alias
GPG_ERR_BAD_MPI = 30
GPG_ERR_EIEIO = 32812
PF_MAX = 32 # Variable c_int
AF_MAX = PF_MAX # alias
# __BLKCNT_T_TYPE = __SLONGWORD_TYPE # alias
def gcry_md_final(a): return gcry_md_ctl ((a), GCRYCTL_FINALIZE, NULL, 0) # macro
BYTE_ORDER = __BYTE_ORDER # alias
SOCK_DGRAM = SOCK_DGRAM # alias
GCRYSEXP_FMT_DEFAULT = 0
GPG_ERR_TIMEOUT = 62
GPG_ERR_INTERNAL = 63
# def gcry_cipher_setkey(h,k,l): return gcry_cipher_ctl( (h), GCRYCTL_SET_KEY, (char*)(k), (l) ) # macro
GPG_ERR_ASSUAN_SERVER_FAULT = 80
GPG_ERR_MODULE_NOT_FOUND = 159
SOCK_SEQPACKET = SOCK_SEQPACKET # alias
GCRYSEXP_FMT_BASE64 = 2
GPG_ERR_ELIBSCN = 32829
def gcry_md_test_algo(a): return gcry_md_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL ) # macro
GPG_ERR_NOT_SUPPORTED = 60
GCRY_PK_RSA = 1
GCRYCTL_ANY_INITIALIZATION_P = 40
GPG_ERR_ETOOMANYREFS = 32901
GPG_ERR_SEXP_BAD_QUOTATION = 206
# __PID_T_TYPE = __S32_TYPE # alias
GPG_ERR_NO_PRIME = 21
MSG_DONTWAIT = 64
MSG_DONTWAIT = MSG_DONTWAIT # alias
# def offsetof(TYPE,MEMBER): return (__offsetof__ (reinterpret_cast <size_t> (&reinterpret_cast <const volatile char &> (static_cast<TYPE *> (0)->MEMBER)))) # macro
GPG_ERR_INV_KEYINFO = 140
# PDP_ENDIAN = __PDP_ENDIAN # alias
GPG_ERR_CARD_NOT_INITIALIZED = 123
def __attribute_format_strfmon__(a,b): return __attribute__ ((__format__ (__strfmon__, a, b))) # macro
GPG_ERR_TIME_CONFLICT = 39
OTRL_MSGTYPE_TAGGEDPLAINTEXT = 1
GPG_ERR_UNKNOWN_CMS_OBJ = 145
__BLKCNT64_T_TYPE = __SQUAD_TYPE # alias
GPG_ERR_NO_POLICY_MATCH = 116
OFFER_NOT = 0
GPG_ERR_BAD_SIGNATURE = 8
GCRYCTL_SUSPEND_SECMEM_WARN = 28
def mpi_mul_2exp(w,u,v): return gcry_mpi_mul_2exp ((w),(u),(v)) # macro
GPG_ERR_ENOTBLK = 32863
GCRY_CIPHER_MODE_CFB = 2
GPG_ERR_EDESTADDRREQ = 32798
GPG_ERR_SEXP_NOT_CANONICAL = 204
def mpi_set(w,u): return gcry_mpi_set( (w), (u) ) # macro
GPG_ERR_EL3HLT = 32823
def FD_ISSET(fd,fdsetp): return __FD_ISSET (fd, fdsetp) # macro
GPG_ERR_EADDRNOTAVAIL = 32771
GPG_ERR_ECONNREFUSED = 32793
GCRY_CIPHER_SERPENT128 = 304
GPG_ERR_ENOPROTOOPT = 32858
GPG_ERR_EPROCLIM = 32878
GPG_ERR_EOF_GCRYPT = 64
# NL_NMAX = INT_MAX # alias
def mpi_clear_bit(a,b): return gcry_mpi_clear_bit ((a),(b)) # macro
GPG_ERR_SYNTAX = 29
GCRY_PK_RSA_E = 2
GPG_ERR_PIN_BLOCKED = 130
GPG_ERR_WRONG_KEY_USAGE = 125
GPG_ERR_INV_OID_STRING = 160
GPG_ERR_EHOSTDOWN = 32809
OTRL_MSGTYPE_QUERY = 2
# def gcry_cipher_setctr(h,k,l): return gcry_cipher_ctl( (h), GCRYCTL_SET_CTR, (char*)(k), (l) ) # macro
GCRYCTL_GET_ALGO_NENCR = 18
def gcry_md_start_debug(a,b): return gcry_md_ctl( (a), GCRYCTL_START_DUMP, (b), 0 ) # macro
__FSBLKCNT64_T_TYPE = __UQUAD_TYPE # alias
GPG_ERR_UNSUPPORTED_CMS_VERSION = 148
GPG_ERR_EDIED = 32799
OTRL_FRAGMENT_UNFRAGMENTED = 0
GPG_ERR_CORRUPTED_PROTECTION = 106
GPG_ERR_ELIBEXEC = 32827
GPG_ERR_UNEXPECTED = 38
def __STRING(x): return #x # macro
GPG_ERR_NO_DIRMNGR = 92
def FD_CLR(fd,fdsetp): return __FD_CLR (fd, fdsetp) # macro
# __CLOCKID_T_TYPE = __S32_TYPE # alias
GCRYCTL_RESUME_SECMEM_WARN = 29
GPG_ERR_ENOSYS = 32862
GPG_ERR_ENODEV = 32848
__FSFILCNT64_T_TYPE = __UQUAD_TYPE # alias
GPG_ERR_NETWORK = 48
MSG_MORE = MSG_MORE # alias
PF_SNA = 22 # Variable c_int
AF_SNA = PF_SNA # alias
GPG_ERR_PUBKEY_NOT_TRUSTED = 151
# def CMSG_LEN(len): return (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len)) # macro
PF_ECONET = 19 # Variable c_int
AF_ECONET = PF_ECONET # alias
MSG_TRUNC = MSG_TRUNC # alias
GPG_ERR_EPROGMISMATCH = 32880
GPG_ERR_EREMOTEIO = 32888
# def strndupa(s,n): return (__extension__ ({ __const char *__old = (s); size_t __len = strnlen (__old, (n)); char *__new = (char *) __builtin_alloca (__len + 1); __new[__len] = '\0'; (char *) memcpy (__new, __old, __len); })) # macro
# CHAR_BIT = __CHAR_BIT__ # alias
OTRL_FRAGMENT_INCOMPLETE = 1
# SHRT_MAX = __SHRT_MAX__ # alias
GPG_ERR_NO_USER_ID = 16
SO_PASSCRED = 16 # Variable c_int
OTRL_PUBKEY_TYPE_DSA = 0 # Variable c_int
SO_RCVTIMEO = 20 # Variable c_int
_SIGSET_H_types = 1 # Variable c_int
LONG_MIN = -2147483648 # Variable c_long
__GNU_LIBRARY__ = 6 # Variable c_int
SO_RCVBUF = 8 # Variable c_int
SO_BROADCAST = 6 # Variable c_int
__USE_XOPEN = 1 # Variable c_int
__USE_LARGEFILE64 = 1 # Variable c_int
USHRT_MAX = 65535 # Variable c_int
__time_t_defined = 1 # Variable c_int
XATTR_SIZE_MAX = 65536 # Variable c_int
MAX_CANON = 255 # Variable c_int
MAX_INPUT = 255 # Variable c_int
SO_ERROR = 4 # Variable c_int
_POSIX_SSIZE_MAX = 32767 # Variable c_int
__USE_POSIX2 = 1 # Variable c_int
__defined_schedparam = 1 # Variable c_int
OTRL_MESSAGE_TAG_V1 = ' \t \t  \t ' # Variable STRING
OTRL_MESSAGE_TAG_V2 = '  \t\t  \t ' # Variable STRING
SOL_AAL = 265 # Variable c_int
_SS_PADSIZE = 120 # Variable c_uint
GPG_ERR_SOURCE_SHIFT = 24 # Variable c_int
IOV_MAX = 1024 # Variable c_int
_POSIX_RTSIG_MAX = 8 # Variable c_int
_POSIX_SEM_VALUE_MAX = 32767 # Variable c_int
SO_TYPE = 3 # Variable c_int
SHRT_MIN = -32768 # Variable c_int
AIO_PRIO_DELTA_MAX = 20 # Variable c_int
_POSIX_HOST_NAME_MAX = 255 # Variable c_int
__STDC_IEC_559__ = 1 # Variable c_int
NZERO = 20 # Variable c_int
OTRL_POLICY_ERROR_START_AKE = 16 # Variable c_int
SO_OOBINLINE = 10 # Variable c_int
_POSIX_THREAD_THREADS_MAX = 64 # Variable c_int
_LIBC_LIMITS_H_ = 1 # Variable c_int
__GLIBC_HAVE_LONG_LONG = 1 # Variable c_int
OTRL_VERSION_MAJOR = 3 # Variable c_int
_SYS_SELECT_H = 1 # Variable c_int
SO_PEERSEC = 31 # Variable c_int
GCRY_AC_FLAG_DEALLOC = 1 # Variable c_int
OTRL_VERSION_SUB = 0 # Variable c_int
_POSIX_TIMER_MAX = 32 # Variable c_int
GCRY_AC_FLAG_NO_BLINDING = 4 # Variable c_int
_ISOC99_SOURCE = 1 # Variable c_int
__USE_POSIX = 1 # Variable c_int
DELAYTIMER_MAX = 2147483647 # Variable c_int
HOST_NAME_MAX = 64 # Variable c_int
OTRL_VERSION = '3.0.0' # Variable STRING
SO_REUSEADDR = 2 # Variable c_int
ULONG_LONG_MAX = 18446744073709551615L # Variable c_ulonglong
SO_BINDTODEVICE = 25 # Variable c_int
SO_PEERNAME = 28 # Variable c_int
PTHREAD_STACK_MIN = 16384 # Variable c_int
GCRY_PRIME_CHECK_AT_GOT_PRIME = 1 # Variable c_int
_POSIX_SOURCE = 1 # Variable c_int
GCRY_PRIME_CHECK_AT_FINISH = 0 # Variable c_int
__clock_t_defined = 1 # Variable c_int
GCRY_PRIME_FLAG_SPECIAL_FACTOR = 2 # Variable c_int
__USE_ANSI = 1 # Variable c_int
OTRL_POLICY_MANUAL = 3 # Variable c_int
__USE_POSIX199309 = 1 # Variable c_int
GCRY_PK_USAGE_ENCR = 2 # Variable c_int
_POSIX_TZNAME_MAX = 6 # Variable c_int
_POSIX_LINK_MAX = 8 # Variable c_int
SO_SNDBUF = 7 # Variable c_int
_POSIX_MQ_OPEN_MAX = 8 # Variable c_int
__GLIBC_MINOR__ = 3 # Variable c_int
OTRL_TLV_PADDING = 0 # Variable c_int
__SOCKADDR_COMMON_SIZE = 2 # Variable c_uint
__clockid_t_defined = 1 # Variable c_int
MB_LEN_MAX = 16 # Variable c_int
SO_ACCEPTCONN = 30 # Variable c_int
__timer_t_defined = 1 # Variable c_int
NGROUPS_MAX = 65536 # Variable c_int
SO_BSDCOMPAT = 14 # Variable c_int
SO_SECURITY_ENCRYPTION_TRANSPORT = 23 # Variable c_int
WORD_BIT = 32 # Variable c_int
__BIT_TYPES_DEFINED__ = 1 # Variable c_int
SO_RCVLOWAT = 18 # Variable c_int
_SVID_SOURCE = 1 # Variable c_int
__USE_XOPEN2K = 1 # Variable c_int
DH1536_GROUP_ID = 5 # Variable c_int
_SYS_TYPES_H = 1 # Variable c_int
SO_NO_CHECK = 11 # Variable c_int
SIOCATMARK = 35077 # Variable c_int
SOMAXCONN = 128 # Variable c_int
_BITS_POSIX2_LIM_H = 1 # Variable c_int
GCRYPT_VERSION = '1.2.2' # Variable STRING
_POSIX_THREAD_KEYS_MAX = 128 # Variable c_int
__timespec_defined = 1 # Variable c_int
__USE_GNU = 1 # Variable c_int
_POSIX_CLOCKRES_MIN = 20000000 # Variable c_int
_STRUCT_TIMEVAL = 1 # Variable c_int
_SYS_TIME_H = 1 # Variable c_int
GPG_ERR_SYSTEM_ERROR = 32768 # Variable c_int
GCRY_AC_FLAG_COPY = 2 # Variable c_int
OTRL_POLICY_ALWAYS = 31 # Variable c_int
XATTR_LIST_MAX = 65536 # Variable c_int
_SYS_UIO_H = 1 # Variable c_int
_LARGEFILE_SOURCE = 1 # Variable c_int
_POSIX_C_SOURCE = 199506 # Variable c_long
SOL_RAW = 255 # Variable c_int
OTRL_VERSION_MINOR = 0 # Variable c_int
_GCRY_GCC_VERSION = 30404 # Variable c_int
_POSIX_CHILD_MAX = 25 # Variable c_int
SO_DEBUG = 1 # Variable c_int
_POSIX2_CHARCLASS_NAME_MAX = 14 # Variable c_int
__USE_SVID = 1 # Variable c_int
__USE_UNIX98 = 1 # Variable c_int
CHILD_MAX = 999 # Variable c_int
_POSIX_STREAM_MAX = 8 # Variable c_int
__USE_MISC = 1 # Variable c_int
OTRL_POLICY_ALLOW_V2 = 2 # Variable c_int
OTRL_POLICY_ALLOW_V1 = 1 # Variable c_int
CHARCLASS_NAME_MAX = 2048 # Variable c_int
_POSIX_TTY_NAME_MAX = 9 # Variable c_int
_POSIX_MQ_PRIO_MAX = 32 # Variable c_int
SOL_DECNET = 261 # Variable c_int
_XOPEN_LIM_H = 1 # Variable c_int
OTRL_TLV_DISCONNECTED = 1 # Variable c_int
_BITS_TYPESIZES_H = 1 # Variable c_int
_POSIX_MAX_INPUT = 255 # Variable c_int
_ENDIAN_H = 1 # Variable c_int
SOL_IRDA = 266 # Variable c_int
SOL_ATM = 264 # Variable c_int
FIOGETOWN = 35075 # Variable c_int
_POSIX_PATH_MAX = 256 # Variable c_int
OTRL_POLICY_VERSION_MASK = 3 # Variable c_int
_SYS_SOCKET_H = 1 # Variable c_int
__STDC_ISO_10646__ = 200009 # Variable c_long
SIOCGSTAMP = 35078 # Variable c_int
GCRY_PRIME_CHECK_AT_MAYBE_PRIME = 2 # Variable c_int
SO_SNDTIMEO = 21 # Variable c_int
__STDC_IEC_559_COMPLEX__ = 1 # Variable c_int
_SYS_SYSMACROS_H = 1 # Variable c_int
_POSIX_DELAYTIMER_MAX = 32 # Variable c_int
__USE_XOPEN_EXTENDED = 1 # Variable c_int
__USE_BSD = 1 # Variable c_int
OTRL_POLICY_REQUIRE_ENCRYPTION = 4 # Variable c_int
_BITS_POSIX1_LIM_H = 1 # Variable c_int
SO_PEERCRED = 17 # Variable c_int
__USE_LARGEFILE = 1 # Variable c_int
GCRY_PK_USAGE_SIGN = 1 # Variable c_int
SO_DONTROUTE = 5 # Variable c_int
_FEATURES_H = 1 # Variable c_int
ULONG_MAX = 4294967295L # Variable c_ulong
GCRY_PRIME_FLAG_SECRET = 1 # Variable c_int
ARG_MAX = 131072 # Variable c_int
OTRL_POLICY_NEVER = 0 # Variable c_int
_POSIX_NGROUPS_MAX = 8 # Variable c_int
__USE_POSIX199506 = 1 # Variable c_int
_POSIX_SEM_NSEMS_MAX = 256 # Variable c_int
_BITS_TYPES_H = 1 # Variable c_int
GPG_ERR_SOURCE_MASK = 255 # Variable c_int
PIPE_BUF = 4096 # Variable c_int
_POSIX_MAX_CANON = 255 # Variable c_int
OTRL_POLICY_SEND_WHITESPACE_TAG = 8 # Variable c_int
_POSIX_SYMLOOP_MAX = 8 # Variable c_int
GPG_ERROR_H = 1 # Variable c_int
_SS_SIZE = 128 # Variable c_int
_POSIX_SYMLINK_MAX = 255 # Variable c_int
_POSIX_QLIMIT = 1 # Variable c_int
UCHAR_MAX = 255 # Variable c_int
FIOSETOWN = 35073 # Variable c_int
RTSIG_MAX = 32 # Variable c_int
_SYS_CDEFS_H = 1 # Variable c_int
PTHREAD_KEYS_MAX = 1024 # Variable c_int
XATTR_NAME_MAX = 255 # Variable c_int
_STRING_H = 1 # Variable c_int
_POSIX_SIGQUEUE_MAX = 32 # Variable c_int
SO_LINGER = 13 # Variable c_int
class _pthread_fastlock(Structure):
    pass
_pthread_fastlock._fields_ = [
    ('__status', c_long),
    ('__spinlock', c_int),
]
class _pthread_descr_struct(Structure):
    pass
_pthread_descr = POINTER(_pthread_descr_struct)
_pthread_descr_struct._fields_ = [
]
class __pthread_attr_s(Structure):
    pass
class __sched_param(Structure):
    pass
__sched_param._fields_ = [
    ('__sched_priority', c_int),
]
size_t = c_uint
__pthread_attr_s._fields_ = [
    ('__detachstate', c_int),
    ('__schedpolicy', c_int),
    ('__schedparam', __sched_param),
    ('__inheritsched', c_int),
    ('__scope', c_int),
    ('__guardsize', size_t),
    ('__stackaddr_set', c_int),
    ('__stackaddr', c_void_p),
    ('__stacksize', size_t),
]
pthread_attr_t = __pthread_attr_s
__pthread_cond_align_t = c_longlong
class pthread_cond_t(Structure):
    pass
pthread_cond_t._pack_ = 4
pthread_cond_t._fields_ = [
    ('__c_lock', _pthread_fastlock),
    ('__c_waiting', _pthread_descr),
    ('__padding', c_char * 28),
    ('__align', __pthread_cond_align_t),
]
class pthread_condattr_t(Structure):
    pass
pthread_condattr_t._fields_ = [
    ('__dummy', c_int),
]
pthread_key_t = c_uint
class pthread_mutex_t(Structure):
    pass
pthread_mutex_t._fields_ = [
    ('__m_reserved', c_int),
    ('__m_count', c_int),
    ('__m_owner', _pthread_descr),
    ('__m_kind', c_int),
    ('__m_lock', _pthread_fastlock),
]
class pthread_mutexattr_t(Structure):
    pass
pthread_mutexattr_t._fields_ = [
    ('__mutexkind', c_int),
]
pthread_once_t = c_int
class _pthread_rwlock_t(Structure):
    pass
_pthread_rwlock_t._fields_ = [
    ('__rw_lock', _pthread_fastlock),
    ('__rw_readers', c_int),
    ('__rw_writer', _pthread_descr),
    ('__rw_read_waiting', _pthread_descr),
    ('__rw_write_waiting', _pthread_descr),
    ('__rw_kind', c_int),
    ('__rw_pshared', c_int),
]
pthread_rwlock_t = _pthread_rwlock_t
class pthread_rwlockattr_t(Structure):
    pass
pthread_rwlockattr_t._fields_ = [
    ('__lockkind', c_int),
    ('__pshared', c_int),
]
pthread_spinlock_t = c_int
class pthread_barrier_t(Structure):
    pass
pthread_barrier_t._fields_ = [
    ('__ba_lock', _pthread_fastlock),
    ('__ba_required', c_int),
    ('__ba_present', c_int),
    ('__ba_waiting', _pthread_descr),
]
class pthread_barrierattr_t(Structure):
    pass
pthread_barrierattr_t._fields_ = [
    ('__pshared', c_int),
]
pthread_t = c_ulong
__sig_atomic_t = c_int
class __sigset_t(Structure):
    pass
__sigset_t._fields_ = [
    ('__val', c_ulong * 32),
]
sa_family_t = c_ushort

# values for enumeration '__socket_type'
__socket_type = c_int # enum
class sockaddr(Structure):
    pass
sockaddr._fields_ = [
    ('sa_family', sa_family_t),
    ('sa_data', c_char * 14),
]
class sockaddr_storage(Structure):
    pass
sockaddr_storage._fields_ = [
    ('ss_family', sa_family_t),
    ('__ss_align', __uint32_t),
    ('__ss_padding', c_char * 120),
]

# values for unnamed enumeration
class msghdr(Structure):
    pass
class iovec(Structure):
    pass
msghdr._fields_ = [
    ('msg_name', c_void_p),
    ('msg_namelen', socklen_t),
    ('msg_iov', POINTER(iovec)),
    ('msg_iovlen', size_t),
    ('msg_control', c_void_p),
    ('msg_controllen', size_t),
    ('msg_flags', c_int),
]
class cmsghdr(Structure):
    pass
cmsghdr._fields_ = [
    ('cmsg_len', size_t),
    ('cmsg_level', c_int),
    ('cmsg_type', c_int),
    ('__cmsg_data', c_ubyte * 0),
]
__cmsg_nxthdr = _libraries['libotr.so.2'].__cmsg_nxthdr
__cmsg_nxthdr.restype = POINTER(cmsghdr)
__cmsg_nxthdr.argtypes = [POINTER(msghdr), POINTER(cmsghdr)]

# values for unnamed enumeration
class ucred(Structure):
    pass
__pid_t = c_int
pid_t = __pid_t
__uid_t = c_uint
uid_t = __uid_t
__gid_t = c_uint
gid_t = __gid_t
ucred._fields_ = [
    ('pid', pid_t),
    ('uid', uid_t),
    ('gid', gid_t),
]
class linger(Structure):
    pass
linger._fields_ = [
    ('l_onoff', c_int),
    ('l_linger', c_int),
]
class timeval(Structure):
    pass
__time_t = c_long
__suseconds_t = c_long
timeval._fields_ = [
    ('tv_sec', __time_t),
    ('tv_usec', __suseconds_t),
]
__u_char = c_ubyte
__u_short = c_ushort
__u_int = c_uint
__u_long = c_ulong
__int8_t = c_byte
__uint8_t = c_ubyte
__int16_t = c_short
__uint16_t = c_ushort
__int32_t = c_int
__int64_t = c_longlong
__uint64_t = c_ulonglong
__dev_t = __u_quad_t
__ino_t = c_ulong
__ino64_t = __u_quad_t
__mode_t = c_uint
__nlink_t = c_uint
__off_t = c_long
__off64_t = __quad_t
class __fsid_t(Structure):
    pass
__fsid_t._fields_ = [
    ('__val', c_int * 2),
]
__clock_t = c_long
__rlim_t = c_ulong
__rlim64_t = __u_quad_t
__id_t = c_uint
__useconds_t = c_uint
__daddr_t = c_int
__swblk_t = c_long
__key_t = c_int
__clockid_t = c_int
__timer_t = c_int
__blksize_t = c_long
__blkcnt_t = c_long
__blkcnt64_t = __quad_t
__fsblkcnt_t = c_ulong
__fsblkcnt64_t = __u_quad_t
__fsfilcnt_t = c_ulong
__fsfilcnt64_t = __u_quad_t
__ssize_t = c_int
__loff_t = __off64_t
__qaddr_t = POINTER(__quad_t)
__caddr_t = STRING
__intptr_t = c_int
iovec._fields_ = [
    ('iov_base', c_void_p),
    ('iov_len', size_t),
]
class gcry_module(Structure):
    pass
gcry_module_t = POINTER(gcry_module)
gcry_module._fields_ = [
]

# values for enumeration 'gpg_err_code_t'
gpg_err_code_t = c_int # enum
gcry_err_code_t = gpg_err_code_t
gcry_cipher_setkey_t = CFUNCTYPE(gcry_err_code_t, c_void_p, POINTER(c_ubyte), c_uint)
gcry_cipher_encrypt_t = CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), POINTER(c_ubyte))
gcry_cipher_decrypt_t = CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), POINTER(c_ubyte))
gcry_cipher_stencrypt_t = CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), POINTER(c_ubyte), c_uint)
gcry_cipher_stdecrypt_t = CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), POINTER(c_ubyte), c_uint)
class gcry_cipher_oid_spec(Structure):
    pass
gcry_cipher_oid_spec._fields_ = [
    ('oid', STRING),
    ('mode', c_int),
]
gcry_cipher_oid_spec_t = gcry_cipher_oid_spec
class gcry_cipher_spec(Structure):
    pass
gcry_cipher_spec._fields_ = [
    ('name', STRING),
    ('aliases', POINTER(STRING)),
    ('oids', POINTER(gcry_cipher_oid_spec_t)),
    ('blocksize', size_t),
    ('keylen', size_t),
    ('contextsize', size_t),
    ('setkey', gcry_cipher_setkey_t),
    ('encrypt', gcry_cipher_encrypt_t),
    ('decrypt', gcry_cipher_decrypt_t),
    ('stencrypt', gcry_cipher_stencrypt_t),
    ('stdecrypt', gcry_cipher_stdecrypt_t),
]
gcry_cipher_spec_t = gcry_cipher_spec
gpg_error_t = c_uint
gcry_error_t = gpg_error_t
gcry_cipher_register = _libraries['libotr.so.2'].gcry_cipher_register
gcry_cipher_register.restype = gcry_error_t
gcry_cipher_register.argtypes = [POINTER(gcry_cipher_spec_t), POINTER(c_int), POINTER(gcry_module_t)]
gcry_cipher_unregister = _libraries['libotr.so.2'].gcry_cipher_unregister
gcry_cipher_unregister.restype = None
gcry_cipher_unregister.argtypes = [gcry_module_t]
class gcry_mpi(Structure):
    pass
gcry_mpi_t = POINTER(gcry_mpi)
gcry_pk_generate_t = CFUNCTYPE(gcry_err_code_t, c_int, c_uint, c_ulong, POINTER(gcry_mpi_t), POINTER(POINTER(gcry_mpi_t)))
gcry_pk_check_secret_key_t = CFUNCTYPE(gcry_err_code_t, c_int, POINTER(gcry_mpi_t))
gcry_pk_encrypt_t = CFUNCTYPE(gcry_err_code_t, c_int, POINTER(gcry_mpi_t), POINTER(gcry_mpi), POINTER(gcry_mpi_t), c_int)
gcry_pk_decrypt_t = CFUNCTYPE(gcry_err_code_t, c_int, POINTER(gcry_mpi_t), POINTER(gcry_mpi_t), POINTER(gcry_mpi_t), c_int)
gcry_pk_sign_t = CFUNCTYPE(gcry_err_code_t, c_int, POINTER(gcry_mpi_t), POINTER(gcry_mpi), POINTER(gcry_mpi_t))
gcry_pk_verify_t = CFUNCTYPE(gcry_err_code_t, c_int, POINTER(gcry_mpi), POINTER(gcry_mpi_t), POINTER(gcry_mpi_t), CFUNCTYPE(c_int, c_void_p, POINTER(gcry_mpi)), c_void_p)
gcry_pk_get_nbits_t = CFUNCTYPE(c_uint, c_int, POINTER(gcry_mpi_t))
class gcry_pk_spec(Structure):
    pass
gcry_pk_spec._fields_ = [
    ('name', STRING),
    ('aliases', POINTER(STRING)),
    ('elements_pkey', STRING),
    ('elements_skey', STRING),
    ('elements_enc', STRING),
    ('elements_sig', STRING),
    ('elements_grip', STRING),
    ('use', c_int),
    ('generate', gcry_pk_generate_t),
    ('check_secret_key', gcry_pk_check_secret_key_t),
    ('encrypt', gcry_pk_encrypt_t),
    ('decrypt', gcry_pk_decrypt_t),
    ('sign', gcry_pk_sign_t),
    ('verify', gcry_pk_verify_t),
    ('get_nbits', gcry_pk_get_nbits_t),
]
gcry_pk_spec_t = gcry_pk_spec
gcry_pk_register = _libraries['libotr.so.2'].gcry_pk_register
gcry_pk_register.restype = gcry_error_t
gcry_pk_register.argtypes = [POINTER(gcry_pk_spec_t), POINTER(c_uint), POINTER(gcry_module_t)]
gcry_pk_unregister = _libraries['libotr.so.2'].gcry_pk_unregister
gcry_pk_unregister.restype = None
gcry_pk_unregister.argtypes = [gcry_module_t]
gcry_md_init_t = CFUNCTYPE(None, c_void_p)
gcry_md_write_t = CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_uint)
gcry_md_final_t = CFUNCTYPE(None, c_void_p)
gcry_md_read_t = CFUNCTYPE(POINTER(c_ubyte), c_void_p)
class gcry_md_oid_spec(Structure):
    pass
gcry_md_oid_spec._fields_ = [
    ('oidstring', STRING),
]
gcry_md_oid_spec_t = gcry_md_oid_spec
class gcry_md_spec(Structure):
    pass
gcry_md_spec._fields_ = [
    ('name', STRING),
    ('asnoid', POINTER(c_ubyte)),
    ('asnlen', c_int),
    ('oids', POINTER(gcry_md_oid_spec_t)),
    ('mdlen', c_int),
    ('init', gcry_md_init_t),
    ('write', gcry_md_write_t),
    ('final', gcry_md_final_t),
    ('read', gcry_md_read_t),
    ('contextsize', size_t),
]
gcry_md_spec_t = gcry_md_spec
gcry_md_register = _libraries['libotr.so.2'].gcry_md_register
gcry_md_register.restype = gcry_error_t
gcry_md_register.argtypes = [POINTER(gcry_md_spec_t), POINTER(c_uint), POINTER(gcry_module_t)]
gcry_md_unregister = _libraries['libotr.so.2'].gcry_md_unregister
gcry_md_unregister.restype = None
gcry_md_unregister.argtypes = [gcry_module_t]

# values for enumeration 'gpg_err_source_t'
gpg_err_source_t = c_int # enum
gcry_err_source_t = gpg_err_source_t
gcry_strerror = _libraries['libotr.so.2'].gcry_strerror
gcry_strerror.restype = STRING
gcry_strerror.argtypes = [gcry_error_t]
gcry_strsource = _libraries['libotr.so.2'].gcry_strsource
gcry_strsource.restype = STRING
gcry_strsource.argtypes = [gcry_error_t]
gcry_err_code_from_errno = _libraries['libotr.so.2'].gcry_err_code_from_errno
gcry_err_code_from_errno.restype = gcry_err_code_t
gcry_err_code_from_errno.argtypes = [c_int]
gcry_err_code_to_errno = _libraries['libotr.so.2'].gcry_err_code_to_errno
gcry_err_code_to_errno.restype = c_int
gcry_err_code_to_errno.argtypes = [gcry_err_code_t]
gcry_err_make_from_errno = _libraries['libotr.so.2'].gcry_err_make_from_errno
gcry_err_make_from_errno.restype = gcry_error_t
gcry_err_make_from_errno.argtypes = [gcry_err_source_t, c_int]
gcry_error_from_errno = _libraries['libotr.so.2'].gcry_error_from_errno
gcry_error_from_errno.restype = gcry_err_code_t
gcry_error_from_errno.argtypes = [c_int]

# values for enumeration 'gcry_thread_option'
gcry_thread_option = c_int # enum
class gcry_thread_cbs(Structure):
    pass
ssize_t = __ssize_t
gcry_thread_cbs._fields_ = [
    ('option', gcry_thread_option),
    ('init', CFUNCTYPE(c_int)),
    ('mutex_init', CFUNCTYPE(c_int, POINTER(c_void_p))),
    ('mutex_destroy', CFUNCTYPE(c_int, POINTER(c_void_p))),
    ('mutex_lock', CFUNCTYPE(c_int, POINTER(c_void_p))),
    ('mutex_unlock', CFUNCTYPE(c_int, POINTER(c_void_p))),
    ('read', CFUNCTYPE(ssize_t, c_int, c_void_p, c_uint)),
    ('write', CFUNCTYPE(ssize_t, c_int, c_void_p, c_uint)),
    ('select', CFUNCTYPE(ssize_t, c_int, POINTER(fd_set), POINTER(fd_set), POINTER(fd_set), POINTER(timeval))),
    ('waitpid', CFUNCTYPE(ssize_t, c_int, POINTER(c_int), c_int)),
    ('accept', CFUNCTYPE(c_int, c_int, POINTER(sockaddr), POINTER(socklen_t))),
    ('connect', CFUNCTYPE(c_int, c_int, POINTER(sockaddr), c_uint)),
    ('sendmsg', CFUNCTYPE(c_int, c_int, POINTER(msghdr), c_int)),
    ('recvmsg', CFUNCTYPE(c_int, c_int, POINTER(msghdr), c_int)),
]
gcry_mpi._fields_ = [
]
GCRY_MPI = POINTER(gcry_mpi)
GcryMPI = POINTER(gcry_mpi)
gcry_check_version = _libraries['libotr.so.2'].gcry_check_version
gcry_check_version.restype = STRING
gcry_check_version.argtypes = [STRING]

# values for enumeration 'gcry_ctl_cmds'
gcry_ctl_cmds = c_int # enum
gcry_control = _libraries['libotr.so.2'].gcry_control
gcry_control.restype = gcry_error_t
gcry_control.argtypes = [gcry_ctl_cmds]
class gcry_sexp(Structure):
    pass
gcry_sexp._fields_ = [
]
gcry_sexp_t = POINTER(gcry_sexp)
GCRY_SEXP = POINTER(gcry_sexp)
GcrySexp = POINTER(gcry_sexp)

# values for enumeration 'gcry_sexp_format'
gcry_sexp_format = c_int # enum
gcry_sexp_new = _libraries['libotr.so.2'].gcry_sexp_new
gcry_sexp_new.restype = gcry_error_t
gcry_sexp_new.argtypes = [POINTER(gcry_sexp_t), c_void_p, size_t, c_int]
gcry_sexp_create = _libraries['libotr.so.2'].gcry_sexp_create
gcry_sexp_create.restype = gcry_error_t
gcry_sexp_create.argtypes = [POINTER(gcry_sexp_t), c_void_p, size_t, c_int, CFUNCTYPE(None, c_void_p)]
gcry_sexp_sscan = _libraries['libotr.so.2'].gcry_sexp_sscan
gcry_sexp_sscan.restype = gcry_error_t
gcry_sexp_sscan.argtypes = [POINTER(gcry_sexp_t), POINTER(size_t), STRING, size_t]
gcry_sexp_build = _libraries['libotr.so.2'].gcry_sexp_build
gcry_sexp_build.restype = gcry_error_t
gcry_sexp_build.argtypes = [POINTER(gcry_sexp_t), POINTER(size_t), STRING]
gcry_sexp_build_array = _libraries['libotr.so.2'].gcry_sexp_build_array
gcry_sexp_build_array.restype = gcry_error_t
gcry_sexp_build_array.argtypes = [POINTER(gcry_sexp_t), POINTER(size_t), STRING, POINTER(c_void_p)]
gcry_sexp_release = _libraries['libotr.so.2'].gcry_sexp_release
gcry_sexp_release.restype = None
gcry_sexp_release.argtypes = [gcry_sexp_t]
gcry_sexp_canon_len = _libraries['libotr.so.2'].gcry_sexp_canon_len
gcry_sexp_canon_len.restype = size_t
gcry_sexp_canon_len.argtypes = [POINTER(c_ubyte), size_t, POINTER(size_t), POINTER(gcry_error_t)]
gcry_sexp_sprint = _libraries['libotr.so.2'].gcry_sexp_sprint
gcry_sexp_sprint.restype = size_t
gcry_sexp_sprint.argtypes = [gcry_sexp_t, c_int, c_void_p, size_t]
gcry_sexp_dump = _libraries['libotr.so.2'].gcry_sexp_dump
gcry_sexp_dump.restype = None
gcry_sexp_dump.argtypes = [gcry_sexp_t]
gcry_sexp_cons = _libraries['libotr.so.2'].gcry_sexp_cons
gcry_sexp_cons.restype = gcry_sexp_t
gcry_sexp_cons.argtypes = [gcry_sexp_t, gcry_sexp_t]
gcry_sexp_alist = _libraries['libotr.so.2'].gcry_sexp_alist
gcry_sexp_alist.restype = gcry_sexp_t
gcry_sexp_alist.argtypes = [POINTER(gcry_sexp_t)]
gcry_sexp_vlist = _libraries['libotr.so.2'].gcry_sexp_vlist
gcry_sexp_vlist.restype = gcry_sexp_t
gcry_sexp_vlist.argtypes = [gcry_sexp_t]
gcry_sexp_append = _libraries['libotr.so.2'].gcry_sexp_append
gcry_sexp_append.restype = gcry_sexp_t
gcry_sexp_append.argtypes = [gcry_sexp_t, gcry_sexp_t]
gcry_sexp_prepend = _libraries['libotr.so.2'].gcry_sexp_prepend
gcry_sexp_prepend.restype = gcry_sexp_t
gcry_sexp_prepend.argtypes = [gcry_sexp_t, gcry_sexp_t]
gcry_sexp_find_token = _libraries['libotr.so.2'].gcry_sexp_find_token
gcry_sexp_find_token.restype = gcry_sexp_t
gcry_sexp_find_token.argtypes = [gcry_sexp_t, STRING, size_t]
gcry_sexp_length = _libraries['libotr.so.2'].gcry_sexp_length
gcry_sexp_length.restype = c_int
gcry_sexp_length.argtypes = [gcry_sexp_t]
gcry_sexp_nth = _libraries['libotr.so.2'].gcry_sexp_nth
gcry_sexp_nth.restype = gcry_sexp_t
gcry_sexp_nth.argtypes = [gcry_sexp_t, c_int]
gcry_sexp_car = _libraries['libotr.so.2'].gcry_sexp_car
gcry_sexp_car.restype = gcry_sexp_t
gcry_sexp_car.argtypes = [gcry_sexp_t]
gcry_sexp_cdr = _libraries['libotr.so.2'].gcry_sexp_cdr
gcry_sexp_cdr.restype = gcry_sexp_t
gcry_sexp_cdr.argtypes = [gcry_sexp_t]
gcry_sexp_cadr = _libraries['libotr.so.2'].gcry_sexp_cadr
gcry_sexp_cadr.restype = gcry_sexp_t
gcry_sexp_cadr.argtypes = [gcry_sexp_t]
gcry_sexp_nth_data = _libraries['libotr.so.2'].gcry_sexp_nth_data
gcry_sexp_nth_data.restype = STRING
gcry_sexp_nth_data.argtypes = [gcry_sexp_t, c_int, POINTER(size_t)]
gcry_sexp_nth_mpi = _libraries['libotr.so.2'].gcry_sexp_nth_mpi
gcry_sexp_nth_mpi.restype = gcry_mpi_t
gcry_sexp_nth_mpi.argtypes = [gcry_sexp_t, c_int, c_int]

# values for enumeration 'gcry_mpi_format'
gcry_mpi_format = c_int # enum

# values for enumeration 'gcry_mpi_flag'
gcry_mpi_flag = c_int # enum
gcry_mpi_new = _libraries['libotr.so.2'].gcry_mpi_new
gcry_mpi_new.restype = gcry_mpi_t
gcry_mpi_new.argtypes = [c_uint]
gcry_mpi_snew = _libraries['libotr.so.2'].gcry_mpi_snew
gcry_mpi_snew.restype = gcry_mpi_t
gcry_mpi_snew.argtypes = [c_uint]
gcry_mpi_release = _libraries['libotr.so.2'].gcry_mpi_release
gcry_mpi_release.restype = None
gcry_mpi_release.argtypes = [gcry_mpi_t]
gcry_mpi_copy = _libraries['libotr.so.2'].gcry_mpi_copy
gcry_mpi_copy.restype = gcry_mpi_t
gcry_mpi_copy.argtypes = [gcry_mpi_t]
gcry_mpi_set = _libraries['libotr.so.2'].gcry_mpi_set
gcry_mpi_set.restype = gcry_mpi_t
gcry_mpi_set.argtypes = [gcry_mpi_t, gcry_mpi_t]
gcry_mpi_set_ui = _libraries['libotr.so.2'].gcry_mpi_set_ui
gcry_mpi_set_ui.restype = gcry_mpi_t
gcry_mpi_set_ui.argtypes = [gcry_mpi_t, c_ulong]
gcry_mpi_swap = _libraries['libotr.so.2'].gcry_mpi_swap
gcry_mpi_swap.restype = None
gcry_mpi_swap.argtypes = [gcry_mpi_t, gcry_mpi_t]
gcry_mpi_cmp = _libraries['libotr.so.2'].gcry_mpi_cmp
gcry_mpi_cmp.restype = c_int
gcry_mpi_cmp.argtypes = [gcry_mpi_t, gcry_mpi_t]
gcry_mpi_cmp_ui = _libraries['libotr.so.2'].gcry_mpi_cmp_ui
gcry_mpi_cmp_ui.restype = c_int
gcry_mpi_cmp_ui.argtypes = [gcry_mpi_t, c_ulong]
gcry_mpi_scan = _libraries['libotr.so.2'].gcry_mpi_scan
gcry_mpi_scan.restype = gcry_error_t
gcry_mpi_scan.argtypes = [POINTER(gcry_mpi_t), gcry_mpi_format, c_void_p, size_t, POINTER(size_t)]
gcry_mpi_print = _libraries['libotr.so.2'].gcry_mpi_print
gcry_mpi_print.restype = gcry_error_t
gcry_mpi_print.argtypes = [gcry_mpi_format, POINTER(c_ubyte), size_t, POINTER(size_t), gcry_mpi_t]
gcry_mpi_aprint = _libraries['libotr.so.2'].gcry_mpi_aprint
gcry_mpi_aprint.restype = gcry_error_t
gcry_mpi_aprint.argtypes = [gcry_mpi_format, POINTER(POINTER(c_ubyte)), POINTER(size_t), gcry_mpi_t]
gcry_mpi_dump = _libraries['libotr.so.2'].gcry_mpi_dump
gcry_mpi_dump.restype = None
gcry_mpi_dump.argtypes = [gcry_mpi_t]
gcry_mpi_add = _libraries['libotr.so.2'].gcry_mpi_add
gcry_mpi_add.restype = None
gcry_mpi_add.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_add_ui = _libraries['libotr.so.2'].gcry_mpi_add_ui
gcry_mpi_add_ui.restype = None
gcry_mpi_add_ui.argtypes = [gcry_mpi_t, gcry_mpi_t, c_ulong]
gcry_mpi_addm = _libraries['libotr.so.2'].gcry_mpi_addm
gcry_mpi_addm.restype = None
gcry_mpi_addm.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_sub = _libraries['libotr.so.2'].gcry_mpi_sub
gcry_mpi_sub.restype = None
gcry_mpi_sub.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_sub_ui = _libraries['libotr.so.2'].gcry_mpi_sub_ui
gcry_mpi_sub_ui.restype = None
gcry_mpi_sub_ui.argtypes = [gcry_mpi_t, gcry_mpi_t, c_ulong]
gcry_mpi_subm = _libraries['libotr.so.2'].gcry_mpi_subm
gcry_mpi_subm.restype = None
gcry_mpi_subm.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_mul = _libraries['libotr.so.2'].gcry_mpi_mul
gcry_mpi_mul.restype = None
gcry_mpi_mul.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_mul_ui = _libraries['libotr.so.2'].gcry_mpi_mul_ui
gcry_mpi_mul_ui.restype = None
gcry_mpi_mul_ui.argtypes = [gcry_mpi_t, gcry_mpi_t, c_ulong]
gcry_mpi_mulm = _libraries['libotr.so.2'].gcry_mpi_mulm
gcry_mpi_mulm.restype = None
gcry_mpi_mulm.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_mul_2exp = _libraries['libotr.so.2'].gcry_mpi_mul_2exp
gcry_mpi_mul_2exp.restype = None
gcry_mpi_mul_2exp.argtypes = [gcry_mpi_t, gcry_mpi_t, c_ulong]
gcry_mpi_div = _libraries['libotr.so.2'].gcry_mpi_div
gcry_mpi_div.restype = None
gcry_mpi_div.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t, gcry_mpi_t, c_int]
gcry_mpi_mod = _libraries['libotr.so.2'].gcry_mpi_mod
gcry_mpi_mod.restype = None
gcry_mpi_mod.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_powm = _libraries['libotr.so.2'].gcry_mpi_powm
gcry_mpi_powm.restype = None
gcry_mpi_powm.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_gcd = _libraries['libotr.so.2'].gcry_mpi_gcd
gcry_mpi_gcd.restype = c_int
gcry_mpi_gcd.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_invm = _libraries['libotr.so.2'].gcry_mpi_invm
gcry_mpi_invm.restype = c_int
gcry_mpi_invm.argtypes = [gcry_mpi_t, gcry_mpi_t, gcry_mpi_t]
gcry_mpi_get_nbits = _libraries['libotr.so.2'].gcry_mpi_get_nbits
gcry_mpi_get_nbits.restype = c_uint
gcry_mpi_get_nbits.argtypes = [gcry_mpi_t]
gcry_mpi_test_bit = _libraries['libotr.so.2'].gcry_mpi_test_bit
gcry_mpi_test_bit.restype = c_int
gcry_mpi_test_bit.argtypes = [gcry_mpi_t, c_uint]
gcry_mpi_set_bit = _libraries['libotr.so.2'].gcry_mpi_set_bit
gcry_mpi_set_bit.restype = None
gcry_mpi_set_bit.argtypes = [gcry_mpi_t, c_uint]
gcry_mpi_clear_bit = _libraries['libotr.so.2'].gcry_mpi_clear_bit
gcry_mpi_clear_bit.restype = None
gcry_mpi_clear_bit.argtypes = [gcry_mpi_t, c_uint]
gcry_mpi_set_highbit = _libraries['libotr.so.2'].gcry_mpi_set_highbit
gcry_mpi_set_highbit.restype = None
gcry_mpi_set_highbit.argtypes = [gcry_mpi_t, c_uint]
gcry_mpi_clear_highbit = _libraries['libotr.so.2'].gcry_mpi_clear_highbit
gcry_mpi_clear_highbit.restype = None
gcry_mpi_clear_highbit.argtypes = [gcry_mpi_t, c_uint]
gcry_mpi_rshift = _libraries['libotr.so.2'].gcry_mpi_rshift
gcry_mpi_rshift.restype = None
gcry_mpi_rshift.argtypes = [gcry_mpi_t, gcry_mpi_t, c_uint]
gcry_mpi_set_opaque = _libraries['libotr.so.2'].gcry_mpi_set_opaque
gcry_mpi_set_opaque.restype = gcry_mpi_t
gcry_mpi_set_opaque.argtypes = [gcry_mpi_t, c_void_p, c_uint]
gcry_mpi_get_opaque = _libraries['libotr.so.2'].gcry_mpi_get_opaque
gcry_mpi_get_opaque.restype = c_void_p
gcry_mpi_get_opaque.argtypes = [gcry_mpi_t, POINTER(c_uint)]
gcry_mpi_set_flag = _libraries['libotr.so.2'].gcry_mpi_set_flag
gcry_mpi_set_flag.restype = None
gcry_mpi_set_flag.argtypes = [gcry_mpi_t, gcry_mpi_flag]
gcry_mpi_clear_flag = _libraries['libotr.so.2'].gcry_mpi_clear_flag
gcry_mpi_clear_flag.restype = None
gcry_mpi_clear_flag.argtypes = [gcry_mpi_t, gcry_mpi_flag]
gcry_mpi_get_flag = _libraries['libotr.so.2'].gcry_mpi_get_flag
gcry_mpi_get_flag.restype = c_int
gcry_mpi_get_flag.argtypes = [gcry_mpi_t, gcry_mpi_flag]
class gcry_cipher_handle(Structure):
    pass
gcry_cipher_handle._fields_ = [
]
gcry_cipher_hd_t = POINTER(gcry_cipher_handle)
GCRY_CIPHER_HD = POINTER(gcry_cipher_handle)
GcryCipherHd = POINTER(gcry_cipher_handle)

# values for enumeration 'gcry_cipher_algos'
gcry_cipher_algos = c_int # enum

# values for enumeration 'gcry_cipher_modes'
gcry_cipher_modes = c_int # enum

# values for enumeration 'gcry_cipher_flags'
gcry_cipher_flags = c_int # enum
gcry_cipher_open = _libraries['libotr.so.2'].gcry_cipher_open
gcry_cipher_open.restype = gcry_error_t
gcry_cipher_open.argtypes = [POINTER(gcry_cipher_hd_t), c_int, c_int, c_uint]
gcry_cipher_close = _libraries['libotr.so.2'].gcry_cipher_close
gcry_cipher_close.restype = None
gcry_cipher_close.argtypes = [gcry_cipher_hd_t]
gcry_cipher_ctl = _libraries['libotr.so.2'].gcry_cipher_ctl
gcry_cipher_ctl.restype = gcry_error_t
gcry_cipher_ctl.argtypes = [gcry_cipher_hd_t, c_int, c_void_p, size_t]
gcry_cipher_info = _libraries['libotr.so.2'].gcry_cipher_info
gcry_cipher_info.restype = gcry_error_t
gcry_cipher_info.argtypes = [gcry_cipher_hd_t, c_int, c_void_p, POINTER(size_t)]
gcry_cipher_algo_info = _libraries['libotr.so.2'].gcry_cipher_algo_info
gcry_cipher_algo_info.restype = gcry_error_t
gcry_cipher_algo_info.argtypes = [c_int, c_int, c_void_p, POINTER(size_t)]
gcry_cipher_algo_name = _libraries['libotr.so.2'].gcry_cipher_algo_name
gcry_cipher_algo_name.restype = STRING
gcry_cipher_algo_name.argtypes = [c_int]
gcry_cipher_map_name = _libraries['libotr.so.2'].gcry_cipher_map_name
gcry_cipher_map_name.restype = c_int
gcry_cipher_map_name.argtypes = [STRING]
gcry_cipher_mode_from_oid = _libraries['libotr.so.2'].gcry_cipher_mode_from_oid
gcry_cipher_mode_from_oid.restype = c_int
gcry_cipher_mode_from_oid.argtypes = [STRING]
gcry_cipher_encrypt = _libraries['libotr.so.2'].gcry_cipher_encrypt
gcry_cipher_encrypt.restype = gcry_error_t
gcry_cipher_encrypt.argtypes = [gcry_cipher_hd_t, c_void_p, size_t, c_void_p, size_t]
gcry_cipher_decrypt = _libraries['libotr.so.2'].gcry_cipher_decrypt
gcry_cipher_decrypt.restype = gcry_error_t
gcry_cipher_decrypt.argtypes = [gcry_cipher_hd_t, c_void_p, size_t, c_void_p, size_t]
gcry_cipher_get_algo_keylen = _libraries['libotr.so.2'].gcry_cipher_get_algo_keylen
gcry_cipher_get_algo_keylen.restype = size_t
gcry_cipher_get_algo_keylen.argtypes = [c_int]
gcry_cipher_get_algo_blklen = _libraries['libotr.so.2'].gcry_cipher_get_algo_blklen
gcry_cipher_get_algo_blklen.restype = size_t
gcry_cipher_get_algo_blklen.argtypes = [c_int]
gcry_cipher_list = _libraries['libotr.so.2'].gcry_cipher_list
gcry_cipher_list.restype = gcry_error_t
gcry_cipher_list.argtypes = [POINTER(c_int), POINTER(c_int)]

# values for enumeration 'gcry_pk_algos'
gcry_pk_algos = c_int # enum
gcry_pk_encrypt = _libraries['libotr.so.2'].gcry_pk_encrypt
gcry_pk_encrypt.restype = gcry_error_t
gcry_pk_encrypt.argtypes = [POINTER(gcry_sexp_t), gcry_sexp_t, gcry_sexp_t]
gcry_pk_decrypt = _libraries['libotr.so.2'].gcry_pk_decrypt
gcry_pk_decrypt.restype = gcry_error_t
gcry_pk_decrypt.argtypes = [POINTER(gcry_sexp_t), gcry_sexp_t, gcry_sexp_t]
gcry_pk_sign = _libraries['libotr.so.2'].gcry_pk_sign
gcry_pk_sign.restype = gcry_error_t
gcry_pk_sign.argtypes = [POINTER(gcry_sexp_t), gcry_sexp_t, gcry_sexp_t]
gcry_pk_verify = _libraries['libotr.so.2'].gcry_pk_verify
gcry_pk_verify.restype = gcry_error_t
gcry_pk_verify.argtypes = [gcry_sexp_t, gcry_sexp_t, gcry_sexp_t]
gcry_pk_testkey = _libraries['libotr.so.2'].gcry_pk_testkey
gcry_pk_testkey.restype = gcry_error_t
gcry_pk_testkey.argtypes = [gcry_sexp_t]
gcry_pk_genkey = _libraries['libotr.so.2'].gcry_pk_genkey
gcry_pk_genkey.restype = gcry_error_t
gcry_pk_genkey.argtypes = [POINTER(gcry_sexp_t), gcry_sexp_t]
gcry_pk_ctl = _libraries['libotr.so.2'].gcry_pk_ctl
gcry_pk_ctl.restype = gcry_error_t
gcry_pk_ctl.argtypes = [c_int, c_void_p, size_t]
gcry_pk_algo_info = _libraries['libotr.so.2'].gcry_pk_algo_info
gcry_pk_algo_info.restype = gcry_error_t
gcry_pk_algo_info.argtypes = [c_int, c_int, c_void_p, POINTER(size_t)]
gcry_pk_algo_name = _libraries['libotr.so.2'].gcry_pk_algo_name
gcry_pk_algo_name.restype = STRING
gcry_pk_algo_name.argtypes = [c_int]
gcry_pk_map_name = _libraries['libotr.so.2'].gcry_pk_map_name
gcry_pk_map_name.restype = c_int
gcry_pk_map_name.argtypes = [STRING]
gcry_pk_get_nbits = _libraries['libotr.so.2'].gcry_pk_get_nbits
gcry_pk_get_nbits.restype = c_uint
gcry_pk_get_nbits.argtypes = [gcry_sexp_t]
gcry_pk_get_keygrip = _libraries['libotr.so.2'].gcry_pk_get_keygrip
gcry_pk_get_keygrip.restype = POINTER(c_ubyte)
gcry_pk_get_keygrip.argtypes = [gcry_sexp_t, POINTER(c_ubyte)]
gcry_pk_list = _libraries['libotr.so.2'].gcry_pk_list
gcry_pk_list.restype = gcry_error_t
gcry_pk_list.argtypes = [POINTER(c_int), POINTER(c_int)]

# values for enumeration 'gcry_ac_id'
gcry_ac_id = c_int # enum
gcry_ac_id_t = gcry_ac_id

# values for enumeration 'gcry_ac_key_type'
gcry_ac_key_type = c_int # enum
gcry_ac_key_type_t = gcry_ac_key_type
class gcry_ac_data(Structure):
    pass
gcry_ac_data._fields_ = [
]
gcry_ac_data_t = POINTER(gcry_ac_data)
class gcry_ac_key(Structure):
    pass
gcry_ac_key_t = POINTER(gcry_ac_key)
gcry_ac_key._fields_ = [
]
class gcry_ac_key_pair(Structure):
    pass
gcry_ac_key_pair_t = POINTER(gcry_ac_key_pair)
gcry_ac_key_pair._fields_ = [
]
class gcry_ac_handle(Structure):
    pass
gcry_ac_handle_t = POINTER(gcry_ac_handle)
gcry_ac_handle._fields_ = [
]
class gcry_ac_key_spec_rsa(Structure):
    pass
gcry_ac_key_spec_rsa._fields_ = [
    ('e', gcry_mpi_t),
]
gcry_ac_key_spec_rsa_t = gcry_ac_key_spec_rsa
gcry_ac_data_new = _libraries['libotr.so.2'].gcry_ac_data_new
gcry_ac_data_new.restype = gcry_error_t
gcry_ac_data_new.argtypes = [POINTER(gcry_ac_data_t)]
gcry_ac_data_destroy = _libraries['libotr.so.2'].gcry_ac_data_destroy
gcry_ac_data_destroy.restype = None
gcry_ac_data_destroy.argtypes = [gcry_ac_data_t]
gcry_ac_data_copy = _libraries['libotr.so.2'].gcry_ac_data_copy
gcry_ac_data_copy.restype = gcry_error_t
gcry_ac_data_copy.argtypes = [POINTER(gcry_ac_data_t), gcry_ac_data_t]
gcry_ac_data_length = _libraries['libotr.so.2'].gcry_ac_data_length
gcry_ac_data_length.restype = c_uint
gcry_ac_data_length.argtypes = [gcry_ac_data_t]
gcry_ac_data_clear = _libraries['libotr.so.2'].gcry_ac_data_clear
gcry_ac_data_clear.restype = None
gcry_ac_data_clear.argtypes = [gcry_ac_data_t]
gcry_ac_data_set = _libraries['libotr.so.2'].gcry_ac_data_set
gcry_ac_data_set.restype = gcry_error_t
gcry_ac_data_set.argtypes = [gcry_ac_data_t, c_uint, STRING, gcry_mpi_t]
gcry_ac_data_get_name = _libraries['libotr.so.2'].gcry_ac_data_get_name
gcry_ac_data_get_name.restype = gcry_error_t
gcry_ac_data_get_name.argtypes = [gcry_ac_data_t, c_uint, STRING, POINTER(gcry_mpi_t)]
gcry_ac_data_get_index = _libraries['libotr.so.2'].gcry_ac_data_get_index
gcry_ac_data_get_index.restype = gcry_error_t
gcry_ac_data_get_index.argtypes = [gcry_ac_data_t, c_uint, c_uint, POINTER(STRING), POINTER(gcry_mpi_t)]
gcry_ac_open = _libraries['libotr.so.2'].gcry_ac_open
gcry_ac_open.restype = gcry_error_t
gcry_ac_open.argtypes = [POINTER(gcry_ac_handle_t), gcry_ac_id_t, c_uint]
gcry_ac_close = _libraries['libotr.so.2'].gcry_ac_close
gcry_ac_close.restype = None
gcry_ac_close.argtypes = [gcry_ac_handle_t]
gcry_ac_key_init = _libraries['libotr.so.2'].gcry_ac_key_init
gcry_ac_key_init.restype = gcry_error_t
gcry_ac_key_init.argtypes = [POINTER(gcry_ac_key_t), gcry_ac_handle_t, gcry_ac_key_type_t, gcry_ac_data_t]
gcry_ac_key_pair_generate = _libraries['libotr.so.2'].gcry_ac_key_pair_generate
gcry_ac_key_pair_generate.restype = gcry_error_t
gcry_ac_key_pair_generate.argtypes = [gcry_ac_handle_t, c_uint, c_void_p, POINTER(gcry_ac_key_pair_t), POINTER(POINTER(gcry_mpi_t))]
gcry_ac_key_pair_extract = _libraries['libotr.so.2'].gcry_ac_key_pair_extract
gcry_ac_key_pair_extract.restype = gcry_ac_key_t
gcry_ac_key_pair_extract.argtypes = [gcry_ac_key_pair_t, gcry_ac_key_type_t]
gcry_ac_key_data_get = _libraries['libotr.so.2'].gcry_ac_key_data_get
gcry_ac_key_data_get.restype = gcry_ac_data_t
gcry_ac_key_data_get.argtypes = [gcry_ac_key_t]
gcry_ac_key_test = _libraries['libotr.so.2'].gcry_ac_key_test
gcry_ac_key_test.restype = gcry_error_t
gcry_ac_key_test.argtypes = [gcry_ac_handle_t, gcry_ac_key_t]
gcry_ac_key_get_nbits = _libraries['libotr.so.2'].gcry_ac_key_get_nbits
gcry_ac_key_get_nbits.restype = gcry_error_t
gcry_ac_key_get_nbits.argtypes = [gcry_ac_handle_t, gcry_ac_key_t, POINTER(c_uint)]
gcry_ac_key_get_grip = _libraries['libotr.so.2'].gcry_ac_key_get_grip
gcry_ac_key_get_grip.restype = gcry_error_t
gcry_ac_key_get_grip.argtypes = [gcry_ac_handle_t, gcry_ac_key_t, POINTER(c_ubyte)]
gcry_ac_key_destroy = _libraries['libotr.so.2'].gcry_ac_key_destroy
gcry_ac_key_destroy.restype = None
gcry_ac_key_destroy.argtypes = [gcry_ac_key_t]
gcry_ac_key_pair_destroy = _libraries['libotr.so.2'].gcry_ac_key_pair_destroy
gcry_ac_key_pair_destroy.restype = None
gcry_ac_key_pair_destroy.argtypes = [gcry_ac_key_pair_t]
gcry_ac_data_encrypt = _libraries['libotr.so.2'].gcry_ac_data_encrypt
gcry_ac_data_encrypt.restype = gcry_error_t
gcry_ac_data_encrypt.argtypes = [gcry_ac_handle_t, c_uint, gcry_ac_key_t, gcry_mpi_t, POINTER(gcry_ac_data_t)]
gcry_ac_data_decrypt = _libraries['libotr.so.2'].gcry_ac_data_decrypt
gcry_ac_data_decrypt.restype = gcry_error_t
gcry_ac_data_decrypt.argtypes = [gcry_ac_handle_t, c_uint, gcry_ac_key_t, POINTER(gcry_mpi_t), gcry_ac_data_t]
gcry_ac_data_sign = _libraries['libotr.so.2'].gcry_ac_data_sign
gcry_ac_data_sign.restype = gcry_error_t
gcry_ac_data_sign.argtypes = [gcry_ac_handle_t, gcry_ac_key_t, gcry_mpi_t, POINTER(gcry_ac_data_t)]
gcry_ac_data_verify = _libraries['libotr.so.2'].gcry_ac_data_verify
gcry_ac_data_verify.restype = gcry_error_t
gcry_ac_data_verify.argtypes = [gcry_ac_handle_t, gcry_ac_key_t, gcry_mpi_t, gcry_ac_data_t]
gcry_ac_id_to_name = _libraries['libotr.so.2'].gcry_ac_id_to_name
gcry_ac_id_to_name.restype = gcry_error_t
gcry_ac_id_to_name.argtypes = [gcry_ac_id_t, POINTER(STRING)]
gcry_ac_name_to_id = _libraries['libotr.so.2'].gcry_ac_name_to_id
gcry_ac_name_to_id.restype = gcry_error_t
gcry_ac_name_to_id.argtypes = [STRING, POINTER(gcry_ac_id_t)]

# values for enumeration 'gcry_md_algos'
gcry_md_algos = c_int # enum

# values for enumeration 'gcry_md_flags'
gcry_md_flags = c_int # enum
class gcry_md_context(Structure):
    pass
gcry_md_context._fields_ = [
]
class gcry_md_handle(Structure):
    pass
gcry_md_handle._fields_ = [
    ('ctx', POINTER(gcry_md_context)),
    ('bufpos', c_int),
    ('bufsize', c_int),
    ('buf', c_ubyte * 1),
]
gcry_md_hd_t = POINTER(gcry_md_handle)
GCRY_MD_HD = POINTER(gcry_md_handle)
GcryMDHd = POINTER(gcry_md_handle)
gcry_md_open = _libraries['libotr.so.2'].gcry_md_open
gcry_md_open.restype = gcry_error_t
gcry_md_open.argtypes = [POINTER(gcry_md_hd_t), c_int, c_uint]
gcry_md_close = _libraries['libotr.so.2'].gcry_md_close
gcry_md_close.restype = None
gcry_md_close.argtypes = [gcry_md_hd_t]
gcry_md_enable = _libraries['libotr.so.2'].gcry_md_enable
gcry_md_enable.restype = gcry_error_t
gcry_md_enable.argtypes = [gcry_md_hd_t, c_int]
gcry_md_copy = _libraries['libotr.so.2'].gcry_md_copy
gcry_md_copy.restype = gcry_error_t
gcry_md_copy.argtypes = [POINTER(gcry_md_hd_t), gcry_md_hd_t]
gcry_md_reset = _libraries['libotr.so.2'].gcry_md_reset
gcry_md_reset.restype = None
gcry_md_reset.argtypes = [gcry_md_hd_t]
gcry_md_ctl = _libraries['libotr.so.2'].gcry_md_ctl
gcry_md_ctl.restype = gcry_error_t
gcry_md_ctl.argtypes = [gcry_md_hd_t, c_int, c_void_p, size_t]
gcry_md_write = _libraries['libotr.so.2'].gcry_md_write
gcry_md_write.restype = None
gcry_md_write.argtypes = [gcry_md_hd_t, c_void_p, size_t]
gcry_md_read = _libraries['libotr.so.2'].gcry_md_read
gcry_md_read.restype = POINTER(c_ubyte)
gcry_md_read.argtypes = [gcry_md_hd_t, c_int]
gcry_md_hash_buffer = _libraries['libotr.so.2'].gcry_md_hash_buffer
gcry_md_hash_buffer.restype = None
gcry_md_hash_buffer.argtypes = [c_int, c_void_p, c_void_p, size_t]
gcry_md_get_algo = _libraries['libotr.so.2'].gcry_md_get_algo
gcry_md_get_algo.restype = c_int
gcry_md_get_algo.argtypes = [gcry_md_hd_t]
gcry_md_get_algo_dlen = _libraries['libotr.so.2'].gcry_md_get_algo_dlen
gcry_md_get_algo_dlen.restype = c_uint
gcry_md_get_algo_dlen.argtypes = [c_int]
gcry_md_is_enabled = _libraries['libotr.so.2'].gcry_md_is_enabled
gcry_md_is_enabled.restype = c_int
gcry_md_is_enabled.argtypes = [gcry_md_hd_t, c_int]
gcry_md_is_secure = _libraries['libotr.so.2'].gcry_md_is_secure
gcry_md_is_secure.restype = c_int
gcry_md_is_secure.argtypes = [gcry_md_hd_t]
gcry_md_info = _libraries['libotr.so.2'].gcry_md_info
gcry_md_info.restype = gcry_error_t
gcry_md_info.argtypes = [gcry_md_hd_t, c_int, c_void_p, POINTER(size_t)]
gcry_md_algo_info = _libraries['libotr.so.2'].gcry_md_algo_info
gcry_md_algo_info.restype = gcry_error_t
gcry_md_algo_info.argtypes = [c_int, c_int, c_void_p, POINTER(size_t)]
gcry_md_algo_name = _libraries['libotr.so.2'].gcry_md_algo_name
gcry_md_algo_name.restype = STRING
gcry_md_algo_name.argtypes = [c_int]
gcry_md_map_name = _libraries['libotr.so.2'].gcry_md_map_name
gcry_md_map_name.restype = c_int
gcry_md_map_name.argtypes = [STRING]
gcry_md_setkey = _libraries['libotr.so.2'].gcry_md_setkey
gcry_md_setkey.restype = gcry_error_t
gcry_md_setkey.argtypes = [gcry_md_hd_t, c_void_p, size_t]
gcry_md_list = _libraries['libotr.so.2'].gcry_md_list
gcry_md_list.restype = gcry_error_t
gcry_md_list.argtypes = [POINTER(c_int), POINTER(c_int)]

# values for enumeration 'gcry_random_level'
gcry_random_level = c_int # enum
gcry_random_level_t = gcry_random_level
gcry_randomize = _libraries['libotr.so.2'].gcry_randomize
gcry_randomize.restype = None
gcry_randomize.argtypes = [c_void_p, size_t, gcry_random_level]
gcry_random_add_bytes = _libraries['libotr.so.2'].gcry_random_add_bytes
gcry_random_add_bytes.restype = gcry_error_t
gcry_random_add_bytes.argtypes = [c_void_p, size_t, c_int]
gcry_random_bytes = _libraries['libotr.so.2'].gcry_random_bytes
gcry_random_bytes.restype = c_void_p
gcry_random_bytes.argtypes = [size_t, gcry_random_level]
gcry_random_bytes_secure = _libraries['libotr.so.2'].gcry_random_bytes_secure
gcry_random_bytes_secure.restype = c_void_p
gcry_random_bytes_secure.argtypes = [size_t, gcry_random_level]
gcry_mpi_randomize = _libraries['libotr.so.2'].gcry_mpi_randomize
gcry_mpi_randomize.restype = None
gcry_mpi_randomize.argtypes = [gcry_mpi_t, c_uint, gcry_random_level]
gcry_create_nonce = _libraries['libotr.so.2'].gcry_create_nonce
gcry_create_nonce.restype = None
gcry_create_nonce.argtypes = [c_void_p, size_t]
gcry_prime_check_func_t = CFUNCTYPE(c_int, c_void_p, c_int, POINTER(gcry_mpi))
gcry_prime_generate = _libraries['libotr.so.2'].gcry_prime_generate
gcry_prime_generate.restype = gcry_error_t
gcry_prime_generate.argtypes = [POINTER(gcry_mpi_t), c_uint, c_uint, POINTER(POINTER(gcry_mpi_t)), gcry_prime_check_func_t, c_void_p, gcry_random_level_t, c_uint]
gcry_prime_group_generator = _libraries['libotr.so.2'].gcry_prime_group_generator
gcry_prime_group_generator.restype = gcry_error_t
gcry_prime_group_generator.argtypes = [POINTER(gcry_mpi_t), gcry_mpi_t, POINTER(gcry_mpi_t), gcry_mpi_t]
gcry_prime_release_factors = _libraries['libotr.so.2'].gcry_prime_release_factors
gcry_prime_release_factors.restype = None
gcry_prime_release_factors.argtypes = [POINTER(gcry_mpi_t)]
gcry_prime_check = _libraries['libotr.so.2'].gcry_prime_check
gcry_prime_check.restype = gcry_error_t
gcry_prime_check.argtypes = [gcry_mpi_t, c_uint]

# values for enumeration 'gcry_log_levels'
gcry_log_levels = c_int # enum
gcry_handler_progress_t = CFUNCTYPE(None, c_void_p, STRING, c_int, c_int, c_int)
gcry_handler_alloc_t = CFUNCTYPE(c_void_p, c_uint)
gcry_handler_secure_check_t = CFUNCTYPE(c_int, c_void_p)
gcry_handler_realloc_t = CFUNCTYPE(c_void_p, c_void_p, c_uint)
gcry_handler_free_t = CFUNCTYPE(None, c_void_p)
gcry_handler_no_mem_t = CFUNCTYPE(c_int, c_void_p, c_uint, c_uint)
gcry_handler_error_t = CFUNCTYPE(None, c_void_p, c_int, STRING)
gcry_handler_log_t = CFUNCTYPE(None, c_void_p, c_int, STRING, STRING)
gcry_set_progress_handler = _libraries['libotr.so.2'].gcry_set_progress_handler
gcry_set_progress_handler.restype = None
gcry_set_progress_handler.argtypes = [gcry_handler_progress_t, c_void_p]
gcry_set_allocation_handler = _libraries['libotr.so.2'].gcry_set_allocation_handler
gcry_set_allocation_handler.restype = None
gcry_set_allocation_handler.argtypes = [gcry_handler_alloc_t, gcry_handler_alloc_t, gcry_handler_secure_check_t, gcry_handler_realloc_t, gcry_handler_free_t]
gcry_set_outofcore_handler = _libraries['libotr.so.2'].gcry_set_outofcore_handler
gcry_set_outofcore_handler.restype = None
gcry_set_outofcore_handler.argtypes = [gcry_handler_no_mem_t, c_void_p]
gcry_set_fatalerror_handler = _libraries['libotr.so.2'].gcry_set_fatalerror_handler
gcry_set_fatalerror_handler.restype = None
gcry_set_fatalerror_handler.argtypes = [gcry_handler_error_t, c_void_p]
gcry_set_log_handler = _libraries['libotr.so.2'].gcry_set_log_handler
gcry_set_log_handler.restype = None
gcry_set_log_handler.argtypes = [gcry_handler_log_t, c_void_p]
gcry_set_gettext_handler = _libraries['libotr.so.2'].gcry_set_gettext_handler
gcry_set_gettext_handler.restype = None
gcry_set_gettext_handler.argtypes = [CFUNCTYPE(STRING, STRING)]
gcry_malloc = _libraries['libotr.so.2'].gcry_malloc
gcry_malloc.restype = c_void_p
gcry_malloc.argtypes = [size_t]
gcry_calloc = _libraries['libotr.so.2'].gcry_calloc
gcry_calloc.restype = c_void_p
gcry_calloc.argtypes = [size_t, size_t]
gcry_malloc_secure = _libraries['libotr.so.2'].gcry_malloc_secure
gcry_malloc_secure.restype = c_void_p
gcry_malloc_secure.argtypes = [size_t]
gcry_calloc_secure = _libraries['libotr.so.2'].gcry_calloc_secure
gcry_calloc_secure.restype = c_void_p
gcry_calloc_secure.argtypes = [size_t, size_t]
gcry_realloc = _libraries['libotr.so.2'].gcry_realloc
gcry_realloc.restype = c_void_p
gcry_realloc.argtypes = [c_void_p, size_t]
gcry_strdup = _libraries['libotr.so.2'].gcry_strdup
gcry_strdup.restype = STRING
gcry_strdup.argtypes = [STRING]
gcry_xmalloc = _libraries['libotr.so.2'].gcry_xmalloc
gcry_xmalloc.restype = c_void_p
gcry_xmalloc.argtypes = [size_t]
gcry_xcalloc = _libraries['libotr.so.2'].gcry_xcalloc
gcry_xcalloc.restype = c_void_p
gcry_xcalloc.argtypes = [size_t, size_t]
gcry_xmalloc_secure = _libraries['libotr.so.2'].gcry_xmalloc_secure
gcry_xmalloc_secure.restype = c_void_p
gcry_xmalloc_secure.argtypes = [size_t]
gcry_xcalloc_secure = _libraries['libotr.so.2'].gcry_xcalloc_secure
gcry_xcalloc_secure.restype = c_void_p
gcry_xcalloc_secure.argtypes = [size_t, size_t]
gcry_xrealloc = _libraries['libotr.so.2'].gcry_xrealloc
gcry_xrealloc.restype = c_void_p
gcry_xrealloc.argtypes = [c_void_p, size_t]
gcry_xstrdup = _libraries['libotr.so.2'].gcry_xstrdup
gcry_xstrdup.restype = STRING
gcry_xstrdup.argtypes = [STRING]
gcry_free = _libraries['libotr.so.2'].gcry_free
gcry_free.restype = None
gcry_free.argtypes = [c_void_p]
gcry_is_secure = _libraries['libotr.so.2'].gcry_is_secure
gcry_is_secure.restype = c_int
gcry_is_secure.argtypes = [c_void_p]
gpg_strerror = _libraries['libotr.so.2'].gpg_strerror
gpg_strerror.restype = STRING
gpg_strerror.argtypes = [gpg_error_t]
gpg_strerror_r = _libraries['libotr.so.2'].gpg_strerror_r
gpg_strerror_r.restype = c_int
gpg_strerror_r.argtypes = [gpg_error_t, STRING, size_t]
gpg_strsource = _libraries['libotr.so.2'].gpg_strsource
gpg_strsource.restype = STRING
gpg_strsource.argtypes = [gpg_error_t]
gpg_err_code_from_errno = _libraries['libotr.so.2'].gpg_err_code_from_errno
gpg_err_code_from_errno.restype = gpg_err_code_t
gpg_err_code_from_errno.argtypes = [c_int]
gpg_err_code_to_errno = _libraries['libotr.so.2'].gpg_err_code_to_errno
gpg_err_code_to_errno.restype = c_int
gpg_err_code_to_errno.argtypes = [gpg_err_code_t]
memcpy = _libraries['libotr.so.2'].memcpy
memcpy.restype = c_void_p
memcpy.argtypes = [c_void_p, c_void_p, size_t]
memmove = _libraries['libotr.so.2'].memmove
memmove.restype = c_void_p
memmove.argtypes = [c_void_p, c_void_p, size_t]
memccpy = _libraries['libotr.so.2'].memccpy
memccpy.restype = c_void_p
memccpy.argtypes = [c_void_p, c_void_p, c_int, size_t]
memset = _libraries['libotr.so.2'].memset
memset.restype = c_void_p
memset.argtypes = [c_void_p, c_int, size_t]
memcmp = _libraries['libotr.so.2'].memcmp
memcmp.restype = c_int
memcmp.argtypes = [c_void_p, c_void_p, size_t]
memchr = _libraries['libotr.so.2'].memchr
memchr.restype = c_void_p
memchr.argtypes = [c_void_p, c_int, size_t]
rawmemchr = _libraries['libotr.so.2'].rawmemchr
rawmemchr.restype = c_void_p
rawmemchr.argtypes = [c_void_p, c_int]
memrchr = _libraries['libotr.so.2'].memrchr
memrchr.restype = c_void_p
memrchr.argtypes = [c_void_p, c_int, size_t]
strcpy = _libraries['libotr.so.2'].strcpy
strcpy.restype = STRING
strcpy.argtypes = [STRING, STRING]
strncpy = _libraries['libotr.so.2'].strncpy
strncpy.restype = STRING
strncpy.argtypes = [STRING, STRING, size_t]
strcat = _libraries['libotr.so.2'].strcat
strcat.restype = STRING
strcat.argtypes = [STRING, STRING]
strncat = _libraries['libotr.so.2'].strncat
strncat.restype = STRING
strncat.argtypes = [STRING, STRING, size_t]
strcmp = _libraries['libotr.so.2'].strcmp
strcmp.restype = c_int
strcmp.argtypes = [STRING, STRING]
strncmp = _libraries['libotr.so.2'].strncmp
strncmp.restype = c_int
strncmp.argtypes = [STRING, STRING, size_t]
strcoll = _libraries['libotr.so.2'].strcoll
strcoll.restype = c_int
strcoll.argtypes = [STRING, STRING]
strxfrm = _libraries['libotr.so.2'].strxfrm
strxfrm.restype = size_t
strxfrm.argtypes = [STRING, STRING, size_t]
class __locale_struct(Structure):
    pass
__locale_t = POINTER(__locale_struct)
strcoll_l = _libraries['libotr.so.2'].strcoll_l
strcoll_l.restype = c_int
strcoll_l.argtypes = [STRING, STRING, __locale_t]
strxfrm_l = _libraries['libotr.so.2'].strxfrm_l
strxfrm_l.restype = size_t
strxfrm_l.argtypes = [STRING, STRING, size_t, __locale_t]
strdup = _libraries['libotr.so.2'].strdup
strdup.restype = STRING
strdup.argtypes = [STRING]
strndup = _libraries['libotr.so.2'].strndup
strndup.restype = STRING
strndup.argtypes = [STRING, size_t]
strchr = _libraries['libotr.so.2'].strchr
strchr.restype = STRING
strchr.argtypes = [STRING, c_int]
strrchr = _libraries['libotr.so.2'].strrchr
strrchr.restype = STRING
strrchr.argtypes = [STRING, c_int]
strchrnul = _libraries['libotr.so.2'].strchrnul
strchrnul.restype = STRING
strchrnul.argtypes = [STRING, c_int]
strcspn = _libraries['libotr.so.2'].strcspn
strcspn.restype = size_t
strcspn.argtypes = [STRING, STRING]
strspn = _libraries['libotr.so.2'].strspn
strspn.restype = size_t
strspn.argtypes = [STRING, STRING]
strpbrk = _libraries['libotr.so.2'].strpbrk
strpbrk.restype = STRING
strpbrk.argtypes = [STRING, STRING]
strstr = _libraries['libotr.so.2'].strstr
strstr.restype = STRING
strstr.argtypes = [STRING, STRING]
strtok = _libraries['libotr.so.2'].strtok
strtok.restype = STRING
strtok.argtypes = [STRING, STRING]
__strtok_r = _libraries['libotr.so.2'].__strtok_r
__strtok_r.restype = STRING
__strtok_r.argtypes = [STRING, STRING, POINTER(STRING)]
strtok_r = _libraries['libotr.so.2'].strtok_r
strtok_r.restype = STRING
strtok_r.argtypes = [STRING, STRING, POINTER(STRING)]
strcasestr = _libraries['libotr.so.2'].strcasestr
strcasestr.restype = STRING
strcasestr.argtypes = [STRING, STRING]
memmem = _libraries['libotr.so.2'].memmem
memmem.restype = c_void_p
memmem.argtypes = [c_void_p, size_t, c_void_p, size_t]
__mempcpy = _libraries['libotr.so.2'].__mempcpy
__mempcpy.restype = c_void_p
__mempcpy.argtypes = [c_void_p, c_void_p, size_t]
mempcpy = _libraries['libotr.so.2'].mempcpy
mempcpy.restype = c_void_p
mempcpy.argtypes = [c_void_p, c_void_p, size_t]
strlen = _libraries['libotr.so.2'].strlen
strlen.restype = size_t
strlen.argtypes = [STRING]
strnlen = _libraries['libotr.so.2'].strnlen
strnlen.restype = size_t
strnlen.argtypes = [STRING, size_t]
strerror = _libraries['libotr.so.2'].strerror
strerror.restype = STRING
strerror.argtypes = [c_int]
strerror_r = _libraries['libotr.so.2'].strerror_r
strerror_r.restype = STRING
strerror_r.argtypes = [c_int, STRING, size_t]
__bzero = _libraries['libotr.so.2'].__bzero
__bzero.restype = None
__bzero.argtypes = [c_void_p, size_t]
bcopy = _libraries['libotr.so.2'].bcopy
bcopy.restype = None
bcopy.argtypes = [c_void_p, c_void_p, size_t]
bzero = _libraries['libotr.so.2'].bzero
bzero.restype = None
bzero.argtypes = [c_void_p, size_t]
bcmp = _libraries['libotr.so.2'].bcmp
bcmp.restype = c_int
bcmp.argtypes = [c_void_p, c_void_p, size_t]
index = _libraries['libotr.so.2'].index
index.restype = STRING
index.argtypes = [STRING, c_int]
rindex = _libraries['libotr.so.2'].rindex
rindex.restype = STRING
rindex.argtypes = [STRING, c_int]
ffs = _libraries['libotr.so.2'].ffs
ffs.restype = c_int
ffs.argtypes = [c_int]
ffsl = _libraries['libotr.so.2'].ffsl
ffsl.restype = c_int
ffsl.argtypes = [c_long]
ffsll = _libraries['libotr.so.2'].ffsll
ffsll.restype = c_int
ffsll.argtypes = [c_longlong]
strcasecmp = _libraries['libotr.so.2'].strcasecmp
strcasecmp.restype = c_int
strcasecmp.argtypes = [STRING, STRING]
strncasecmp = _libraries['libotr.so.2'].strncasecmp
strncasecmp.restype = c_int
strncasecmp.argtypes = [STRING, STRING, size_t]
strcasecmp_l = _libraries['libotr.so.2'].strcasecmp_l
strcasecmp_l.restype = c_int
strcasecmp_l.argtypes = [STRING, STRING, __locale_t]
strncasecmp_l = _libraries['libotr.so.2'].strncasecmp_l
strncasecmp_l.restype = c_int
strncasecmp_l.argtypes = [STRING, STRING, size_t, __locale_t]
strsep = _libraries['libotr.so.2'].strsep
strsep.restype = STRING
strsep.argtypes = [POINTER(STRING), STRING]
strverscmp = _libraries['libotr.so.2'].strverscmp
strverscmp.restype = c_int
strverscmp.argtypes = [STRING, STRING]
strsignal = _libraries['libotr.so.2'].strsignal
strsignal.restype = STRING
strsignal.argtypes = [c_int]
__stpcpy = _libraries['libotr.so.2'].__stpcpy
__stpcpy.restype = STRING
__stpcpy.argtypes = [STRING, STRING]
stpcpy = _libraries['libotr.so.2'].stpcpy
stpcpy.restype = STRING
stpcpy.argtypes = [STRING, STRING]
__stpncpy = _libraries['libotr.so.2'].__stpncpy
__stpncpy.restype = STRING
__stpncpy.argtypes = [STRING, STRING, size_t]
stpncpy = _libraries['libotr.so.2'].stpncpy
stpncpy.restype = STRING
stpncpy.argtypes = [STRING, STRING, size_t]
strfry = _libraries['libotr.so.2'].strfry
strfry.restype = STRING
strfry.argtypes = [STRING]
memfrob = _libraries['libotr.so.2'].memfrob
memfrob.restype = c_void_p
memfrob.argtypes = [c_void_p, size_t]
basename = _libraries['libotr.so.2'].basename
basename.restype = STRING
basename.argtypes = [STRING]
sigset_t = __sigset_t
fd_mask = __fd_mask
select = _libraries['libotr.so.2'].select
select.restype = c_int
select.argtypes = [c_int, POINTER(fd_set), POINTER(fd_set), POINTER(fd_set), POINTER(timeval)]
class timespec(Structure):
    pass
timespec._fields_ = [
    ('tv_sec', __time_t),
    ('tv_nsec', c_long),
]
pselect = _libraries['libotr.so.2'].pselect
pselect.restype = c_int
pselect.argtypes = [c_int, POINTER(fd_set), POINTER(fd_set), POINTER(fd_set), POINTER(timespec), POINTER(__sigset_t)]
class osockaddr(Structure):
    pass
osockaddr._fields_ = [
    ('sa_family', c_ushort),
    ('sa_data', c_ubyte * 14),
]

# values for unnamed enumeration
socket = _libraries['libotr.so.2'].socket
socket.restype = c_int
socket.argtypes = [c_int, c_int, c_int]
socketpair = _libraries['libotr.so.2'].socketpair
socketpair.restype = c_int
socketpair.argtypes = [c_int, c_int, c_int, POINTER(c_int)]
bind = _libraries['libotr.so.2'].bind
bind.restype = c_int
bind.argtypes = [c_int, POINTER(sockaddr), socklen_t]
getsockname = _libraries['libotr.so.2'].getsockname
getsockname.restype = c_int
getsockname.argtypes = [c_int, POINTER(sockaddr), POINTER(socklen_t)]
connect = _libraries['libotr.so.2'].connect
connect.restype = c_int
connect.argtypes = [c_int, POINTER(sockaddr), socklen_t]
getpeername = _libraries['libotr.so.2'].getpeername
getpeername.restype = c_int
getpeername.argtypes = [c_int, POINTER(sockaddr), POINTER(socklen_t)]
send = _libraries['libotr.so.2'].send
send.restype = ssize_t
send.argtypes = [c_int, c_void_p, size_t, c_int]
recv = _libraries['libotr.so.2'].recv
recv.restype = ssize_t
recv.argtypes = [c_int, c_void_p, size_t, c_int]
sendto = _libraries['libotr.so.2'].sendto
sendto.restype = ssize_t
sendto.argtypes = [c_int, c_void_p, size_t, c_int, POINTER(sockaddr), socklen_t]
recvfrom = _libraries['libotr.so.2'].recvfrom
recvfrom.restype = ssize_t
recvfrom.argtypes = [c_int, c_void_p, size_t, c_int, POINTER(sockaddr), POINTER(socklen_t)]
sendmsg = _libraries['libotr.so.2'].sendmsg
sendmsg.restype = ssize_t
sendmsg.argtypes = [c_int, POINTER(msghdr), c_int]
recvmsg = _libraries['libotr.so.2'].recvmsg
recvmsg.restype = ssize_t
recvmsg.argtypes = [c_int, POINTER(msghdr), c_int]
getsockopt = _libraries['libotr.so.2'].getsockopt
getsockopt.restype = c_int
getsockopt.argtypes = [c_int, c_int, c_int, c_void_p, POINTER(socklen_t)]
setsockopt = _libraries['libotr.so.2'].setsockopt
setsockopt.restype = c_int
setsockopt.argtypes = [c_int, c_int, c_int, c_void_p, socklen_t]
listen = _libraries['libotr.so.2'].listen
listen.restype = c_int
listen.argtypes = [c_int, c_int]
accept = _libraries['libotr.so.2'].accept
accept.restype = c_int
accept.argtypes = [c_int, POINTER(sockaddr), POINTER(socklen_t)]
shutdown = _libraries['libotr.so.2'].shutdown
shutdown.restype = c_int
shutdown.argtypes = [c_int, c_int]
sockatmark = _libraries['libotr.so.2'].sockatmark
sockatmark.restype = c_int
sockatmark.argtypes = [c_int]
isfdtype = _libraries['libotr.so.2'].isfdtype
isfdtype.restype = c_int
isfdtype.argtypes = [c_int, c_int]
gnu_dev_major = _libraries['libotr.so.2'].gnu_dev_major
gnu_dev_major.restype = c_uint
gnu_dev_major.argtypes = [c_ulonglong]
gnu_dev_minor = _libraries['libotr.so.2'].gnu_dev_minor
gnu_dev_minor.restype = c_uint
gnu_dev_minor.argtypes = [c_ulonglong]
gnu_dev_makedev = _libraries['libotr.so.2'].gnu_dev_makedev
gnu_dev_makedev.restype = c_ulonglong
gnu_dev_makedev.argtypes = [c_uint, c_uint]
class timezone(Structure):
    pass
timezone._fields_ = [
    ('tz_minuteswest', c_int),
    ('tz_dsttime', c_int),
]
__timezone_ptr_t = POINTER(timezone)
gettimeofday = _libraries['libotr.so.2'].gettimeofday
gettimeofday.restype = c_int
gettimeofday.argtypes = [POINTER(timeval), __timezone_ptr_t]
settimeofday = _libraries['libotr.so.2'].settimeofday
settimeofday.restype = c_int
settimeofday.argtypes = [POINTER(timeval), POINTER(timezone)]
adjtime = _libraries['libotr.so.2'].adjtime
adjtime.restype = c_int
adjtime.argtypes = [POINTER(timeval), POINTER(timeval)]

# values for enumeration '__itimer_which'
__itimer_which = c_int # enum
class itimerval(Structure):
    pass
itimerval._fields_ = [
    ('it_interval', timeval),
    ('it_value', timeval),
]
__itimer_which_t = c_int
getitimer = _libraries['libotr.so.2'].getitimer
getitimer.restype = c_int
getitimer.argtypes = [__itimer_which_t, POINTER(itimerval)]
setitimer = _libraries['libotr.so.2'].setitimer
setitimer.restype = c_int
setitimer.argtypes = [__itimer_which_t, POINTER(itimerval), POINTER(itimerval)]
utimes = _libraries['libotr.so.2'].utimes
utimes.restype = c_int
utimes.argtypes = [STRING, POINTER(timeval)]
lutimes = _libraries['libotr.so.2'].lutimes
lutimes.restype = c_int
lutimes.argtypes = [STRING, POINTER(timeval)]
futimes = _libraries['libotr.so.2'].futimes
futimes.restype = c_int
futimes.argtypes = [c_int, POINTER(timeval)]
u_char = __u_char
u_short = __u_short
u_int = __u_int
u_long = __u_long
quad_t = __quad_t
u_quad_t = __u_quad_t
fsid_t = __fsid_t
loff_t = __loff_t
ino_t = __ino_t
ino64_t = __ino64_t
dev_t = __dev_t
mode_t = __mode_t
nlink_t = __nlink_t
off_t = __off_t
off64_t = __off64_t
id_t = __id_t
daddr_t = __daddr_t
caddr_t = __caddr_t
key_t = __key_t
useconds_t = __useconds_t
suseconds_t = __suseconds_t
ulong = c_ulong
ushort = c_ushort
uint = c_uint
int8_t = c_byte
int16_t = c_short
int32_t = c_int
int64_t = c_longlong
u_int8_t = c_ubyte
u_int16_t = c_ushort
u_int32_t = c_uint
u_int64_t = c_ulonglong
register_t = c_int
blksize_t = __blksize_t
blkcnt_t = __blkcnt_t
fsblkcnt_t = __fsblkcnt_t
fsfilcnt_t = __fsfilcnt_t
blkcnt64_t = __blkcnt64_t
fsblkcnt64_t = __fsblkcnt64_t
fsfilcnt64_t = __fsfilcnt64_t
readv = _libraries['libotr.so.2'].readv
readv.restype = ssize_t
readv.argtypes = [c_int, POINTER(iovec), c_int]
writev = _libraries['libotr.so.2'].writev
writev.restype = ssize_t
writev.argtypes = [c_int, POINTER(iovec), c_int]
clock_t = __clock_t
time_t = __time_t
clockid_t = __clockid_t
timer_t = __timer_t
class locale_data(Structure):
    pass
__locale_struct._fields_ = [
    ('__locales', POINTER(locale_data) * 13),
    ('__ctype_b', POINTER(c_ushort)),
    ('__ctype_tolower', POINTER(c_int)),
    ('__ctype_toupper', POINTER(c_int)),
    ('__names', STRING * 13),
]
locale_data._fields_ = [
]
__gnuc_va_list = STRING
va_list = __gnuc_va_list
ptrdiff_t = c_int

# values for enumeration 'OtrlAuthState'
OtrlAuthState = c_int # enum
class OtrlAuthInfo(Structure):
    pass
class DH_keypair(Structure):
    pass
DH_keypair._fields_ = [
    ('groupid', c_uint),
    ('priv', gcry_mpi_t),
    ('pub', gcry_mpi_t),
]

# values for enumeration 'OtrlSessionIdHalf'
OtrlSessionIdHalf = c_int # enum
OtrlAuthInfo._fields_ = [
    ('authstate', OtrlAuthState),
    ('our_dh', DH_keypair),
    ('our_keyid', c_uint),
    ('encgx', POINTER(c_ubyte)),
    ('encgx_len', size_t),
    ('r', c_ubyte * 16),
    ('hashgx', c_ubyte * 32),
    ('their_pub', gcry_mpi_t),
    ('their_keyid', c_uint),
    ('enc_c', gcry_cipher_hd_t),
    ('enc_cp', gcry_cipher_hd_t),
    ('mac_m1', gcry_md_hd_t),
    ('mac_m1p', gcry_md_hd_t),
    ('mac_m2', gcry_md_hd_t),
    ('mac_m2p', gcry_md_hd_t),
    ('their_fingerprint', c_ubyte * 20),
    ('initiated', c_int),
    ('protocol_version', c_uint),
    ('secure_session_id', c_ubyte * 20),
    ('secure_session_id_len', size_t),
    ('session_id_half', OtrlSessionIdHalf),
    ('lastauthmsg', STRING),
]
otrl_auth_new = _libraries['libotr.so.2'].otrl_auth_new
otrl_auth_new.restype = None
otrl_auth_new.argtypes = [POINTER(OtrlAuthInfo)]
otrl_auth_clear = _libraries['libotr.so.2'].otrl_auth_clear
otrl_auth_clear.restype = None
otrl_auth_clear.argtypes = [POINTER(OtrlAuthInfo)]
otrl_auth_start_v2 = _libraries['libotr.so.2'].otrl_auth_start_v2
otrl_auth_start_v2.restype = gcry_error_t
otrl_auth_start_v2.argtypes = [POINTER(OtrlAuthInfo)]
otrl_auth_handle_commit = _libraries['libotr.so.2'].otrl_auth_handle_commit
otrl_auth_handle_commit.restype = gcry_error_t
otrl_auth_handle_commit.argtypes = [POINTER(OtrlAuthInfo), STRING]
class s_OtrlPrivKey(Structure):
    pass
OtrlPrivKey = s_OtrlPrivKey
otrl_auth_handle_key = _libraries['libotr.so.2'].otrl_auth_handle_key
otrl_auth_handle_key.restype = gcry_error_t
otrl_auth_handle_key.argtypes = [POINTER(OtrlAuthInfo), STRING, POINTER(c_int), POINTER(OtrlPrivKey)]
otrl_auth_handle_revealsig = _libraries['libotr.so.2'].otrl_auth_handle_revealsig
otrl_auth_handle_revealsig.restype = gcry_error_t
otrl_auth_handle_revealsig.argtypes = [POINTER(OtrlAuthInfo), STRING, POINTER(c_int), POINTER(OtrlPrivKey), CFUNCTYPE(gcry_error_t, POINTER(OtrlAuthInfo), c_void_p), c_void_p]
otrl_auth_handle_signature = _libraries['libotr.so.2'].otrl_auth_handle_signature
otrl_auth_handle_signature.restype = gcry_error_t
otrl_auth_handle_signature.argtypes = [POINTER(OtrlAuthInfo), STRING, POINTER(c_int), CFUNCTYPE(gcry_error_t, POINTER(OtrlAuthInfo), c_void_p), c_void_p]
otrl_auth_start_v1 = _libraries['libotr.so.2'].otrl_auth_start_v1
otrl_auth_start_v1.restype = gcry_error_t
otrl_auth_start_v1.argtypes = [POINTER(OtrlAuthInfo), POINTER(DH_keypair), c_uint, POINTER(OtrlPrivKey)]
otrl_auth_handle_v1_key_exchange = _libraries['libotr.so.2'].otrl_auth_handle_v1_key_exchange
otrl_auth_handle_v1_key_exchange.restype = gcry_error_t
otrl_auth_handle_v1_key_exchange.argtypes = [POINTER(OtrlAuthInfo), STRING, POINTER(c_int), POINTER(OtrlPrivKey), POINTER(DH_keypair), c_uint, CFUNCTYPE(gcry_error_t, POINTER(OtrlAuthInfo), c_void_p), c_void_p]
otrl_base64_encode = _libraries['libotr.so.2'].otrl_base64_encode
otrl_base64_encode.restype = size_t
otrl_base64_encode.argtypes = [STRING, POINTER(c_ubyte), size_t]
otrl_base64_decode = _libraries['libotr.so.2'].otrl_base64_decode
otrl_base64_decode.restype = size_t
otrl_base64_decode.argtypes = [STRING, POINTER(c_ubyte), size_t]
otrl_base64_otr_encode = _libraries['libotr.so.2'].otrl_base64_otr_encode
otrl_base64_otr_encode.restype = STRING
otrl_base64_otr_encode.argtypes = [POINTER(c_ubyte), size_t]
otrl_base64_otr_decode = _libraries['libotr.so.2'].otrl_base64_otr_decode
otrl_base64_otr_decode.restype = c_int
otrl_base64_otr_decode.argtypes = [STRING, POINTER(POINTER(c_ubyte)), POINTER(size_t)]

# values for enumeration 'OtrlMessageState'
OtrlMessageState = c_int # enum
class fingerprint(Structure):
    pass
class context(Structure):
    pass
fingerprint._fields_ = [
    ('next', POINTER(fingerprint)),
    ('tous', POINTER(POINTER(fingerprint))),
    ('fingerprint', POINTER(c_ubyte)),
    ('context', POINTER(context)),
    ('trust', STRING),
]
Fingerprint = fingerprint
class DH_sesskeys(Structure):
    pass
DH_sesskeys._fields_ = [
    ('sendctr', c_ubyte * 16),
    ('rcvctr', c_ubyte * 16),
    ('sendenc', gcry_cipher_hd_t),
    ('rcvenc', gcry_cipher_hd_t),
    ('sendmac', gcry_md_hd_t),
    ('sendmackey', c_ubyte * 20),
    ('sendmacused', c_int),
    ('rcvmac', gcry_md_hd_t),
    ('rcvmackey', c_ubyte * 20),
    ('rcvmacused', c_int),
]

# values for unnamed enumeration
context._fields_ = [
    ('next', POINTER(context)),
    ('tous', POINTER(POINTER(context))),
    ('username', STRING),
    ('accountname', STRING),
    ('protocol', STRING),
    ('fragment', STRING),
    ('fragment_len', size_t),
    ('fragment_n', c_ushort),
    ('fragment_k', c_ushort),
    ('msgstate', OtrlMessageState),
    ('auth', OtrlAuthInfo),
    ('fingerprint_root', Fingerprint),
    ('active_fingerprint', POINTER(Fingerprint)),
    ('their_keyid', c_uint),
    ('their_y', gcry_mpi_t),
    ('their_old_y', gcry_mpi_t),
    ('our_keyid', c_uint),
    ('our_dh_key', DH_keypair),
    ('our_old_dh_key', DH_keypair),
    ('sesskeys', DH_sesskeys * 2 * 2),
    ('sessionid', c_ubyte * 20),
    ('sessionid_len', size_t),
    ('sessionid_half', OtrlSessionIdHalf),
    ('protocol_version', c_uint),
    ('preshared_secret', POINTER(c_ubyte)),
    ('preshared_secret_len', size_t),
    ('numsavedkeys', c_uint),
    ('saved_mac_keys', POINTER(c_ubyte)),
    ('generation', c_uint),
    ('lastsent', time_t),
    ('lastmessage', STRING),
    ('may_retransmit', c_int),
    ('otr_offer', c_int),
    ('app_data', c_void_p),
    ('app_data_free', CFUNCTYPE(None, c_void_p)),
]
ConnContext = context
class s_OtrlUserState(Structure):
    pass
OtrlUserState = POINTER(s_OtrlUserState)
otrl_context_find = _libraries['libotr.so.2'].otrl_context_find
otrl_context_find.restype = POINTER(ConnContext)
otrl_context_find.argtypes = [OtrlUserState, STRING, STRING, STRING, c_int, POINTER(c_int), CFUNCTYPE(None, c_void_p, POINTER(ConnContext)), c_void_p]
otrl_context_find_fingerprint = _libraries['libotr.so.2'].otrl_context_find_fingerprint
otrl_context_find_fingerprint.restype = POINTER(Fingerprint)
otrl_context_find_fingerprint.argtypes = [POINTER(ConnContext), POINTER(c_ubyte), c_int, POINTER(c_int)]
otrl_context_set_trust = _libraries['libotr.so.2'].otrl_context_set_trust
otrl_context_set_trust.restype = None
otrl_context_set_trust.argtypes = [POINTER(Fingerprint), STRING]
otrl_context_set_preshared_secret = _libraries['libotr.so.2'].otrl_context_set_preshared_secret
otrl_context_set_preshared_secret.restype = None
otrl_context_set_preshared_secret.argtypes = [POINTER(ConnContext), POINTER(c_ubyte), size_t]
otrl_context_force_finished = _libraries['libotr.so.2'].otrl_context_force_finished
otrl_context_force_finished.restype = None
otrl_context_force_finished.argtypes = [POINTER(ConnContext)]
otrl_context_force_plaintext = _libraries['libotr.so.2'].otrl_context_force_plaintext
otrl_context_force_plaintext.restype = None
otrl_context_force_plaintext.argtypes = [POINTER(ConnContext)]
otrl_context_forget_fingerprint = _libraries['libotr.so.2'].otrl_context_forget_fingerprint
otrl_context_forget_fingerprint.restype = None
otrl_context_forget_fingerprint.argtypes = [POINTER(Fingerprint), c_int]
otrl_context_forget = _libraries['libotr.so.2'].otrl_context_forget
otrl_context_forget.restype = None
otrl_context_forget.argtypes = [POINTER(ConnContext)]
otrl_context_forget_all = _libraries['libotr.so.2'].otrl_context_forget_all
otrl_context_forget_all.restype = None
otrl_context_forget_all.argtypes = [OtrlUserState]
otrl_dh_init = _libraries['libotr.so.2'].otrl_dh_init
otrl_dh_init.restype = None
otrl_dh_init.argtypes = []
otrl_dh_keypair_init = _libraries['libotr.so.2'].otrl_dh_keypair_init
otrl_dh_keypair_init.restype = None
otrl_dh_keypair_init.argtypes = [POINTER(DH_keypair)]
otrl_dh_keypair_copy = _libraries['libotr.so.2'].otrl_dh_keypair_copy
otrl_dh_keypair_copy.restype = None
otrl_dh_keypair_copy.argtypes = [POINTER(DH_keypair), POINTER(DH_keypair)]
otrl_dh_keypair_free = _libraries['libotr.so.2'].otrl_dh_keypair_free
otrl_dh_keypair_free.restype = None
otrl_dh_keypair_free.argtypes = [POINTER(DH_keypair)]
otrl_dh_gen_keypair = _libraries['libotr.so.2'].otrl_dh_gen_keypair
otrl_dh_gen_keypair.restype = gcry_error_t
otrl_dh_gen_keypair.argtypes = [c_uint, POINTER(DH_keypair)]
otrl_dh_session = _libraries['libotr.so.2'].otrl_dh_session
otrl_dh_session.restype = gcry_error_t
otrl_dh_session.argtypes = [POINTER(DH_sesskeys), POINTER(DH_keypair), gcry_mpi_t]
otrl_dh_compute_v2_auth_keys = _libraries['libotr.so.2'].otrl_dh_compute_v2_auth_keys
otrl_dh_compute_v2_auth_keys.restype = gcry_error_t
otrl_dh_compute_v2_auth_keys.argtypes = [POINTER(DH_keypair), gcry_mpi_t, POINTER(c_ubyte), POINTER(size_t), POINTER(gcry_cipher_hd_t), POINTER(gcry_cipher_hd_t), POINTER(gcry_md_hd_t), POINTER(gcry_md_hd_t), POINTER(gcry_md_hd_t), POINTER(gcry_md_hd_t)]
otrl_dh_compute_v1_session_id = _libraries['libotr.so.2'].otrl_dh_compute_v1_session_id
otrl_dh_compute_v1_session_id.restype = gcry_error_t
otrl_dh_compute_v1_session_id.argtypes = [POINTER(DH_keypair), gcry_mpi_t, POINTER(c_ubyte), POINTER(size_t), POINTER(OtrlSessionIdHalf)]
otrl_dh_session_free = _libraries['libotr.so.2'].otrl_dh_session_free
otrl_dh_session_free.restype = None
otrl_dh_session_free.argtypes = [POINTER(DH_sesskeys)]
otrl_dh_session_blank = _libraries['libotr.so.2'].otrl_dh_session_blank
otrl_dh_session_blank.restype = None
otrl_dh_session_blank.argtypes = [POINTER(DH_sesskeys)]
otrl_dh_incctr = _libraries['libotr.so.2'].otrl_dh_incctr
otrl_dh_incctr.restype = None
otrl_dh_incctr.argtypes = [POINTER(c_ubyte)]
otrl_dh_cmpctr = _libraries['libotr.so.2'].otrl_dh_cmpctr
otrl_dh_cmpctr.restype = c_int
otrl_dh_cmpctr.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
otrl_mem_init = _libraries['libotr.so.2'].otrl_mem_init
otrl_mem_init.restype = None
otrl_mem_init.argtypes = []

# values for enumeration 'OtrlNotifyLevel'
OtrlNotifyLevel = c_int # enum
class s_OtrlMessageAppOps(Structure):
    pass
OtrlPolicy = c_uint
s_OtrlMessageAppOps._fields_ = [
    ('policy', CFUNCTYPE(OtrlPolicy, c_void_p, POINTER(ConnContext))),
    ('create_privkey', CFUNCTYPE(None, c_void_p, STRING, STRING)),
    ('is_logged_in', CFUNCTYPE(c_int, c_void_p, STRING, STRING, STRING)),
    ('inject_message', CFUNCTYPE(None, c_void_p, STRING, STRING, STRING, STRING)),
    ('notify', CFUNCTYPE(None, c_void_p, OtrlNotifyLevel, STRING, STRING, STRING, STRING, STRING, STRING)),
    ('display_otr_message', CFUNCTYPE(c_int, c_void_p, STRING, STRING, STRING, STRING)),
    ('update_context_list', CFUNCTYPE(None, c_void_p)),
    ('protocol_name', CFUNCTYPE(STRING, c_void_p, STRING)),
    ('protocol_name_free', CFUNCTYPE(None, c_void_p, STRING)),
    ('new_fingerprint', CFUNCTYPE(None, c_void_p, POINTER(s_OtrlUserState), STRING, STRING, STRING, POINTER(c_ubyte))),
    ('write_fingerprints', CFUNCTYPE(None, c_void_p)),
    ('gone_secure', CFUNCTYPE(None, c_void_p, POINTER(ConnContext))),
    ('gone_insecure', CFUNCTYPE(None, c_void_p, POINTER(ConnContext))),
    ('still_secure', CFUNCTYPE(None, c_void_p, POINTER(ConnContext), c_int)),
    ('log_message', CFUNCTYPE(None, c_void_p, STRING)),
]
OtrlMessageAppOps = s_OtrlMessageAppOps
otrl_message_free = _libraries['libotr.so.2'].otrl_message_free
otrl_message_free.restype = None
otrl_message_free.argtypes = [STRING]
class s_OtrlTLV(Structure):
    pass
OtrlTLV = s_OtrlTLV
otrl_message_sending = _libraries['libotr.so.2'].otrl_message_sending
otrl_message_sending.restype = gcry_error_t
otrl_message_sending.argtypes = [OtrlUserState, POINTER(OtrlMessageAppOps), c_void_p, STRING, STRING, STRING, STRING, POINTER(OtrlTLV), POINTER(STRING), CFUNCTYPE(None, c_void_p, POINTER(ConnContext)), c_void_p]
otrl_message_receiving = _libraries['libotr.so.2'].otrl_message_receiving
otrl_message_receiving.restype = c_int
otrl_message_receiving.argtypes = [OtrlUserState, POINTER(OtrlMessageAppOps), c_void_p, STRING, STRING, STRING, STRING, POINTER(STRING), POINTER(POINTER(OtrlTLV)), CFUNCTYPE(None, c_void_p, POINTER(ConnContext)), c_void_p]
otrl_message_disconnect = _libraries['libotr.so.2'].otrl_message_disconnect
otrl_message_disconnect.restype = None
otrl_message_disconnect.argtypes = [OtrlUserState, POINTER(OtrlMessageAppOps), c_void_p, STRING, STRING, STRING]
s_OtrlPrivKey._fields_ = [
    ('next', POINTER(s_OtrlPrivKey)),
    ('tous', POINTER(POINTER(s_OtrlPrivKey))),
    ('accountname', STRING),
    ('protocol', STRING),
    ('pubkey_type', c_ushort),
    ('privkey', gcry_sexp_t),
    ('pubkey_data', POINTER(c_ubyte)),
    ('pubkey_datalen', size_t),
]
otrl_privkey_hash_to_human = _libraries['libotr.so.2'].otrl_privkey_hash_to_human
otrl_privkey_hash_to_human.restype = None
otrl_privkey_hash_to_human.argtypes = [STRING, POINTER(c_ubyte)]
otrl_privkey_fingerprint = _libraries['libotr.so.2'].otrl_privkey_fingerprint
otrl_privkey_fingerprint.restype = STRING
otrl_privkey_fingerprint.argtypes = [OtrlUserState, STRING, STRING, STRING]
otrl_privkey_read = _libraries['libotr.so.2'].otrl_privkey_read
otrl_privkey_read.restype = gcry_error_t
otrl_privkey_read.argtypes = [OtrlUserState, STRING]
otrl_privkey_generate = _libraries['libotr.so.2'].otrl_privkey_generate
otrl_privkey_generate.restype = gcry_error_t
otrl_privkey_generate.argtypes = [OtrlUserState, STRING, STRING, STRING]
otrl_privkey_read_fingerprints = _libraries['libotr.so.2'].otrl_privkey_read_fingerprints
otrl_privkey_read_fingerprints.restype = gcry_error_t
otrl_privkey_read_fingerprints.argtypes = [OtrlUserState, STRING, CFUNCTYPE(None, c_void_p, POINTER(ConnContext)), c_void_p]
otrl_privkey_write_fingerprints = _libraries['libotr.so.2'].otrl_privkey_write_fingerprints
otrl_privkey_write_fingerprints.restype = gcry_error_t
otrl_privkey_write_fingerprints.argtypes = [OtrlUserState, STRING]
otrl_privkey_find = _libraries['libotr.so.2'].otrl_privkey_find
otrl_privkey_find.restype = POINTER(OtrlPrivKey)
otrl_privkey_find.argtypes = [OtrlUserState, STRING, STRING]
otrl_privkey_forget = _libraries['libotr.so.2'].otrl_privkey_forget
otrl_privkey_forget.restype = None
otrl_privkey_forget.argtypes = [POINTER(OtrlPrivKey)]
otrl_privkey_forget_all = _libraries['libotr.so.2'].otrl_privkey_forget_all
otrl_privkey_forget_all.restype = None
otrl_privkey_forget_all.argtypes = [OtrlUserState]
otrl_privkey_sign = _libraries['libotr.so.2'].otrl_privkey_sign
otrl_privkey_sign.restype = gcry_error_t
otrl_privkey_sign.argtypes = [POINTER(POINTER(c_ubyte)), POINTER(size_t), POINTER(OtrlPrivKey), POINTER(c_ubyte), size_t]
otrl_privkey_verify = _libraries['libotr.so.2'].otrl_privkey_verify
otrl_privkey_verify.restype = gcry_error_t
otrl_privkey_verify.argtypes = [POINTER(c_ubyte), size_t, c_ushort, gcry_sexp_t, POINTER(c_ubyte), size_t]

# values for enumeration 'OtrlMessageType'
OtrlMessageType = c_int # enum

# values for enumeration 'OtrlFragmentResult'
OtrlFragmentResult = c_int # enum
otrl_init = _libraries['libotr.so.2'].otrl_init
otrl_init.restype = None
otrl_init.argtypes = [c_uint, c_uint, c_uint]
otrl_version = _libraries['libotr.so.2'].otrl_version
otrl_version.restype = STRING
otrl_version.argtypes = []
otrl_proto_default_query_msg = _libraries['libotr.so.2'].otrl_proto_default_query_msg
otrl_proto_default_query_msg.restype = STRING
otrl_proto_default_query_msg.argtypes = [STRING, OtrlPolicy]
otrl_proto_query_bestversion = _libraries['libotr.so.2'].otrl_proto_query_bestversion
otrl_proto_query_bestversion.restype = c_uint
otrl_proto_query_bestversion.argtypes = [STRING, OtrlPolicy]
otrl_proto_whitespace_bestversion = _libraries['libotr.so.2'].otrl_proto_whitespace_bestversion
otrl_proto_whitespace_bestversion.restype = c_uint
otrl_proto_whitespace_bestversion.argtypes = [STRING, POINTER(STRING), POINTER(STRING), OtrlPolicy]
otrl_proto_message_type = _libraries['libotr.so.2'].otrl_proto_message_type
otrl_proto_message_type.restype = OtrlMessageType
otrl_proto_message_type.argtypes = [STRING]
otrl_proto_create_data = _libraries['libotr.so.2'].otrl_proto_create_data
otrl_proto_create_data.restype = gcry_error_t
otrl_proto_create_data.argtypes = [POINTER(STRING), POINTER(ConnContext), STRING, POINTER(OtrlTLV), c_ubyte]
otrl_proto_data_read_flags = _libraries['libotr.so.2'].otrl_proto_data_read_flags
otrl_proto_data_read_flags.restype = gcry_error_t
otrl_proto_data_read_flags.argtypes = [STRING, POINTER(c_ubyte)]
otrl_proto_accept_data = _libraries['libotr.so.2'].otrl_proto_accept_data
otrl_proto_accept_data.restype = gcry_error_t
otrl_proto_accept_data.argtypes = [POINTER(STRING), POINTER(POINTER(OtrlTLV)), POINTER(ConnContext), STRING, POINTER(c_ubyte)]
otrl_proto_fragment_accumulate = _libraries['libotr.so.2'].otrl_proto_fragment_accumulate
otrl_proto_fragment_accumulate.restype = OtrlFragmentResult
otrl_proto_fragment_accumulate.argtypes = [POINTER(STRING), POINTER(ConnContext), STRING]
s_OtrlTLV._fields_ = [
    ('type', c_ushort),
    ('len', c_ushort),
    ('data', POINTER(c_ubyte)),
    ('next', POINTER(s_OtrlTLV)),
]
otrl_tlv_new = _libraries['libotr.so.2'].otrl_tlv_new
otrl_tlv_new.restype = POINTER(OtrlTLV)
otrl_tlv_new.argtypes = [c_ushort, c_ushort, POINTER(c_ubyte)]
otrl_tlv_parse = _libraries['libotr.so.2'].otrl_tlv_parse
otrl_tlv_parse.restype = POINTER(OtrlTLV)
otrl_tlv_parse.argtypes = [POINTER(c_ubyte), size_t]
otrl_tlv_free = _libraries['libotr.so.2'].otrl_tlv_free
otrl_tlv_free.restype = None
otrl_tlv_free.argtypes = [POINTER(OtrlTLV)]
otrl_tlv_seriallen = _libraries['libotr.so.2'].otrl_tlv_seriallen
otrl_tlv_seriallen.restype = size_t
otrl_tlv_seriallen.argtypes = [POINTER(OtrlTLV)]
otrl_tlv_serialize = _libraries['libotr.so.2'].otrl_tlv_serialize
otrl_tlv_serialize.restype = None
otrl_tlv_serialize.argtypes = [POINTER(c_ubyte), POINTER(OtrlTLV)]
otrl_tlv_find = _libraries['libotr.so.2'].otrl_tlv_find
otrl_tlv_find.restype = POINTER(OtrlTLV)
otrl_tlv_find.argtypes = [POINTER(OtrlTLV), c_ushort]
s_OtrlUserState._fields_ = [
    ('context_root', POINTER(ConnContext)),
    ('privkey_root', POINTER(OtrlPrivKey)),
]
otrl_userstate_create = _libraries['libotr.so.2'].otrl_userstate_create
otrl_userstate_create.restype = OtrlUserState
otrl_userstate_create.argtypes = []
otrl_userstate_free = _libraries['libotr.so.2'].otrl_userstate_free
otrl_userstate_free.restype = None
otrl_userstate_free.argtypes = [OtrlUserState]
__all__ = ['__int16_t', 'otrl_init', '__OFF64_T_TYPE', 'SO_RCVBUF',
           'GPG_ERR_INV_HANDLE', 'GPG_ERR_ENOMEM',
           'otrl_dh_keypair_copy', 'GPG_ERR_SOURCE_DIM',
           'gcry_mpi_sub_ui', 'GCRYCTL_GET_BLKLEN', 'otrl_dh_cmpctr',
           'otrl_userstate_free', 'GPG_ERR_NO_VALUE', 'mpi_get_nbits',
           'MSG_CTRUNC', 'SO_OOBINLINE', 'GPG_ERR_EPFNOSUPPORT',
           '__NFDBITS', 'gcry_sexp_nth', '__SQUAD_TYPE',
           'GCRY_CIPHER_BLOWFISH', 'AF_BLUETOOTH', 'gnu_dev_makedev',
           'GCRYCTL_ENABLE_M_GUARD', '__off64_t',
           'GCRY_CIPHER_MODE_CBC', 'GCRYCTL_DISABLE_ALGO', 'mpi_set',
           'GPG_ERR_EPROCLIM', 'GCRY_MD_HAVAL',
           'GPG_ERR_NOT_PROCESSED', 'WORD_BIT', 'GPG_ERR_EIO',
           'GCRYMPI_FLAG_OPAQUE', 'GCRY_VERY_STRONG_RANDOM',
           'gcry_ac_close', 'GPG_ERR_ENOTTY', 'gcry_sexp_dump',
           'gcry_ctl_cmds', 'pthread_t', '__P',
           'GPG_ERR_INV_OID_STRING', 'gcry_mpi_snew',
           'gcry_err_source_t', '_POSIX_STREAM_MAX',
           'otrl_base64_otr_decode', 'AF_NETBEUI', 'GPG_ERR_ELIBMAX',
           'GPG_ERR_ENOTDIR', 'GPG_ERR_AGENT',
           'otrl_userstate_create', 'GPG_ERR_NO_SCDAEMON',
           'GPG_ERR_PIN_BLOCKED', 'GCRY_CIPHER_MODE_CTR',
           'GPG_ERR_EPROTOTYPE', 'GPG_ERR_UNSUPPORTED_CERT',
           '_POSIX_NGROUPS_MAX', 'PF_APPLETALK', 'GPG_ERR_ENONET',
           'readv', 'gcry_mpi_set_ui', 'gcry_sexp_new', 'off_t',
           '__fsblkcnt_t', '__mempcpy', 'memfrob',
           'gcry_ac_key_type_t', 'OTRL_AUTHSTATE_V1_SETUP',
           'LINE_MAX', 'gcry_md_register', 'GPG_ERR_NO_ERROR',
           '_pthread_fastlock', 'pthread_rwlockattr_t',
           'GCRY_AC_KEY_SECRET', 'strerror_r', '__u_int',
           'GPG_ERR_ENOSPC', 'GCRY_CIPHER_MODE_OFB',
           'GPG_ERR_BAD_PIN_METHOD', '_POSIX_C_SOURCE',
           'OTRL_SESSIONID_SECOND_HALF_BOLD', 'GCRY_PK_DSA',
           'pthread_mutexattr_t', 'PF_ROSE', 'GPG_ERR_EHOSTUNREACH',
           '__USE_POSIX2', 'blkcnt_t', 'GPG_ERR_INV_TAG',
           'otrl_context_forget_fingerprint', 'gcry_mpi_release',
           'gpg_err_source_t', 'AIO_PRIO_DELTA_MAX',
           'GPG_ERR_UNKNOWN_HOST', 'u_char', 'gcry_mpi_t', 'uid_t',
           'u_int64_t', 'u_int16_t', 'GPG_ERR_NOT_LOCKED',
           'GPG_ERR_UNKNOWN_ALGORITHM', 'AF_FILE',
           'OTRL_MSGSTATE_PLAINTEXT', 'gcry_ac_name_to_id',
           '__itimer_which', 'GCRY_AC_FLAG_NO_BLINDING',
           'GPG_ERR_USER_11', 'GPG_ERR_USER_10', 'GPG_ERR_USER_13',
           'GPG_ERR_USER_12', 'GPG_ERR_USER_15', 'GPG_ERR_USER_14',
           'GPG_ERR_USER_16', 'HOST_NAME_MAX', 'GPG_ERR_EPERM',
           'va_copy', 'GPG_ERR_USER_5', 'GPG_ERR_USER_4',
           'GPG_ERR_USER_7', 'GPG_ERR_EREMCHG', 'GPG_ERR_USER_1',
           'GPG_ERR_USER_3', 'GPG_ERR_USER_2',
           'GPG_ERR_CARD_NOT_PRESENT', 'GPG_ERR_USER_9',
           'GPG_ERR_USER_8', 'gcry_ac_key_test',
           'GPG_ERR_INV_CERT_OBJ', '__INO64_T_TYPE', 'gcry_mpi_div',
           'GPG_ERR_TOO_LARGE', 'AF_IPX', 'GCRY_CIPHER_CAST5',
           'GPG_ERR_EDEADLOCK', 'SO_DEBUG',
           'GCRYCTL_SET_RANDOM_SEED_FILE', 'GCRYCTL_GET_ALGO_NSKEY',
           'gcry_cipher_test_algo', 'gcry_mpi_test_bit', 'AF_INET',
           'gcry_cipher_get_algo_blklen', 'OTRL_POLICY_ALWAYS',
           'cmsghdr', '__rlim64_t', 'ino_t',
           'GPG_ERR_UNKNOWN_VERSION', 'otrl_base64_decode',
           'otrl_context_find_fingerprint', '__blksize_t',
           '__USE_ANSI', 'GPG_ERR_SEXP_STRING_TOO_LONG', 'strncpy',
           'otrl_dh_compute_v1_session_id', 'GCRYSEXP_FMT_ADVANCED',
           'ino64_t', 'memcmp', 'GPG_ERR_SOURCE_GSTI',
           'GPG_ERR_EL3RST', '_POSIX_PATH_MAX',
           'GCRYCTL_DUMP_SECMEM_STATS', 'OTRL_POLICY_VERSION_MASK',
           '__blkcnt64_t', '__STDC_ISO_10646__', 'BC_DIM_MAX',
           'gcry_ac_data_get_name', 'otrl_privkey_hash_to_human',
           'gcry_pk_get_nbits', 'ULONG_MAX', 'setitimer',
           'GPG_ERR_BAD_MPI', '_BITS_TYPES_H',
           'GPG_ERR_NOT_DER_ENCODED', 'gcry_handler_progress_t',
           'GPG_ERR_DIRMNGR', 'isfdtype', 'iovec',
           'GCRY_CIPHER_CBC_CTS', 'GPG_ERROR_H', '__rlim_t',
           '__FLOAT_WORD_ORDER', 'PTHREAD_STACK_MIN', 'GPG_ERR_EBUSY',
           'pthread_mutex_t', 'GCRY_CIPHER_SAFER_SK128',
           'GPG_ERR_INV_KEYRING', 'otrl_privkey_forget_all',
           'otrl_privkey_read', 'mpi_mulm', 'otrl_dh_keypair_free',
           'GPG_ERR_BUFFER_TOO_SHORT', 'gcry_sexp_length',
           'gcry_ac_key_pair_extract', 'GPG_ERR_INV_ENGINE',
           '__key_t', 'dev_t', 'PF_NETROM', 'gcry_xcalloc_secure',
           'AF_IRDA', 'gcry_sexp_prepend',
           'OTRL_POLICY_ERROR_START_AKE', 'GPG_ERR_INCOMPLETE_LINE',
           'gcry_sexp_vlist', '__GNU_LIBRARY__', '_BITS_TYPESIZES_H',
           'GPG_ERR_BAD_URI', '__defined_schedparam', 'gcry_mpi_mulm',
           '_POSIX_RTSIG_MAX', '_POSIX_SEM_VALUE_MAX',
           'GPG_ERR_ENCODING_PROBLEM', 'GPG_ERR_WRONG_CARD',
           'GPG_ERR_EDOM', 'gcry_mpi_aprint', 'rawmemchr',
           'OTRL_POLICY_OPPORTUNISTIC', 'GPG_ERR_WEAK_KEY',
           'gcry_md_map_name', 'otrl_dh_compute_v2_auth_keys',
           'gcry_mpi_set_highbit', '__fsid_t', 'strncmp', 'strcat',
           'GPG_ERR_SOURCE_DIRMNGR', 'gcry_pk_check_secret_key_t',
           'AF_KEY', 'mpi_mul_2exp', 'getsockname',
           'OTRL_FRAGMENT_UNFRAGMENTED', 'mpi_sub_ui',
           'GPG_ERR_INV_CIPHER_MODE', 'MSG_ERRQUEUE',
           'OTRL_MSGTYPE_TAGGEDPLAINTEXT', '_POSIX_ARG_MAX',
           'gcry_realloc', 'gcry_mpi_dump', 'gcry_error_from_errno',
           '__FD_SETSIZE', 'GPG_ERR_SOURCE_GPGME',
           'GCRY_CIPHER_CBC_MAC', 'setsockopt', 'gcry_cipher_decrypt',
           'SO_TIMESTAMP', 'GCRYCTL_SET_KEY', 'SHUT_WR', 'int32_t',
           'off64_t', 'gcry_md_spec', 'gcry_md_stop_debug',
           'GPG_ERR_UNSUPPORTED_CMS_OBJ', 'gcry_cipher_encrypt',
           'PF_IPX', '_POSIX_TTY_NAME_MAX', 'GPG_ERR_MISSING_ACTION',
           'SOL_DECNET', 'GPG_ERR_EIEIO', 'gnu_dev_major', 'AF_LOCAL',
           'strsignal', 'GPG_ERR_SYNTAX', 'gcry_mpi_invm', 'mpi_subm',
           'GCRYCTL_GET_ALGO_USAGE', 'gcry_cipher_get_algo_keylen',
           'GPG_ERR_PUBKEY_NOT_TRUSTED', '__suseconds_t',
           'otrl_privkey_find', 'otrl_context_forget',
           'gcry_ac_id_to_name', 'gcry_xmalloc_secure', 'AF_ROSE',
           'mpi_sub', 'GCRY_MD_SHA256', 'AF_UNSPEC',
           'GPG_ERR_SOURCE_PINENTRY', 'gcry_cipher_list',
           'GCRYCTL_DISABLE_INTERNAL_LOCKING', '_POSIX_SYMLOOP_MAX',
           'otrl_privkey_forget', 'u_short', 'AF_DECnet', 'RTSIG_MAX',
           'gcry_ac_open', 'OtrlPolicy', 'GPG_ERR_INV_URI',
           'GPG_ERR_NO_CRL_KNOWN', '_POSIX_SIGQUEUE_MAX',
           'GPG_ERR_EEXIST', 'gcry_ac_key_destroy',
           'gcry_ac_key_data_get', 'gcry_pk_test_algo',
           'mpi_get_opaque', 'PF_FILE', 'OTRL_PUBKEY_TYPE_DSA',
           'pthread_condattr_t', 'pthread_once_t', '__timer_t',
           'otrl_proto_whitespace_bestversion', '__uint32_t',
           'GPG_ERR_ENOMEDIUM', 'GPG_ERR_EUCLEAN', 'GPG_ERR_EFTYPE',
           'loff_t', 'gpg_err_code_to_errno', 'blksize_t',
           '__STDC_IEC_559__', 'GPG_ERR_BAD_KEY',
           'GPG_ERR_SEXP_UNMATCHED_DH', 'gcry_md_test_algo',
           'gnu_dev_minor', 'SO_PEERSEC', 'GPG_ERR_NO_PIN_ENTRY',
           'GPG_ERR_EINTR', '_ISOC99_SOURCE', 'gcry_pk_register',
           'GPG_ERR_NO_PKCS15_APP', 'PF_ATMPVC', 'getitimer',
           'OTRL_FRAGMENT_INCOMPLETE', 'GPG_ERR_ETIMEDOUT',
           'GPG_ERR_ETIME', 'OTRL_POLICY_MANUAL', '__id_t',
           'GPG_ERR_ENEEDAUTH', 'ulong',
           'otrl_proto_query_bestversion', '__timer_t_defined',
           'lutimes', 'OtrlUserState', 'gcry_error_t',
           'GPG_ERR_INV_FLAG', 'FD_ISSET', 'SCM_CREDENTIALS',
           'gcry_err_code_t', 'GPG_ERR_SOURCE_KSBA',
           'gcry_ac_data_encrypt', 'gcry_ac_key_pair', 'OtrlAuthInfo',
           'GPG_ERR_EL3HLT', 'mpi_copy', '_SIGSET_H_types',
           'GPG_ERR_EPIPE', 'gcry_pk_map_name', 'GPG_ERR_INV_NAME',
           'AF_ECONET', 'GPG_ERR_PIN_NOT_SYNCED',
           'GPG_ERR_UNSUPPORTED_ENCODING', 'AF_WANPIPE',
           'gcry_md_start_debug', 'OTRL_MSGTYPE_DH_COMMIT',
           'gcry_pk_generate_t', 'gcry_pk_genkey', 'PF_BRIDGE',
           'gcry_sexp_release', 'gcry_mpi_rshift', '_POSIX_MAX_INPUT',
           'GCRYCTL_INITIALIZATION_FINISHED', 'GPG_ERR_SIG_CLASS',
           'GPG_ERR_IDENTIFIER_NOT_FOUND',
           'otrl_auth_handle_signature', 'GPG_ERR_PUBKEY_ALGO',
           'PF_KEY', 'GPG_ERR_ERPCMISMATCH', 'GPG_ERR_ENOPKG',
           'gcry_sexp_create', 'otrl_proto_create_data', 'timezone',
           'OTRL_AUTHSTATE_NONE', 'BYTE_ORDER', 'gcry_strsource',
           'gpg_strerror_r', 'memmem', '__u_quad_t', '__u_short',
           'GCRYCTL_GET_ALGO_NENCR', 'AF_BRIDGE',
           'GCRY_MD_CRC32_RFC1510', 'AF_ASH', 'PF_WANPIPE',
           'useconds_t', '__bos0', 'gcry_pk_encrypt',
           'gcry_sexp_canon_len', 'GPG_ERR_NO_PRIME', 'BC_BASE_MAX',
           'NFDBITS', '_POSIX_HIWAT', 'SO_PASSCRED', 'gcry_ac_key',
           'AF_PACKET', 'GPG_ERR_ECONNREFUSED', 'gcry_md_oid_spec_t',
           'USHRT_MAX', 'mpi_set_ui', '_POSIX_UIO_MAXIOV',
           'otrl_privkey_write_fingerprints', 'OtrlAuthState',
           'GPG_ERR_EREMOTEIO', 'mpi_test_bit', 'OTRL_MESSAGE_TAG_V1',
           'OTRL_MESSAGE_TAG_V2', 'GPG_ERR_INV_STATE', 'SOL_AAL',
           'GPG_ERR_CARD_REMOVED', 'GPG_ERR_SOURCE_SHIFT',
           'otrl_tlv_serialize', 'GCRYCTL_DISABLE_SECMEM_WARN',
           'GPG_ERR_EDQUOT', 'GCRYMPI_FLAG_SECURE',
           'GPG_ERR_EPROGMISMATCH', '__time_t_defined', '__time_t',
           '__GLIBC_PREREQ', 'strnlen', 'MSG_RST',
           'GPG_ERR_NO_PUBKEY', '_POSIX_THREAD_DESTRUCTOR_ITERATIONS',
           'pthread_rwlock_t', 'GPG_ERR_CONFLICT', 'GCRY_AC_ELG_E',
           'timespec', 'gcry_prime_check_func_t',
           'GPG_ERR_CERT_TOO_YOUNG', 'strerror', '__stpcpy',
           'GPG_ERR_EADDRINUSE', '__fsfilcnt64_t',
           'gcry_sexp_nth_mpi', 'ffsll', 'SO_BROADCAST', 'socketpair',
           '__attribute_format_strfmon__', 'DH1536_GROUP_ID',
           'SO_NO_CHECK', 'GPG_ERR_ASSUAN', '__u_long',
           'SCM_TIMESTAMP', 'GPG_ERR_INV_DATA', 'gcry_calloc',
           '_LARGEFILE_SOURCE', 'GCRY_CIPHER_AES192', 'bzero',
           'GPG_ERR_ENOPROTOOPT', '__off_t',
           'otrl_auth_handle_v1_key_exchange', 'u_quad_t', 'rindex',
           'GPG_ERR_UNUSABLE_SECKEY', 'daddr_t', 'strdup',
           'GPG_ERR_NO_AGENT', 'FIOGETOWN', 'GPG_ERR_SOURCE_GPGSM',
           '__int8_t', '__FSFILCNT64_T_TYPE', 'gettimeofday',
           'GCRY_CIPHER_SECURE', 'MSG_SYN', 'PF_IRDA',
           'gcry_md_final', 'GCRY_PRIME_FLAG_SECRET', 'pthread_key_t',
           'gcry_ac_handle_t', '__locale_struct', 'u_int8_t',
           'GPG_ERR_BAD_SIGNATURE', 'GPG_ERR_ENOEXEC', 'FD_ZERO',
           '__locale_t', 'strncat', 'GPG_ERR_ENOTSOCK',
           'GCRY_MD_SHA384', 'GCRY_CIPHER_MODE_CFB', 'memrchr',
           'GPG_ERR_INV_USER_ID', 'uint', 'gcry_pk_algo_name',
           'strncasecmp_l', 'ITIMER_PROF', 'GPG_ERR_INV_CMS_OBJ',
           'gcry_handler_secure_check_t', 'GCRYCTL_IS_ALGO_ENABLED',
           'GPG_ERR_INV_KEYLEN', 'size_t', 'GCRY_MD_SHA512',
           'GPG_ERR_ENOTBLK', 'SOCK_SEQPACKET', 'GPG_ERR_GENERAL',
           'gcry_handler_error_t', 'SOL_IRDA', '__qaddr_t',
           'gcry_mpi_scan', 'gcry_sexp', 'gpg_err_code_from_errno',
           'GPG_ERR_UNKNOWN_SEXP', 'strcoll_l', '__pthread_attr_s',
           '_LIBC_LIMITS_H_', 'GPG_ERR_LINE_TOO_LONG', 'MSG_OOB',
           'sigset_t', 'mpi_invm', 'gcry_cipher_cts',
           'gcry_cipher_ctl', 'GCRYMPI_FMT_HEX', 'sendto',
           '__USE_POSIX', 'DELAYTIMER_MAX', 'GCRY_CIPHER_RFC2268_40',
           'GcrySexp', 'SCHAR_MIN', 'GPG_ERR_NO_ENCRYPTION_SCHEME',
           '__fd_mask', 'UCHAR_MAX', 'GPG_ERR_CIPHER_ALGO',
           '__useconds_t', 'GCRY_CIPHER_SERPENT192',
           '__clockid_t_defined', '_POSIX_CLOCKRES_MIN',
           'GPG_ERR_CHECKSUM', 'GPG_ERR_EHOSTDOWN', 'u_int32_t',
           'SO_RCVLOWAT', 'SHUT_RDWR', 'gcry_mpi_clear_bit',
           '_SYS_TYPES_H', 'PF_NETBEUI', 'getpeername',
           'GPG_ERR_ENOTCONN', 'GPG_ERR_ENOSTR', 'gcry_mpi_sub',
           '__USE_GNU', '_SYS_TIME_H', 'gcry_ac_data_destroy',
           'pthread_attr_t', '__attribute_format_arg__',
           'XATTR_LIST_MAX', 'futimes',
           'PTHREAD_DESTRUCTOR_ITERATIONS', 'GPG_ERR_EBADRQC',
           'GPG_ERR_EADV', 'GPG_ERR_EROFS', 'GCRY_CIPHER_DES_SK',
           'gcry_ac_data_new', 'SOCK_DGRAM', '_POSIX_MQ_PRIO_MAX',
           'OtrlFragmentResult', 'strfry', 'Fingerprint', 'SOL_ATM',
           'OtrlMessageType', 'gcry_sexp_sscan',
           'GPG_ERR_NOT_SUPPORTED', 'GPG_ERR_UNKNOWN_CMS_OBJ',
           'GPG_ERR_BAD_PUBKEY', 'gcry_md_reset',
           'GCRYCTL_GET_ALGO_NSIGN', 'quad_t', 'GPG_ERR_EINVAL',
           'GPG_ERR_INV_CARD', 'pthread_cond_t', 'gcry_sexp_alist',
           'gcry_md_read', 'GPG_ERR_EMEDIUMTYPE',
           'GCRY_THREAD_OPTION_DEFAULT', 'gcry_ac_key_init',
           'GCRY_MD_FLAG_SECURE', 'gcry_cipher_stdecrypt_t',
           'nlink_t', '__UQUAD_TYPE', 'GCRYMPI_FMT_SSH', 'PF_LOCAL',
           'GCRY_MD_CRC24_RFC2440', 'GPG_ERR_INV_SESSION_KEY',
           'XATTR_NAME_MAX', 'strpbrk', 'int8_t', 'fsblkcnt_t',
           'GPG_ERR_CODE_DIM', '__uint16_t', 'gcry_sexp_cons',
           'fsfilcnt_t', '__swblk_t', '_POSIX_LINK_MAX', 'id_t',
           'GPG_ERR_INV_LENGTH', 'GPG_ERR_WRONG_PUBKEY_ALGO',
           'SO_ERROR', 'GPG_ERR_ENOTUNIQ', 'PF_ROUTE',
           'gcry_mpi_get_flag', 'GcryMPI', 'basename', 'CMSG_NXTHDR',
           '_GCRY_PTH_FD_SET', 'GPG_ERR_NO_DIRMNGR',
           'GPG_ERR_CONFIGURATION', '__GLIBC_HAVE_LONG_LONG',
           'GCRY_AC_FLAG_DEALLOC', 'CHAR_MIN', 'gcry_mpi_new',
           'GCRY_PK_ELG_E', 'SO_REUSEADDR',
           'GPG_ERR_UNSUPPORTED_PROTOCOL', 'GPG_ERR_ENOBUFS',
           'SO_BINDTODEVICE', 'GPG_ERR_INV_SEXP', 'PF_PPPOX',
           'itimerval', 'GCRY_CIPHER_AES', 'GCRY_THREAD_OPTION_PTH',
           '_POSIX_MQ_OPEN_MAX', 'GPG_ERR_NO_POLICY_MATCH',
           'GPG_ERR_CRL_TOO_OLD', 'GCRY_LOG_CONT', 'GPG_ERR_EDEADLK',
           '_POSIX_PIPE_BUF', 'SO_SECURITY_ENCRYPTION_TRANSPORT',
           'otrl_privkey_generate', '__USE_XOPEN2K', 'gcry_pk_sign',
           'GPG_ERR_EAGAIN', '__blkcnt_t', 'GCRY_LOG_ERROR',
           'gcry_randomize', 'strxfrm', 'gcry_sexp_build_array',
           'GPG_ERR_WRONG_BLOB_TYPE', 'GPG_ERR_NO_OBJ', 'mpi_addm',
           'GPG_ERR_NO_SECKEY', 'OTRL_TLV_DISCONNECTED',
           'gpg_strsource', 'gcry_cipher_decrypt_t',
           'GPG_ERR_CERT_REVOKED', 'GPG_ERR_ELIBEXEC',
           'gcry_cipher_close', '_POSIX_DELAYTIMER_MAX',
           'GPG_ERR_ERESTART', 'OTRL_POLICY_REQUIRE_ENCRYPTION',
           'GPG_ERR_BAD_PIN', 'gcry_mpi_clear_flag',
           'gcry_random_bytes_secure', 'PF_NETLINK',
           'otrl_base64_encode', 'SO_PEERCRED', 'time_t', 'GcryMDHd',
           'gcry_mpi_mod', 'gcry_pk_spec_t', 'fsblkcnt64_t',
           'GPG_ERR_ESRMNT', 'otrl_dh_keypair_init', 'GPG_ERR_EISDIR',
           'GCRYCTL_STOP_DUMP', 'otrl_version', 'GPG_ERR_EBADRPC',
           'gcry_ac_data_get_index', 'gcry_xcalloc',
           'GCRYCTL_CFB_SYNC', '__int64_t', 'gcry_cipher_unregister',
           'gcry_set_progress_handler', '__LITTLE_ENDIAN',
           'GCRYCTL_RESET', 'MSG_PEEK', 'OTRL_POLICY_DEFAULT',
           'GPG_ERR_BAD_SECKEY', '_STRUCT_TIMEVAL',
           'GPG_ERR_CERT_EXPIRED', 'mpi_add_ui',
           'GCRY_THREAD_OPTION_PTHREAD', 'GPG_ERR_EDOTDOT',
           'otrl_context_set_trust', 'otrl_proto_data_read_flags',
           'SHRT_MIN', '_POSIX_FD_SETSIZE', 'GCRY_CIPHER_MODE_NONE',
           'gcry_prime_generate', 'va_start', 'OtrlMessageAppOps',
           'GPG_ERR_ECANCELED', 'OTRL_VERSION_MAJOR',
           'gcry_ac_data_set', 'memmove', 'GPG_ERR_EADDRNOTAVAIL',
           'GPG_ERR_SOURCE_UNKNOWN', 'GPG_ERR_ED',
           'GPG_ERR_SEXP_ODD_HEX_NUMBERS', 'otrl_tlv_new',
           'GPG_ERR_EDIED', 'mpi_clear_highbit', '__nlink_t',
           'DH_sesskeys', 'strcmp', '_POSIX2_BC_BASE_MAX',
           'GPG_ERR_SEXP_UNEXPECTED_PUNC', 'PF_PACKET', '__U64_TYPE',
           'gcry_md_write_t', 'mpi_clear_bit', 'GCRYCTL_TEST_ALGO',
           'GCRY_CIPHER_RIJNDAEL192', 'GPG_ERR_EREMOTE',
           'GPG_ERR_ENOTEMPTY', 'GCRY_AC_KEY_PUBLIC', 'gcry_mpi_set',
           'GPG_ERR_ENODATA', '_SVID_SOURCE', 'GCRY_PK_USAGE_ENCR',
           'GPG_ERR_ENOMSG', 'gcry_md_close',
           'GPG_ERR_UNKNOWN_PACKET', 'otrl_base64_otr_encode',
           'GCRY_CIPHER_TWOFISH128', 'GPG_ERR_KEYRING_OPEN',
           'SOL_RAW', 'mpi_set_highbit', 'MSG_CONFIRM',
           'GPG_ERR_INV_ID', 'GPG_ERR_ESHUTDOWN',
           'GCRYCTL_UPDATE_RANDOM_SEED_FILE', 'GPG_ERR_ECOMM',
           '_XOPEN_LIM_H', 'GCRYCTL_SUSPEND_SECMEM_WARN', '__caddr_t',
           'GPG_ERR_NETWORK', 'GPG_ERR_EBFONT', 'SOCK_PACKET',
           'GPG_ERR_SEXP_NOT_CANONICAL', 'OTRL_MSGTYPE_SIGNATURE',
           'GPG_ERR_ELEMENT_NOT_FOUND', '_GCRY_ERR_SOURCE_DEFAULT',
           'DH_keypair', 'OTRL_MSGSTATE_FINISHED', 'GCRY_WEAK_RANDOM',
           'gcry_cipher_open', 'MSG_FIN',
           'GPG_ERR_ASSUAN_SERVER_FAULT', 'GPG_ERR_USER_6',
           'OTRL_POLICY_NEVER', 'FD_SET', 'GPG_ERR_SOURCE_MASK',
           'GCRYCTL_ANY_INITIALIZATION_P', '__STRING',
           'gcry_md_algo_info', '__GNUC_PREREQ', '__BLKCNT64_T_TYPE',
           'GPG_ERR_EBADF', 'GPG_ERR_EACCES', 'GPG_ERR_INV_OBJ',
           'fsid_t', '__pid_t', 'gcry_cipher_mode_from_oid',
           'GCRY_STRONG_RANDOM', 'OTRL_NOTIFY_INFO', 'GPG_ERR_ELNRNG',
           'otrl_mem_init', 'GPG_ERR_SEXP_BAD_QUOTATION',
           'GPG_ERR_SOURCE_GPG', 'GPG_ERR_ETXTBSY',
           'GPG_ERR_SELFTEST_FAILED', 'GCRY_CIPHER_IDEA',
           'gcry_strerror', 'gcry_ac_id', 'makedev',
           'gcry_mpi_set_opaque', 'PF_X25', 'SOCK_RDM',
           'gcry_cipher_flags', 'gcry_strdup', 'otrl_dh_incctr',
           'gcry_mpi_format', 'GCRY_CIPHER_AES128',
           'GPG_ERR_CARD_RESET', 'gcry_mpi_clear_highbit',
           '_POSIX_SOURCE', 'gcry_sexp_car', 'recvfrom',
           'gcry_ac_data_copy', 'pthread_barrier_t', '__uint64_t',
           'GPG_ERR_UNKNOWN_ERRNO', 'gcry_mpi_gcd', '__clockid_t',
           'GPG_ERR_ENETRESET', 'strcspn', 'osockaddr',
           'gcry_is_secure', 'MB_LEN_MAX', 'GCRY_CIPHER_MODE_ECB',
           'gcry_cipher_setkey_t', 'otrl_context_force_finished',
           'SHUT_RD', '_POSIX_THREAD_KEYS_MAX', 'gcry_handler_log_t',
           'SCM_RIGHTS', 'sendmsg', 'GPG_ERR_EPROCUNAVAIL',
           '__mode_t', 'select', 'GPG_ERR_ELIBSCN', 'GPG_ERR_EMFILE',
           'GCRYCTL_DUMP_RANDOM_STATS', '_pthread_descr',
           'GCRYCTL_SET_DEBUG_FLAGS', 'gcry_set_outofcore_handler',
           'minor', 'gpg_err_code_t', '_STRING_H', 'gcry_cipher_sync',
           'GCRY_PK_RSA_S', 'GPG_ERR_BAD_DATA', 'gcry_ac_key_type',
           'SIOCGSTAMP', 'GCRY_PK_RSA_E', 'pthread_barrierattr_t',
           'GCRY_PRIME_FLAG_SPECIAL_FACTOR', '__FSBLKCNT64_T_TYPE',
           'GCRY_CIPHER_DES', 'pid_t', 'otrl_proto_accept_data',
           'mpi_set_bit', 'AF_X25', '__bzero', 'GPG_ERR_EALREADY',
           'gcry_md_algo_name', 'GCRY_MD_FLAG_HMAC', 'accept',
           'PIPE_BUF', 'strlen', 'GCRY_CIPHER_SERPENT256',
           'gcry_mpi_cmp', 'AF_SNA', 'otrl_context_force_plaintext',
           'GPG_ERR_EOF_GCRYPT', 'gcry_cipher_encrypt_t',
           'GPG_ERR_EXFULL', 'gcry_set_fatalerror_handler',
           'gcry_module_t', 'gcry_md_unregister', 'GPG_ERR_EFBIG',
           'gcry_sexp_t', 'GPG_ERR_NO_DATA', 'AF_MAX', '__clock_t',
           'gcry_pk_list', '__fsfilcnt_t', 'GPG_ERR_INV_CRL',
           'GCRY_LOG_DEBUG', 'gcry_md_enable', 'gcry_ac_data_sign',
           'GPG_ERR_ENOTSUP', 'gcry_check_version', 'ffs',
           '__LONG_LONG_PAIR', 'gcry_ac_data_decrypt',
           'otrl_tlv_parse', 'otrl_context_find', 'GPG_ERR_EBADSLT',
           'XATTR_SIZE_MAX', 'GPG_ERR_EILSEQ', 'GPG_ERR_SOURCE_SCD',
           '__cmsg_nxthdr', 'GCRYCTL_SET_THREAD_CBS',
           'GPG_ERR_TIMEOUT', '_POSIX2_LINE_MAX', 'gcry_md_spec_t',
           '_POSIX_MAX_CANON', 'OTRL_MSGTYPE_ERROR', 'GPG_ERR_ENFILE',
           'GPG_ERR_NO_CMS_OBJ', 'otrl_dh_gen_keypair',
           '_POSIX_THREAD_THREADS_MAX', 'SO_LINGER',
           'GPG_ERR_TIME_CONFLICT', 'strcoll', 'NL_LANGMAX',
           'strverscmp', 'gcry_md_hd_t', 'GPG_ERR_NOT_CONFIRMED',
           'SO_PEERNAME', 'GPG_ERR_EBADR', 'SOCK_STREAM',
           'GPG_ERR_ECONNRESET', 'otrl_auth_new', '_XOPEN_IOV_MAX',
           'gcry_calloc_secure', 'connect', 'GPG_ERR_EOVERFLOW',
           'GPG_ERR_DECRYPT_FAILED', 'GPG_ERR_EBADE',
           '__GLIBC_MINOR__', 'SO_ACCEPTCONN', 'strrchr',
           'GPG_ERR_EGRATUITOUS', 'GPG_ERR_UNKNOWN_NAME', 'mpi_gcd',
           'gcry_mpi_get_opaque', 'otrl_dh_session_free', 'strchrnul',
           'gcry_mpi_cmp_ui', 'GPG_ERR_UNSUPPORTED_ALGORITHM',
           'GPG_ERR_WRONG_KEY_USAGE', 'gcry_ac_data_t',
           '_BITS_POSIX2_LIM_H', 'recv', 'GPG_ERR_EFAULT',
           'GCRYCTL_SET_VERBOSITY', 'MSG_WAITALL',
           'gcry_cipher_stencrypt_t', 'otrl_proto_default_query_msg',
           'gcry_cipher_algo_info', 'GCRY_AC_FLAG_COPY',
           'gcry_pk_verify_t', 'major', 'GCRYCTL_FINALIZE',
           'pthread_spinlock_t', 'gcry_cipher_spec_t',
           'GPG_ERR_ENOLCK', 'AF_UNIX', 'gcry_ac_key_pair_t',
           'mpi_mul_ui', 'OTRL_MSGTYPE_DATA',
           'GCRY_PRIME_CHECK_AT_MAYBE_PRIME', 'AF_ATMPVC',
           'gcry_sexp_append', 'gcry_pk_decrypt_t',
           'GPG_ERR_EMSGSIZE', '__USE_LARGEFILE',
           'GPG_ERR_SEXP_NESTED_DH', '_FEATURES_H', 'listen',
           'gcry_mpi_get_nbits', 'strtok_r', 'pselect', 'GCRY_MPI',
           'GPG_ERR_SEXP_INV_LEN_SPEC', 'GCRYCTL_START_DUMP',
           'GPG_ERR_DUP_VALUE', 'AF_APPLETALK',
           'GPG_ERR_ETOOMANYREFS', 'OTRL_MSGSTATE_ENCRYPTED',
           'timeval', 'GPG_ERR_MISSING_VALUE', 'gcry_mpi_flag',
           'otrl_privkey_verify', 'GPG_ERR_ELOOP',
           '_pthread_rwlock_t', 'GCRYCTL_GET_ALGO_NPKEY',
           'GPG_ERR_VALUE_NOT_FOUND', 'gcry_pk_get_nbits_t',
           'OFFER_NOT', 'gcry_sexp_format', 'strncasecmp',
           'GCRYCTL_DROP_PRIVS', 'GCRY_LOG_BUG',
           'GPG_ERR_INV_KEYINFO', 'gcry_cipher_reset',
           'GCRY_CIPHER_NONE', 'mode_t', 'mpi_cmp_ui',
           'GPG_ERR_UNEXPECTED_TAG', '_POSIX_SSIZE_MAX',
           'GPG_ERR_HARDWARE', 'writev', '__loff_t', 'SO_TYPE',
           'FD_CLR', 'NGROUPS_MAX', 'otrl_proto_message_type',
           'GPG_ERR_BAD_CERT_CHAIN', 'gcry_free', 'strsep',
           'GPG_ERR_EPROTONOSUPPORT', 'gcry_set_log_handler',
           'OTRL_VERSION_SUB', 'GCRY_CIPHER_AES256', 'va_list',
           's_OtrlPrivKey', 'fd_mask', 'GPG_ERR_SCDAEMON',
           'otrl_tlv_free', 'GPG_ERR_INV_PACKET', '__FDELT',
           'mpi_new', 'OtrlSessionIdHalf', 'GPG_ERR_ENOSR', 'strchr',
           '_POSIX_TZNAME_MAX', 'gcry_control',
           'GCRYCTL_CLEAR_DEBUG_FLAGS', 'gcry_xstrdup',
           'gcry_cipher_map_name', 'SIOCATMARK', '__intptr_t',
           'PF_SNA', '__timespec_defined', 'GPG_ERR_KEYSERVER',
           'gcry_create_nonce', 'GPG_ERR_SYSTEM_ERROR',
           'GPG_ERR_NOT_FOUND', 'GPG_ERR_MODULE_NOT_FOUND',
           '_SYS_UIO_H', 'gcry_err_code_to_errno', 'gcry_mpi_copy',
           'GCRY_CIPHER_ENABLE_SYNC',
           'otrl_context_set_preshared_secret', '_GCRY_GCC_VERSION',
           'gcry_mpi_mul_ui', 'shutdown', '_POSIX_SEM_NSEMS_MAX',
           '__BIT_TYPES_DEFINED__', 'GPG_ERR_TOO_SHORT',
           'sockaddr_storage', 'GPG_ERR_UNSUPPORTED_OPERATION',
           'GPG_ERR_EOPNOTSUPP', 'adjtime', 'gcry_md_info',
           'otrl_message_disconnect', 'OTRL_VERSION', 'u_long',
           'GPG_ERR_ENOTNAM', 'IOV_MAX', 'GPG_ERR_EWOULDBLOCK',
           'gcry_mpi_mul_2exp', '__DEV_T_TYPE',
           'GCRY_CIPHER_RIJNDAEL128', 'mpi_mod', 'PF_MAX',
           'gcry_pk_algo_info', 'AF_NETROM', 'GCRY_AC_ELG',
           's_OtrlUserState', 'GCRY_MD_HD', 'FIOSETOWN',
           'GCRYCTL_ENABLE_ALGO', 'gcry_random_level_t',
           'otrl_tlv_find', '_SYS_CDEFS_H', 'gcry_malloc_secure',
           'gcry_md_ctl', 'GCRY_CIPHER_ARCFOUR', 'GPG_ERR_ENOANO',
           'GCRY_MD_NONE', 'GCRY_CIPHER_SERPENT128', 'gcry_xrealloc',
           'suseconds_t', 'mempcpy', 'GPG_ERR_NOT_IMPLEMENTED',
           'stpncpy', 'GPG_ERR_SOURCE_USER_4',
           'GPG_ERR_SOURCE_USER_2', 'GPG_ERR_SOURCE_USER_3',
           'GPG_ERR_SOURCE_USER_1', 'SO_RCVTIMEO', 'GCRY_PK_ELG',
           'fd_set', '_POSIX_HOST_NAME_MAX', 'gcry_md_init_t',
           'GPG_ERR_ENOSYS', 'GPG_ERR_ENETUNREACH', 'register_t',
           'mpi_fdiv', 'strstr', 'AF_SECURITY', '_POSIX_TIMER_MAX',
           'GCRYCTL_TERM_SECMEM', 'GPG_ERR_CANCELED',
           'GPG_ERR_USE_CONDITIONS', 'GCRYPT_VERSION', 'gcry_md_copy',
           'GCRY_CIPHER_HD', 'GPG_ERR_LOCALE_PROBLEM', 'SOCK_RAW',
           'otrl_auth_handle_revealsig', 'gcry_ac_id_t',
           'gcry_pk_unregister', 'GCRYSEXP_FMT_DEFAULT',
           'gcry_sexp_nth_data', 'GCRY_CIPHER_3DES', 'gcry_sexp_cdr',
           'GPG_ERR_EDESTADDRREQ', 'socklen_t', 'gcry_sexp_sprint',
           '_BITS_POSIX1_LIM_H', 'gcry_pk_verify', 'SOMAXCONN',
           'gcry_md_get_algo', 'GPG_ERR_ESTALE', '__USE_BSD',
           '__CONCAT', 'ptrdiff_t', 'AF_INET6', 'gcry_ac_data_length',
           'GPG_ERR_UNEXPECTED', '_POSIX_CHILD_MAX',
           'GPG_ERR_ENOLINK', 'gcry_cipher_oid_spec_t', 'memccpy',
           'gcry_prime_check', 'GPG_ERR_EISNAM',
           'GCRY_CIPHER_RIJNDAEL', 'gcry_md_context', 'u_int',
           'GCRY_PRIME_CHECK_AT_GOT_PRIME', 'gid_t',
           '__STDC_IEC_559_COMPLEX__', 'otrl_auth_handle_key',
           'OTRL_MSGTYPE_NOTOTR', 'GPG_ERR_INV_ATTR',
           'gcry_ac_key_pair_destroy', 'gpg_strerror', 'blkcnt64_t',
           'ffsl', 'GPG_ERR_UNSUPPORTED_PROTECTION', 'ITIMER_REAL',
           '_POSIX_QLIMIT', 'GPG_ERR_ECHILD', 'GCRYCTL_IS_SECURE',
           'GPG_ERR_INV_BER', 'AF_PPPOX', 'GPG_ERR_EUSERS',
           'mpi_set_opaque', 'gcry_ac_key_pair_generate',
           '__sched_param', 'GPG_ERR_EBADMSG', 'GCRY_LOG_INFO',
           'GPG_ERR_EXDEV', '__socklen_t', 'MSG_EOR',
           'GPG_ERR_ECHRNG', 'gcry_handler_no_mem_t',
           'GPG_ERR_INTERNAL', 'gcry_md_setkey', 'gcry_md_get_asnoid',
           'LONG_MIN', 'otrl_auth_start_v1', 'otrl_auth_start_v2',
           'MSG_DONTROUTE', '_POSIX_OPEN_MAX', 'gcry_mpi_randomize',
           'PF_SECURITY', 'OTRL_AUTHSTATE_AWAITING_DHKEY', 'send',
           'va_end', 'GPG_ERR_INV_PARAMETER', 'gcry_cipher_algos',
           '_pthread_descr_struct', 'GPG_ERR_UNSUPPORTED_CMS_VERSION',
           'gcry_ac_key_spec_rsa_t', 'GPG_ERR_BUG',
           'otrl_context_forget_all', 'gcry_module',
           'GCRYCTL_INITIALIZATION_FINISHED_P', '__ASMNAME',
           'GCRY_PK_RSA', 'GPG_ERR_EPROGUNAVAIL',
           'GCRY_ERR_SOURCE_DEFAULT', 'GPG_ERR_EL2NSYNC', 'memset',
           'GCRYCTL_GET_KEYLEN', 'GPG_ERR_EIDRM', 'strcasestr',
           'GPG_ERR_SOURCE_KEYBOX', 'MSG_NOSIGNAL',
           '__USE_POSIX199309', 'GCRYCTL_INIT_SECMEM', 'index',
           'gcry_ac_data_clear', 'gcry_cipher_spec',
           'OTRL_AUTHSTATE_AWAITING_SIG', 'GCRY_MD_TIGER',
           'gcry_pk_testkey', 'MSG_TRYHARD', 'settimeofday',
           'otrl_message_receiving', 'otrl_privkey_sign',
           'GCRYMPI_FMT_NONE', 'gcry_mpi_swap',
           'GPG_ERR_SEXP_BAD_OCT_CHAR', 'gcry_sexp_cadr',
           'GPG_ERR_ENETDOWN', 'GPG_ERR_ENOCSI', '__PMT',
           'GPG_ERR_INV_PASSPHRASE', '__pthread_cond_align_t',
           'getsockopt', 'fsfilcnt64_t', 'gcry_pk_decrypt',
           'GPG_ERR_EL2HLT', 'otrl_dh_session_blank',
           'GPG_ERR_NO_SIGNATURE_SCHEME', '__fsblkcnt64_t',
           'gcry_mpi_print', 'gcry_ac_handle', 'GPG_ERR_WRONG_SECKEY',
           'BIG_ENDIAN', 'msghdr', 'GcryCipherHd',
           '__USE_XOPEN_EXTENDED', 'timer_t', 'linger',
           'GCRYCTL_FAST_POLL', 'PF_BLUETOOTH', 'SO_DONTROUTE',
           'GCRYCTL_DUMP_MEMORY_STATS', 'GCRY_MD_SHA1',
           'gcry_md_get_algo_dlen', 'GPG_ERR_COMPR_ALGO',
           'GCRY_CIPHER_RIJNDAEL256', 'GPG_ERR_UNUSABLE_PUBKEY',
           'OTRL_POLICY_SEND_WHITESPACE_TAG', '_POSIX_SYMLINK_MAX',
           'GPG_ERR_EAFNOSUPPORT', 'gcry_mpi_set_flag',
           'otrl_privkey_fingerprint', 'key_t', 'GPG_ERR_ENODEV',
           'otrl_auth_clear', 'ITIMER_VIRTUAL', 'bind',
           '__socket_type', 'gcry_pk_sign_t', 'GPG_ERR_INV_REQUEST',
           'ssize_t', 'otrl_auth_handle_commit', 'sa_family_t',
           's_OtrlMessageAppOps', 'GPG_ERR_INV_TIME', '__USE_XOPEN',
           'gcry_random_bytes', 'GPG_ERR_SEXP_UNMATCHED_PAREN',
           'GCRYCTL_ENABLE_QUICK_RANDOM', 'GPG_ERR_ELIBACC',
           'gcry_xmalloc', 'gcry_mpi', 'GPG_ERR_INV_ARMOR',
           'GPG_ERR_ESPIPE', 'LITTLE_ENDIAN', 'MSG_TRUNC',
           'gcry_set_allocation_handler', 'gcry_md_final_t',
           'fingerprint', 'GPG_ERR_PROTOCOL_VIOLATION',
           'gcry_pk_algos', 'gcry_thread_cbs', 'otrl_message_sending',
           '__int32_t', 'mpi_tdiv', 'GPG_ERR_NO_USER_ID',
           'gcry_mpi_set_bit', 'GCRY_PRIME_CHECK_AT_FINISH',
           'gcry_pk_ctl', 'clock_t', 'GPG_ERR_EMLINK',
           'OTRL_MSGTYPE_QUERY', 'GPG_ERR_CARD', 'mpi_cmp',
           'GPG_ERR_ENAMETOOLONG', 'GPG_ERR_TRUSTDB', 'GPG_ERR_EAUTH',
           '__SOCKADDR_COMMON_SIZE', 'PF_ASH', 'GPG_ERR_NOT_TRUSTED',
           '__BYTE_ORDER', 'ucred', 'OTRL_FRAGMENT_COMPLETE',
           'OTRL_MSGTYPE_UNKNOWN', 'gcry_cipher_hd_t', 'SO_BSDCOMPAT',
           'otrl_message_free', '__gnuc_va_list',
           'GPG_ERR_SOURCE_GCRYPT', 'gcry_mpi_subm', '__ss_aligntype',
           'mpi_secure_new', 'otrl_tlv_seriallen', 'bcopy',
           '_POSIX2_CHARCLASS_NAME_MAX', '__USE_SVID',
           'gcry_cipher_modes', 'AF_ROUTE', 'CHARCLASS_NAME_MAX',
           'OTRL_MSGTYPE_REVEALSIG', 'gcry_md_open', 'PF_UNSPEC',
           'GPG_ERR_ESOCKTNOSUPPORT', 'strcasecmp',
           'GCRYSEXP_FMT_BASE64', 'gcry_random_add_bytes',
           'gcry_mpi_mul', 'GPG_ERR_EGREGIOUS', 'OFFER_SENT',
           '__uint8_t', 'mpi_mul', '__u_char', '__sig_atomic_t',
           '_SYS_SOCKET_H', 'otrl_privkey_read_fingerprints',
           'SO_SNDTIMEO', 'GPG_ERR_ERANGE', 'gcry_md_algos',
           'gcry_err_make_from_errno', 'gcry_cipher_algo_name',
           '_GCRY_PTH_SOCKLEN_T', 'gcry_pk_spec', 'ARG_MAX',
           'mpi_powm', 'gcry_thread_option', 'GPG_ERR_EUNATCH',
           'NL_ARGMAX', 'GCRYMPI_FMT_STD', 'GPG_ERR_SOURCE_DEFAULT',
           'PF_DECnet', 'MSG_DONTWAIT', 'AF_NETLINK',
           'gcry_mpi_add_ui', 'gcry_cipher_handle',
           'GPG_ERR_BAD_CERT', 'OtrlTLV', 'GPG_ERR_AMBIGUOUS_NAME',
           'GPG_ERR_EBACKGROUND', 'gcry_cipher_info',
           'GPG_ERR_INV_MAC', 'OtrlPrivKey',
           'GCRYCTL_USE_SECURE_RNDPOOL', '__quad_t', '__uid_t',
           'utimes', 'GCRY_AC_RSA', 'OTRL_NOTIFY_WARNING',
           'GCRYCTL_SET_CBC_CTS', 'OtrlNotifyLevel',
           '__USE_LARGEFILE64', 'OTRL_MSGTYPE_V1_KEYEXCH', 'strtok',
           'GPG_ERR_SEXP_ZERO_PREFIX', 'OTRL_NOTIFY_ERROR',
           'GPG_ERR_SEXP_BAD_CHARACTER', '__RLIM64_T_TYPE',
           'GPG_ERR_EOF', 'NZERO', 'bcmp', 'strxfrm_l',
           'GPG_ERR_ESTRPIPE', '__itimer_which_t', 'memcpy',
           'OTRL_SESSIONID_FIRST_HALF_BOLD', 'GPG_ERR_RESOURCE_LIMIT',
           '__bos', 'gcry_fast_random_poll', '__ssize_t',
           'gcry_cipher_register', 'gcry_prime_release_factors',
           'int16_t', 'stpcpy', '__sigset_t', 'SO_SNDBUF',
           'GCRY_MD_RMD160', 'GPG_ERR_INV_VALUE',
           '_POSIX2_BC_DIM_MAX', 'GPG_ERR_EPROTO', 'GPG_ERR_ENXIO',
           'GPG_ERR_INV_OP', 'GPG_ERR_INV_CRL_OBJ',
           'gcry_ac_key_spec_rsa', 'gcry_pk_encrypt_t', 'MAX_INPUT',
           'GPG_ERR_E2BIG', '_ENDIAN_H', 'gcry_pk_get_keygrip',
           'gcry_md_oid_spec', 'ushort', 'clockid_t', 'GPG_ERR_ESRCH',
           'caddr_t', 'OTRL_VERSION_MINOR', 'PF_INET',
           'GPG_ERR_INV_RESPONSE', '__USE_MISC', 'mpi_add',
           'GPG_ERR_BAD_BER', 'PF_INET6', 'va_arg', 'gcry_md_list',
           'GPG_ERR_CARD_NOT_INITIALIZED', 'GPG_ERR_SOURCE_GPGAGENT',
           'GPG_ERR_EISCONN', 'PF_UNIX', 'GCRY_CIPHER_MODE_STREAM',
           '__dev_t', 'GCRYCTL_SET_CBC_MAC', '_SYS_SYSMACROS_H',
           'gcry_log_levels', 'gcry_mpi_powm', 'gcry_mpi_add',
           'gcry_md_is_secure', '__USE_POSIX199506', '__S64_TYPE',
           '__BIG_ENDIAN', 'int64_t', 'GPG_ERR_NO_ENCODING_METHOD',
           'GCRYSEXP_FMT_CANON', 'GCRYMPI_FMT_USG', 'GCRY_AC_DSA',
           'strcasecmp_l', 'GCRYCTL_SET_IV', 'recvmsg',
           'GPG_ERR_EBADFD', 'GCRYCTL_RESUME_SECMEM_WARN', 'context',
           '__strtok_r', 'gcry_handler_alloc_t', '__ino_t',
           'gcry_set_gettext_handler', 'GCRY_THREAD_OPTION_USER',
           'GPG_ERR_ECONNABORTED', 'MSG_MORE',
           'GPG_ERR_CORRUPTED_PROTECTION', 'PF_ECONET', 'gcry_malloc',
           'GPG_ERR_EMULTIHOP', 'GPG_ERR_ENAVAIL', 'MAX_CANON',
           'GCRY_LOG_WARN', 'gcry_md_read_t', 'OtrlMessageState',
           '__ino64_t', '_SS_PADSIZE', 'GPG_ERR_ELIBBAD',
           'gcry_md_flags', 'GCRYCTL_DISABLE_SECMEM',
           'GPG_ERR_DIGEST_ALGO', 'gcry_random_level',
           '_SYS_SELECT_H', 'gcry_cipher_oid_spec',
           'gcry_handler_free_t', 'strcpy',
           'OTRL_AUTHSTATE_AWAITING_REVEALSIG', 'ULONG_LONG_MAX',
           'gcry_md_is_enabled', 'GCRYCTL_SET_CTR',
           '__clock_t_defined', 'gcry_sexp_build', 'gcry_ac_data',
           'GPG_ERR_KEY_EXPIRED', 's_OtrlTLV', 'gcry_ac_key_t',
           'gpg_error_t', 'OTRL_TLV_PADDING', 'GPG_ERR_NOTHING_FOUND',
           'otrl_dh_init', 'otrl_proto_fragment_accumulate',
           'GPG_ERR_TRIBUTE_TO_D_A', 'ConnContext', '__stpncpy',
           'gcry_md_hash_buffer', 'GCRY_CIPHER_RFC2268_128',
           'gcry_handler_realloc_t', 'socket',
           'gcry_err_code_from_errno', 'GPG_ERR_BAD_PASSPHRASE',
           '_SS_SIZE', 'GPG_ERR_BAD_CA_CERT', 'memchr',
           'gcry_prime_group_generator', 'GPG_ERR_PIN_ENTRY',
           'gcry_ac_data_verify', 'gcry_ac_key_get_nbits',
           '__USE_UNIX98', 'CHILD_MAX', '__timezone_ptr_t',
           'GCRYMPI_FMT_PGP', 'OTRL_POLICY_ALLOW_V2',
           'OTRL_POLICY_ALLOW_V1', '__gid_t', 'sockatmark',
           'gcry_md_write', 'GPG_ERR_EINPROGRESS',
           'gcry_ac_key_get_grip', '__daddr_t', 'OFFER_REJECTED',
           'GPG_ERR_ENOENT', 'GCRY_SEXP', 'GCRY_CIPHER_TWOFISH',
           'GCRY_MD_CRC32', 'locale_data', 'GCRY_MD_MD4',
           'GCRY_MD_MD5', 'MSG_PROXY', 'GCRY_MD_MD2',
           'GCRY_PK_USAGE_SIGN', 'strspn', 'GPG_ERR_TRUNCATED',
           'mpi_rshift', 'sockaddr', 'strndup', 'GPG_ERR_INV_INDEX',
           'OFFER_ACCEPTED', 'gcry_md_handle', 'OTRL_MSGTYPE_DH_KEY',
           '__va_copy', 'GPG_ERR_NOT_ENCRYPTED', 'GCRY_LOG_FATAL',
           'GPG_ERR_MISSING_CERT', 'PTHREAD_KEYS_MAX', 'FD_SETSIZE',
           'gcry_mpi_addm', 'gcry_sexp_find_token', 'otrl_dh_session',
           'GPG_ERR_SEXP_BAD_HEX_CHAR', 'GPG_ERR_SIG_EXPIRED',
           'GCRYCTL_GET_ASNOID', 'GPG_ERR_UNSUPPORTED_CRL_VERSION',
           'GPG_ERR_INV_ARG']
