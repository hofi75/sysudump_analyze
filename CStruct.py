
from memory import Memory
import copy

class CField:
	name = ""
	pointer = False
	offset = 0
	size = 0
	alignment = 0

	def __init__( self, name):
		self.name = name

	def set_offset( self, offset: int):
		self.offset = offset
		if self.alignment != 0:
			self.offset = self.offset + self.alignment - 1
			self.offset &= 0xffffffff - self.alignment + 1;

	def get_offset( self) -> int:
		return seld.offset

	def get_size( self) -> int:
		return self.size

class ctype_long( CField):

	def __init__( self, name: str):
		self.name = name
		self.size = 4
		self.alignment = 4

	def get_value( self, memory: Memory, address: int):
		b = memory.get_memory_block( address, self.size)
		value = int.from_bytes( b, byteorder='big', signed=False)
		return { "%s(int)[%.8X]" % ( self.name, self.offset) : "%d(0x%.4X)" % ( value, value) }

class ctype_short( CField):

	def __init__( self, name: str):
		self.name = name
		self.size = 2
		self.alignment = 2

	def get_value( self, memory: Memory, address: int):
		b = memory.get_memory_block( address, self.size)
		value = int.from_bytes( b, byteorder='big', signed=False)
		return { "%s(short)[%.4X]" % ( self.name, self.offset) : "%d(0x%.4X)" % ( value, value) }

class ctype_void( CField):

	def __init__( self, name: str):
		self.name 		= name
		self.size 		= 4
		self.alignment	= 4

	def get_value( self, memory: Memory, base: int):
		print( "get_value(%s@%.8X) -->" % (self.name, base))
		b = memory.get_memory_block( base, self.size)
		return { "%s(void *)[%.8X]" % ( self.name, self.offset) : "0x%.8X" % ( int.from_bytes( b, byteorder='big', signed=False)) }

class ctype_char( CField):

	def __init__( self, name: str, size: int, dump=False, encoding='cp500'):
		self.name 		= name
		self.size 		= size
		self.alignment	= 0
		self.encoding	= encoding
		self.dump		= dump

	def get_value( self, memory: Memory, base: int):
		print( "get_value(%s@%.8X) -->" % (self.name, base))
		mb = memory.get_memory_block( base, self.size)
		rslt = dict()
		rslt["%s(char[%d])[%.8X]" % ( self.name, self.size, self.offset)] = bytearray.decode( mb, encoding=self.encoding, errors='ignore').rstrip('\0')
		if self.dump:
			for i in range(0, self.size, 16):
				rslt["dump[%.8X:%.4X]" % (base + i, i) ] = bytearray.hex( mb[i:i+15])
		return rslt

class CStruct:
	name 		= ""
	fields		= []
	size		= 0
	offset		= 0

	def gen_field( name, ftype, size=0, pointer=False, dim=1):
		return { "name" : { "type" : ftype, "size" : size, "pointer" : pointer, "dim" : dim, "offset" : 0}}

	pcx = list()
	pcx.append( gen_field( "ID", "char", 4))
	pcx.append( gen_field( "SubID", "char", 3))
	pcx.append( gen_field( "exHost", "char", 4))

	zulogg = list()
	zulogg.append( gen_field( "ID", 		"char", 4))
	zulogg.append( gen_field( "filename", 	"char", 128))
	zulogg.append( gen_field( "fcb", 		"void"))
	zulogg.append( gen_field( "hlpHandle", "void"))
	zulogg.append( gen_field( "msgFlg",	"long"))
	zulogg.append( gen_field( "pFirstMsg", "void"))
	zulogg.append( gen_field( "pLastMsg",	"void"))
	zulogg.append( gen_field( "msgCount",	"long"))
	zulogg.append( gen_field( "orig_stdout", "void"))
	zulogg.append( gen_field( "logIndex",	"long"))
	zulogg.append( gen_field( "logCount",	"long"))
	zulogg.append( gen_field( "lock", 		"void"))

	definition = [
		{ "PCX" : pcx },
		{ "WAR_ZULOGG": zulogg }
	]

	def calculate_offsets( self):
		for sname, struct in self.definition:
			print( "Processing structure '%s'" % sname)
			offset = 0
			for fname, field in struct:
				print( "Processing field '%s'" % fname)

	def __init__( self, name: str):
		self.name		= name
		self.offset		= 0
		self.calculate_offsets()

	def get_size( self):
		return self.size

	def get_offset( self):
		return self.offset

	def set_offset( self, offset):
		self.offset = offset

	def add_field( self, pfield, dim=1, pointer=False):		
		for i in range(dim):
			field = copy.copy(pfield)
			if dim != 1:
				field.name = "%s[%d]" % (pfield.name, i)
			field.set_offset( self.size)
			self.size = field.offset
			if pointer:
				self.size += 4
			else:
				self.size += field.get_size()
			field.pointer = pointer
			print( "Adding field '%s'[%d,size=%d] to '%s'" % ( field.name, field.offset, field.size, self.name))
			self.fields.append( field)
	
	def get_value( self, memory: Memory, paddress: int):
		rslt = { "%s[%.8X-%.8X]" % ( self.name, self.offset, paddress) : self.name, "content" : None}
		print( "get_value(%s) -->" % self.name)
		print( paddress)
		content = []
		for field in self.fields:
			if field.pointer:
				address = memory.get_pointer_be( paddress + field.offset)
			else:
				address = paddress + field.offset
			print( "processing %s.%s[0x%.8X]" % ( self.name, field.name, address))
			content.append( field.get_value( memory, address))
		rslt["content"] = content
			
		return rslt

class WAR_ZULOGG(CStruct):

	def __init__( self, name="WAR_ZULOGG"):
		self.name = name
		self.fields = list()
		self.offset = 0
		self.add_field( ctype_char( "ID", 4))
		self.add_field( ctype_char( "filename", 128))
		self.add_field( ctype_void( "fcb"))
		self.add_field( ctype_void( "hlpHandle"))
		self.add_field( ctype_long( "msgFlg"))
		self.add_field( ctype_void( "pFirstMsg"))
		self.add_field( ctype_void( "pLastMsg"))
		self.add_field( ctype_long( "msgCount"))
		self.add_field( ctype_void( "orig_stdout"))
		self.add_field( ctype_long( "logIndex"))
		self.add_field( ctype_long( "logCount"))
		self.add_field( ctype_void( "lock"))

class PCX(CStruct):

	def __init__( self, name="pcx"):
		self.name = name
		self.fields = list()
		self.offset = 0
		self.add_field( ctype_char( "ID", 4))
		self.add_field( ctype_char( "SubID", 3))
		self.add_field( ctype_char( "exHost", 33))
		self.add_field( ctype_char( "version", 256))
		self.add_field( ctype_char( "exSystem", 33))
		self.add_field( ctype_char( "Language", 1))
		self.add_field( ctype_char( "Language2", 1))
		self.add_field( ctype_char( "pathBin", 64))
		self.add_field( ctype_char( "pathTmp", 64))
		self.add_field( ctype_long( "hlpHnd"))
		self.add_field( WAR_ZULOGG( "logHnd"), pointer=True)
		self.add_field( ctype_long( "trcHnd"))
		self.add_field( ctype_char( "trcFlags", 16))
		self.add_field( ctype_void( "firstFH"))
		self.add_field( ctype_void( "firstFT"))
		self.add_field( ctype_void( "firstFTDir"))
		self.add_field( ctype_void( "firstJOB"))
		self.add_field( ctype_void( "firstREP"))
		self.add_field( ctype_void( "firstEF"))
		self.add_field( ctype_void( "firstFF"))
		self.add_field( ctype_long( "iPrimaryCpPort"))
		self.add_field( ctype_long( "portNr"))
		self.add_field( ctype_char( "bindaddr", 256))
		self.add_field( ctype_char( "iniFile", 55))
		self.add_field( ctype_char( "exJobName", 16))
		self.add_field( ctype_char( "exJobID", 16))
		self.add_field( ctype_char( "exUser", 16))
		self.add_field( ctype_void( "firstSocket"))
		self.add_field( ctype_long( "connWaitTime"))
		self.add_field( ctype_long( "connectTime"))
		self.add_field( ctype_long( "checkTime"))
		self.add_field( ctype_long( "timerTime"))
		self.add_field( ctype_long( "aliveTime"))
		self.add_field( ctype_long( "reportTime"))
		self.add_field( ctype_char( "report_typ", 8))
		self.add_field( ctype_long( "report_id"))
		self.add_field( ctype_long( "report_blksize"))
		self.add_field( ctype_long( "lastConnectTime"))
		self.add_field( ctype_long( "lastReportTime"))
		self.add_field( ctype_long( "lastCheckTime"))
		self.add_field( ctype_long( "lastAliveTime"))
		self.add_field( ctype_long( "lEventCount"))
		self.add_field( ctype_void( "addr_ecb_write_signal"))
		self.add_field( ctype_long( "completeJobout"))
		self.add_field( ctype_short( "sRelMsgClass"))
		self.add_field( ctype_char( "cGetMsgClass", 36))
		self.add_field( ctype_char( "cRouteMsgClass", 36))
		self.add_field( ctype_short( "sJobPurge"))
		self.add_field( ctype_char( "cUseChiffre", 1))
		self.add_field( ctype_char( "cStartTyp", 1))
		self.add_field( ctype_char( "Ft_Temp_File", 1))
		self.add_field( ctype_void( "firstEV"))
		self.add_field( ctype_void( "firstFHEvent"))
		self.add_field( ctype_long( "iSrvCnt"))
		self.add_field( ctype_long( "askRACF"))
		self.add_field( ctype_char( "cJESName", 8))
		self.add_field( ctype_long( "tStartTime"))
		self.add_field( ctype_void( "sStartTime"))
		self.add_field( ctype_long( "iAbnormalEnd"))
		self.add_field( ctype_short( "sMakeJobCard"))
		self.add_field( ctype_short( "sReportMethod"))
		self.add_field( ctype_short( "sWaitOnJobEnd"))
		self.add_field( ctype_short( "sJobACF2"))
		self.add_field( ctype_short( "sSBBFlg"))
		self.add_field( ctype_long( "lastAliveTimeEx"))
		self.add_field( ctype_short( "sJobAccount"))
		self.add_field( ctype_short( "sExAktjQu"))
		self.add_field( ctype_short( "sJobMd"))
		self.add_field( ctype_short( "sVanishedRetry"))
		self.add_field( ctype_short( "lDefaultCode"))
		self.add_field( ctype_void( "pDefaultCode"))
		self.add_field( ctype_char( "code2ascii", 256, dump=True))
		self.add_field( ctype_char( "code2ebcdic", 256, dump=True))

"""
typedef struct EX_PCX
{
  char            code2ascii [256];  /* default translate tables */
  char            code2ebcdic[256];
  int             joinreadFlg;    /* Passwort aus Join lesen      */
  int             waitOnCPs;
  short           sWaitSpoolReady;
  short           sWaitSpoolRetry;
  long            lJoboutputPriCyl;
  long            lJoboutputSecCyl;
  short           sDebug32106;
  short           sDebugUnused;
  int             loop;
#define LOOP_END                0
#define LOOP_RUNNING            1
#define LOOP_WAIT_TASKS         3
#define LOOP_WAIT_SOCKETS       4
  int             flagEXSTARTQ;  /* wenn der Executor die EXTSTARTQ
                                    erhalten hat, darf er seinen
                                    selbst generierte nachrichten
                                    an der Server schicken */
// JCL-Exit specific area
  char            JEName[8];
  int             maxJclRecords;
  void            *JclExitEntryPoint;
  char            *JCLOrig;
  char            *JCLNew;
  int             logIndex;       /* actual LOGnnnnn index        */
  char            logPurgeClass;
  int             logCount;
  long            ft_compress_strong;
  short           sIgnoreEmptyJCL; /* 1 = yes                     */
                                   /* 0 = no                      */
  int             cpNumber;
  void            *hTcpMsg;
  int             ft_performance_test;  /* 0/1 */
  int             max_file_count;
  long            srv_session_counter;

  // GSS related datas
   gss_name_t           sName;
   int                  iGssQop;
   char                 enc_comp; /* from EXSTARTQ */
   char                 cKStoreName[128];
   char                 cPIAttrib[128];

   // flags
   unsigned int         flag1;
#define PFLG1_FIRST_EXSTARTQ_ARRIVED 0x00000001
#define PFLG1_EM_SUBTASK             0x00000002
#define PFLG1_LOG_TO_DB              0x00000004
#define PFLG1_PASSWORD_MIXEDCASE     0x00000008
#define PFLG1_SIMULATE_FTX_ERROR     0x00000010
#define PFLG1_TEMP_FILE_USS          0x00000020
#define PFLG1_ANONYMOUS_FT           0x00000040
#define PFLG1_ANONYMOUS_JOB          0x00000080
#define PFLG1_DELETED_SOCKET         0x00000100
#define PFLG1_NAGEL_AGENT            0x00000200
#define PFLG1_NAGEL_FT               0x00000400
#define PFLG1_USE_MD5                0x00000800
#define PFLG1_CHANGE_LOG             0x00001000 // singnal tcp thread
#define PFLG1_CHANGE_TRACE           0x00002000 // singnal tcp thread
#define PFLG1_SHUTDOWN               0x00004000 // in shutdown process
#define PFLG1_NEW_SOCKET             0x00008000 // socket was created
#define PFLG1_AGENT_SHELL            0x00010000 // agent shell allowed
#define PFLG1_SRVINFO_PROTOCOLED     0x00020000
#define PFLG1_EXSTARTQ               0x00040000 // exstartq arrived
#define PFLG1_FORCE_TIMER            0x00080000 // force start timer
#define PFLG1_THREAD_LEVEL_SECURITY  0x00100000
#define PFLG1_FH_VERSION_2           0x00200000
#define PFLG1_JOBSUBMITCONTEXT_USER     0x00400000
#define PFLG1_CHECK_SCHENV              0x00800000
#define PFLG1_CHECK_INITIATOR_SYSPLEX   0x01000000
#define PFLG1_CHECK_INITIATOR_SYSTEM    0x02000000
#define PFLG1_CHECK_DUPLICATE_JOB       0x04000000
#define PFLG1_LOG_JOB_BLOCKING_REASON   0x08000000
#define PFLG1_CP_SELECT_PROGRESS        0x10000000

   void                 *savedLogging;

   struct __ftxArea     *firstFTX;
   pthread_rwlock_t     ftxLock;

   struct __uc_thread   *main_thread;

   pthread_rwlock_t     socketsLock;      // rwlock for socket table
   pthread_mutex_t      socketsReentryLock;
   int                  socketsLockCount; // number of locks

   /* FTX related variables */
   SBB_INT_16           ft_rst_life;     // restart info lifetime
   SBB_INT_16           ft_rst_check_hh; // status store check abs time
   SBB_INT_16           ft_rst_check_mm;
   SBB_INT_16           ft_rst_check_ss;
   time_t               ftx_cleanup_time; // next cleanup time
   SBB_INT_16           ft_stat_timer;   // ftxsta timer
   SBB_INT_16           ft_rst_timer;    // restart info timer
   SBB_INT_16           ft_con_timeout;  // connection timeout
 /* TO DELETE: FT_USE_MD5 */
   SBB_INT_16           ft_use_md5;      // usage of md5
   SBB_INT_16           ft_report_time;  // reporting timer

   time_t               force_stop_time;

   msgconv_ctx_t        msgconv2_ctx;   // msgconv2 context

   unsigned int         simflag;
#define  SIMERR_THREAD_CREATE        0x00000001
#define  SIMERR_FAKE_LISTEN_SIGNAL   0x00000002
#define  SIMULATE_JOB_BLOCKING       0x00000004
   int                  logMsgProcessing;

   char                 *wbuffer64K;  // working buffer SIZE_64K

#define WLM_MAX_SYSTEMS  32
   int                  nof_systems;
   char                 systems[WLM_MAX_SYSTEMS][16];
   char                 default_jobclass;

   // agent effective user id
   uid_t                aeuid;
   gid_t                aegid;
   pthread_mutex_t      aeuid_lock;
   int                  aeuid_flag;
#define AEUID_INQUIRED  0x00001
#define AEUID_SWITCHED  0x00002  // agent runs under user euid

#define aeuid_inquired \
   flag_test( pcx->aeuid_flag, AEUID_INQUIRED)
#define aeuid_switched \
   flag_test( pcx->aeuid_flag, AEUID_SWITCHED)

	LLIST_DEFINE( ip_entry_t, trusted_ip_list)

   char                 patch[60];
} _ex_pcx, PCX;

"""