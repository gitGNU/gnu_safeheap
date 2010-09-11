/*
  Safeheap detects double free, unallocated free, unallocated realloc, buffer overrun,
  underrun, unallocated src buffer usage, ininitialized src buffer usage
  through strcpy, strncpy, strcat, strncat, memcpy, memmove, and memset.
  Upon detecting abobe cases, applicaiton would be stopped with segmentation fault.
  This makes it easier to debug the application. 

  Copyright (C) 2009,2010 Ravi Sankar Guntur <ravisankar.g@gmail.com>
  
  Safeheap is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation, either version 3
  of the License, or any later version.
 
  Safeheap is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Safeheap.  If not, see <http://www.gnu.org/licenses/>.

*/


#define _GNU_SOURCE
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <error.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <execinfo.h>

#define __VERSION "0.20"
#define SH_LIBC_VER "/lib/libc.so.6"
#define _SH_WARN "a fool is still a fool even with a tool"

#define _BT_LABEL "\nBacktrace ...\n"
#define _MAPS_LABEL "\nProcess maps information is ..\n"
#ifdef _SLP
#define _SAFELOGFILE "/var/log/safeheap.log"
#else
#define _SAFELOGFILE "safeheap.log"
#endif
#define __RSIGNATURE1__ 0xdeadbeaf
#define __RSIGNATURE2__ 0xabcdefff
#define __FSIG1__ 0xcafebabe
#define __FSIG2__ 0xdeaffeed
#define __HEADER_LEN__ 4 + 4 + 4	// size, sig1, sig2
#define __FOOTER_LEN__ 4 + 4	// sig1 sig2
#define __BT_SIZE 100
#define _UNDEFINED 0x2		//STX: Ctrl char
#define true 1
#define false 0
#define _SIG_NOT_FOUND -9999
#define _INVALID_BUFFER (_SIG_NOT_FOUND+1)

/* Type to use for aligned memory operations.
 * This should normally be the biggest type supported by a single load
 * and store.  Must be an unsigned type.  */
#define shop_t	unsigned long int
#define SHOPSIZ (sizeof(shop_t))
#define powerof2(x)	((((x)-1)&(x))==0)
static pthread_mutex_t _lock1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t _lock2 = PTHREAD_MUTEX_INITIALIZER;
static FILE *fp = NULL;
static char format[200];
static int logfd = 0;
static char *caltime = NULL;
static char logfile_name[100];
static int _err_caught;
static int *__first_alloc = NULL;

typedef struct _sh_map_info
{
  void *base;
  int size;
  void *end;
  struct _sh_map_info *next;
} _sh_map_info_t;

static _sh_map_info_t *_sh_map_info;

/*	doug lea's routines	*/
extern void *dlcalloc (size_t, size_t);
extern void *dlmalloc (size_t);
extern void dlfree (void *);
extern void *dlrealloc (void *, size_t);
extern void *dlmemalign (size_t, size_t);
extern void *dlvalloc (size_t);

/*	libc handle	*/
static void *handle = NULL;

/*	libc string utility function ptrs	*/
static char *(*_dlstrcpy) (char *dst, const char *src) = NULL;
static char *(*_dlstrncpy) (char *dst, const char *src, size_t len) = NULL;
static char *(*_dlstrcat) (char *dst, const char *src) = NULL;
static char *(*_dlstrncat) (char *dst, const char *src, size_t len) = NULL;
static void *(*_dlmemcpy) (void *dest, const void *src, size_t n) = NULL;
static void *(*_dlmemmove) (void *dest, const void *src, size_t n) = NULL;
void *internal_memset (void *s, int c, size_t n);
void *internal_memcpy (void *dest, const void *src, size_t n);
__attribute__ ((constructor))
     void
     init (void);
__attribute__ ((destructor))
     void
     deinit (void);

/*
 *	Public functions
 */
/*	alternate  malloc fucntions 	*/
     void *
     calloc (size_t, size_t);
     void *
     malloc (size_t);
     void
     free (void *);
     void *
     realloc (void *, size_t);
     void *
     memalign (size_t, size_t);
     void *
     valloc (size_t);
     int
     posix_memalign (void **memptr, size_t alignment, size_t size);

/*	hijacked string manipulaiton functions	*/
     char *
     strcpy (char *dst, const char *src);
     char *
     strncpy (char *dst, const char *src, size_t len);
     char *
     strcat (char *dst, const char *src);
     char *
     strncat (char *dst, const char *src, size_t len);
     void *
     memcpy (void *dest, const void *src, size_t n);
     void *
     memmove (void *dest, const void *src, size_t n);
     void *
     memset (void *s, int c, size_t n);

     void
     _get_time (void)
{
  time_t result;
  result = time (NULL);
  caltime = ctime (&result);
}

/*	Generate & prints bt to logfile	*/
static void
bt (void)
{
  int nptrs;

  /*    3 for safeheap  */
  void *buffer[__BT_SIZE];
  nptrs = backtrace (buffer, __BT_SIZE);
  write (logfd, _BT_LABEL, (sizeof (_BT_LABEL)-1));
  backtrace_symbols_fd (buffer, nptrs, logfd);
  write (logfd, "\n", (sizeof ("\n")-1));
  return;
}


/*	Raise segmentation fault 	*/
static int
__bt (int bail_out)
{
  bt ();
  _err_caught = 1;		// not to remove the log file by deinit upon exit

#ifdef _test_suite		// irresepctive of bailout option, we proceed.
  return 0;

#else /*  if bailout is set, then fatal err is detected. deinit and raise SIGSEGV */
  if (bail_out)
    {
      deinit ();
      return raise (SIGSEGV);
    }
  else
    return 0;
#endif /*  */
}


/*	memory alloc lock	*/
static int
_do_lock1 (void)
{
#ifdef _DEBUG_ON
  printf ("_do_lock1: enter\n");
#endif
  int err = pthread_mutex_lock (&_lock1);
  if (err)
    {
      perror ("pthread_mutex_lock1: ");
      abort ();
    }
#ifdef _DEBUG_ON
  printf ("_do_lock1: leave\n");
#endif
  return err;
}


/*	memory alloc lock	*/
static int
_undo_lock1 (void)
{
#ifdef _DEBUG_ON
  printf ("_undo_lock1: enter\n");
#endif
  int err = pthread_mutex_unlock (&_lock1);
  if (err)
    {
      perror ("pthread_mutex_unlock1: ");
      abort ();
    }
#ifdef _DEBUG_ON
  printf ("_undo_lock1: leave\n");
#endif
  return err;
}


/*	log file write lock	*/
static int
_do_lock2 (void)
{
#ifdef _DEBUG_ON
  printf ("_do_lock2: enter\n");
#endif
  int err = pthread_mutex_lock (&_lock2);
  if (err)
    {
      perror ("pthread_mutex_trylock2: ");
      abort ();
    }
#ifdef _DEBUG_ON
  printf ("_do_lock2: leave\n");
#endif
  return err;
}


/*	log file write lock	*/
static int
_undo_lock2 (void)
{
#ifdef _DEBUG_ON
  printf ("_undo_lock2: enter\n");
#endif
  int err = pthread_mutex_unlock (&_lock2);
  if (err)
    {
      perror ("pthread_mutex_unlock2: ");
      abort ();
    }
#ifdef _DEBUG_ON
  printf ("_undo_lock2: leave\n");
#endif
  return err;
}

/*	traverse map info list and get the current buffer size */
static int
_get_me_map_size (void *ptr)
{
  _sh_map_info_t *tmp = _sh_map_info;

  while (tmp != NULL)
    {
      if ((tmp->base <= ptr) && (tmp->end >= ptr))
	return (tmp->size - (ptr - tmp->base));	//gives allowed buffer size
      else
	tmp = (_sh_map_info_t *) tmp->next;
    }
  if (tmp == NULL)
    return _SIG_NOT_FOUND;

  return _SIG_NOT_FOUND;
}

/*	append entry to the map list	*/
static int
_insert_map_info (void *ptr, int size)
{
  _sh_map_info_t *new_node = NULL;

  /*  no nodes        */
  if (_sh_map_info == NULL)
    {
      _sh_map_info = dlmalloc (sizeof (_sh_map_info_t));
      _sh_map_info->base = ptr;
      _sh_map_info->end = (void *) ((int) ptr + size);
      _sh_map_info->size = size;
      _sh_map_info->next = NULL;
    }
  else
    {
      new_node = dlmalloc (sizeof (_sh_map_info_t));
      new_node->base = ptr;
      new_node->end = (void *) ((int) ptr + size);
      new_node->size = size;
      new_node->next = _sh_map_info;
      _sh_map_info = new_node;
    }

  return 0;
}

/*	modify entry in map list	*/
static int
_modify_map_info (void *old, void *new, int size)
{
  _sh_map_info_t *tmp = _sh_map_info;
  /*      go to old node */
  while (tmp != NULL)
    {
      if (tmp->base == old)
	break;
      else
	tmp = (_sh_map_info_t *) tmp->next;
    }
  /*      node not found. insert new one  */
  if (tmp == NULL)
    return _insert_map_info (new, size);
  else
    {
      tmp->base = new;
      tmp->end = (void *) ((int) new + size);
      tmp->size = size;
    }
  return 0;
}

/*	delete  entry in map list	*/
static int
_delete_map_info (void *ptr)
{
  _sh_map_info_t *cur = _sh_map_info;
  _sh_map_info_t *prev = NULL;

  /*      go to last node */
  while (cur != NULL)
    {
      if (cur->base == ptr)
	break;
      else
	{
	  prev = cur;
	  cur = cur->next;
	}
    }
  if (cur == NULL)
    return -1;
  /*  first node      */
  else if (prev == NULL)
    {
      _sh_map_info = cur->next;
      dlfree (cur);
    }
  else
    {
      prev->next = cur->next;
      dlfree (cur);
    }

  return 0;
}

/*	Validate the address. 		
 */
static int
_verify_heap (void *ptr)
{
  void *limit;
  limit = sbrk (0);
  if (__first_alloc)
    {
      if ((ptr < limit) && (ptr > (void *) __first_alloc))
	return 0;

      else
	return 1;
    }
  else
    {
      if ((ptr < limit) && (ptr > (void *) 0x1000))
	return 0;

      else
	return 1;
    }
}

/*
* scans memory to find current location and hopefully get buffer length
* incase of within buffer references. 
*/
static int
_whereami (char *ptr)
{
  int *mem;
  int val;
  int size, offset, allowed;
  char *tmp = ptr;
_HERE:
  if ((int) ptr <= ((int) __first_alloc))
    {
      return _INVALID_BUFFER;
    }
  mem = (int *) ptr;
  val = *mem;
  /*while ((val != (int) __RSIGNATURE2__) && (val != (int) __FSIG2__)) { */
  while (!((val == (int) __RSIGNATURE2__) || (val == (int) __FSIG2__)))
    {
      ptr--;
      if ((int) ptr <= (int) __first_alloc)
	{
	  return _INVALID_BUFFER;
	}
      mem = (int *) ptr;
      val = *mem;
    }

  /*      sig2 match      */
  if (val == (int) __RSIGNATURE2__)
    {
      mem--;			// go to next 4B for sig1
      val = *mem;
      /*      sig1 match      */
      if (val == (int) __RSIGNATURE1__)
	{
	  mem--;		// go to next 4B for size
	  size = *mem;		// size value
	  offset = (int) tmp - (int) mem - ((int) __HEADER_LEN__);
	  if (offset < 0)
	    return _INVALID_BUFFER;	// user data (block-1) 'th address. offset == -1.  
	  allowed = size - offset;
#ifdef _UNDER_DEV
	  printf
	    ("whereamI-4: ptr %p, Header1 %p, Header2 %p, offset %d, allowed %d, size %d\n",
	     tmp, mem, (mem + 1), offset, allowed, size);
#endif

	  /*will always be >=0 */
	  return allowed;
	}
      /*      accidental sig1. go back to find sig1   */
      else
	{
	  ptr--;
	  goto _HERE;
	}
    }
  /*      fsig2 match     */
  else if (val == (int) __FSIG2__)
    {
      mem--;			// go to next 4B for fsig1
      val = *mem;
      if (val == (int) __FSIG1__)
	{
#ifdef _UNDER_DEV
	  printf ("whereamI-5: footer hit\n");
#endif
	  return _INVALID_BUFFER;
	}
      /*      accidental fsig1, go back to find fsig1 */
      else
	{
	  ptr--;
	  goto _HERE;
	}
    }
  else
    {
      printf ("\nwhereamI-6: Should never reach here\n");
    }

  /*should not reach here */
  return _INVALID_BUFFER;
}

/*	Get the signature and hopefully the allocated buffer length
 *	return: _SIG_NOT_FOUND, in case address is not from heap and not malloc( >= 256KB )
		_INVALID_BUFFER, in case address is from heap and not a valid block address
		size >= 0 , in case address is from heap and is a valid block.
 */
static int
_give_me_size (void *ptr)
{
  int *sigptr1, *sigptr2, *sizeptr, *allocptr, *temp;
  size_t size = 0;
  temp = ptr;
  if (_verify_heap (ptr))
    {
      return _get_me_map_size (ptr);
    }
  sigptr2 = (int *) (ptr) - 1;
  sigptr1 = sigptr2 - 1;
  if ((*sigptr1 == (int) __RSIGNATURE1__)
      && (*sigptr2 == (int) __RSIGNATURE2__))
    {
      sizeptr = sigptr1 - 1;
      allocptr = sizeptr;
      size = *sizeptr;
      return size;
    }

  else
    {
      return _whereami ((char *) ptr);
    }
}


/*	wrappers to doug les's malloc allocators 	*/
void *
malloc (size_t size)
{
  int *ptr, *sigptr1, *sigptr2, *sizeptr, *usrptr, *fsigptr1, *fsigptr2;
  size_t alt_size = size + __HEADER_LEN__ + __FOOTER_LEN__;	// for size and sig
  ptr = dlmalloc (alt_size);
  if (ptr == NULL)
    return NULL;
  if (!__first_alloc && ((void *) ptr < sbrk (0)))
    __first_alloc = ptr;	// heap base
  sizeptr = ptr;
  sigptr1 = sizeptr + 1;
  sigptr2 = sigptr1 + 1;
  usrptr = sigptr2 + 1;


  if (size % 4)
    fsigptr1 = usrptr + (size / 4) + 1;
  else
    fsigptr1 = usrptr + (size / 4);
  fsigptr2 = fsigptr1 + 1;

#ifdef _UNDER_DEV
  printf
    ("malloc:%p + %d B. Header1 at %p, Header2 at %p, Footer1 %p, Footer2 %p\n",
     usrptr, size, sizeptr, sigptr1, fsigptr1, fsigptr2);
#endif
  _do_lock1 ();
  *sizeptr = size;		// insert size move
  *sigptr1 = __RSIGNATURE1__;	// insert sig1
  *sigptr2 = __RSIGNATURE2__;	// insert sig2
  *fsigptr1 = __FSIG1__;	// insert footer sig1
  *fsigptr2 = __FSIG2__;	// insert footer sig2
  internal_memset (usrptr, _UNDEFINED, size);	// clear the data

  if ((void *) ptr > sbrk (0))	// m mapped 
    {
      _insert_map_info (usrptr, size);
    }
  _undo_lock1 ();

#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "malloc:%p + %d B\n", usrptr, *sizeptr);
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }

  else
    printf
      ("malloc:%p + %d B. Header1 at %p, Header2 at %p, Footer1 %p, Footer2 %p\n",
       usrptr, size, sizeptr, sigptr1, fsigptr1, fsigptr2);
#endif /*  */
  return usrptr;
}


/*	wrappers to doug les's malloc allocators 	*/
void
free (void *ptr)
{
  int *sigptr1, *sigptr2, *sizeptr, *allocptr, *fsigptr1, *fsigptr2;
  size_t size;
  if (ptr)
    {
      if (_give_me_size (ptr) < 0)
	goto _INVALID_FREE;

      sigptr2 = (int *) (ptr) - 1;
      sigptr1 = sigptr2 - 1;
      sizeptr = sigptr1 - 1;
      allocptr = sizeptr;
      size = *sizeptr;
      if ((*sigptr1 == (int) __RSIGNATURE1__)
	  && (*sigptr2 == (int) __RSIGNATURE2__))
	{
	  if (size % 4)
	    fsigptr1 = (int *) ptr + (size / 4) + 1;
	  else
	    fsigptr1 = (int *) ptr + (size / 4);

	  fsigptr2 = fsigptr1 + 1;
#ifdef _UNDER_DEV
	  printf
	    ("free:%p - %d B, Header1 %p, Header2 %p, fsig1 %p, fsig2 %p\n",
	     ptr, size, sizeptr, sigptr1, fsigptr1, fsigptr2);
#endif
	  if ((*fsigptr1 == (int) __FSIG1__)
	      && (*fsigptr2 == (int) __FSIG2__))
	    {
	      /*      clear the contents so that we dont get accidental sigs  */
	      //memset(sizeptr, _UNDEFINED, __HEADER_LEN__);
	      *sizeptr = _UNDEFINED;
	      *sigptr1 = _UNDEFINED;
	      *sigptr2 = _UNDEFINED;
	      *fsigptr1 = _UNDEFINED;
	      *fsigptr2 = _UNDEFINED;
	      if ((void *) ptr > sbrk (0))	// m mapped 
		{
		  _delete_map_info (ptr);
		}
	      dlfree (sizeptr);
	    }
	  else
	    {
	      pid_t pid = getpid ();

	      if (logfd)
		{
		  _do_lock2 ();
		  sprintf (format,
			   "%s:%d:free-error: footer trampled at %p\n",
			   program_invocation_short_name, pid, ptr);
		  write (logfd, format, strlen (format));
		  _undo_lock2 ();
		}
	      else
		printf ("%s:%d:free-error: sig footer trampled at %p\n",
			program_invocation_short_name, pid, ptr);
	      __bt (true);
	      return;
	    }
	}
      else
	{
	  pid_t pid;
	_INVALID_FREE:pid = getpid ();

	  if (logfd)
	    {
	      _do_lock2 ();
	      sprintf (format, "%s:%d:free-error: invalid free of %p\n",
		       program_invocation_short_name, pid, ptr);
	      write (logfd, format, strlen (format));
	      _undo_lock2 ();
	    }
	  else
	    {
	      printf ("%s:%d:free-error: invalid free of %p\n",
		      program_invocation_short_name, pid, ptr);
	    }
	  __bt (true);
	  return;
	}
    }
  /*      NULL free       */
  else
    {
#if 0
      pid_t pid = getpid ();

      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format, "%s:%d:free-error: attempt to free NULL\n",
		   program_invocation_short_name, pid);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}
      else
	printf ("%s:%d:free-error: attempt to free NULL\n",
		program_invocation_short_name, pid);
      __bt (false);
#endif
      return;
    }

}


/*	wrappers to doug les's malloc allocators 	*/
void *
realloc (void *ptr, size_t size)
{
  int *sigptr1, *sigptr2, *sizeptr, *newptr, *usrptr, *fsigptr1, *fsigptr2;
  int prev_size;

  /*      as per the manpages. the same order of checks were performed    */
  if (ptr == NULL)
    return malloc (size);
  if (size == 0)
    {
      free (ptr);
      return ptr;
    }
  if (_give_me_size (ptr) < 0)
    {
      pid_t pid = getpid ();
      _get_time ();

      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%srealloc-error: previous buffer was not allocated at %p\n",
		   program_invocation_short_name, pid, caltime, ptr);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}
      else
	printf
	  ("%s:%d:%srealloc-error: previous buffer was not allocated  at %p\n",
	   program_invocation_short_name, pid, caltime, ptr);
      __bt (true);
      return ptr;
    }

  sigptr2 = (int *) (ptr) - 1;
  sigptr1 = sigptr2 - 1;
  sizeptr = sigptr1 - 1;
  prev_size = *sizeptr;

  if ((prev_size % 4))
    fsigptr1 = (int *) ptr + (prev_size / 4) + 1;
  else
    fsigptr1 = (int *) ptr + (prev_size / 4);

  fsigptr2 = fsigptr1 + 1;
  if ((*fsigptr1 == (int) __FSIG1__) && (*fsigptr2 == (int) __FSIG2__))
    {
      /*  reset the previous footer       */
      internal_memset (fsigptr1, _UNDEFINED, __FOOTER_LEN__);
    }
  else
    {
      pid_t pid = getpid ();
      _get_time ();

      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%srealloc-error: footer trampled at %p\n",
		   program_invocation_short_name, pid, caltime, ptr);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}
      else
	printf
	  ("%s:%d:%srealloc-error: footer trampled at %p\n",
	   program_invocation_short_name, pid, caltime, ptr);
      __bt (true);
      return ptr;

    }

  size_t alt_size = size + __HEADER_LEN__ + __FOOTER_LEN__;	// for size and sig
  newptr = dlrealloc (sizeptr, alt_size);
  if (newptr == NULL)
    return newptr;
  sizeptr = newptr;
  sigptr1 = sizeptr + 1;
  sigptr2 = sigptr1 + 1;
  usrptr = sigptr2 + 1;
  if (size % 4)
    fsigptr1 = usrptr + (size / 4) + 1;
  else
    fsigptr1 = usrptr + (size / 4);

  fsigptr2 = fsigptr1 + 1;
#ifdef _UNDER_DEV
  printf
    ("realloc: %p + %d, Header1 %p, Header2 %p, Footer1 %p, Footer2 %p\n",
     usrptr, size, sizeptr, sigptr1, fsigptr1, fsigptr1);
#endif
  _do_lock1 ();
  *sizeptr = size;		// insert size move
  *sigptr1 = __RSIGNATURE1__;	// insert sig
  *sigptr2 = __RSIGNATURE2__;	// insert sig
  *fsigptr1 = __FSIG1__;
  *fsigptr2 = __FSIG2__;

  if ((void *) ptr > sbrk (0))	// m mapped 
    {
      _modify_map_info (ptr, usrptr, size);
    }
  _undo_lock1 ();
  return usrptr;
}


/*	wrappers to doug les's malloc allocators 	*/
void *
calloc (size_t nmemb, size_t size)
{
  return dlcalloc (nmemb, size);
}

void *
memalign (size_t boundary, size_t size)
{
  int *ptr, *sigptr1, *sigptr2, *sizeptr, *usrptr, *fsigptr1, *fsigptr2;
  size_t alt_size = size + __HEADER_LEN__ + __FOOTER_LEN__;	// for size and sig
  ptr = dlmemalign (boundary, alt_size);
  if (ptr == NULL)
    return NULL;
  if (!__first_alloc && ((void *) ptr < sbrk (0)))
    __first_alloc = ptr;	// heap base
  sizeptr = ptr;
  sigptr1 = sizeptr + 1;
  sigptr2 = sigptr1 + 1;
  usrptr = sigptr2 + 1;
  if (size % 4)
    fsigptr1 = usrptr + (size / 4) + 1;
  else
    fsigptr1 = usrptr + (size / 4);
  fsigptr2 = fsigptr1 + 1;

#ifdef _UNDER_DEV
  printf
    ("dlmemalign:%p + %d B. Header1 at %p, Header2 at %p, Footer1 %p, Footer2 %p\n",
     usrptr, size, sizeptr, sigptr1, fsigptr1, fsigptr2);
#endif
  _do_lock1 ();
  *sizeptr = size;		// insert size move
  *sigptr1 = __RSIGNATURE1__;	// insert sig1
  *sigptr2 = __RSIGNATURE2__;	// insert sig2
  *fsigptr1 = __FSIG1__;	// insert footer sig1
  *fsigptr2 = __FSIG2__;	// insert footer sig2
  internal_memset (usrptr, _UNDEFINED, size);	// clear the data

  if ((void *) ptr > sbrk (0))	// m mapped 
    {
      _insert_map_info (usrptr, size);
    }
  _undo_lock1 ();

#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "memalign: boundary %d, size %d\n", boundary, size);
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }

  else
    printf ("memalign: boundary %d, size %d\n", boundary, size);
#endif

  return usrptr;
}

void *
valloc (size_t size)
{
  size_t boundary = sysconf (_SC_PAGESIZE);

#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "valloc: boundary %d, size %d\n", boundary, size);
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }

  else
    printf ("valloc: boundary %d, size %d\n", boundary, size);
#endif
  return memalign (boundary, size);

}

/* We need a wrapper function for one of the additions of POSIX.  */
int
posix_memalign (void **memptr, size_t alignment, size_t size)
{
  void *mem;

  /* Test whether the SIZE argument is valid.  It must be a power of
     two multiple of sizeof (void *).  */
  if (alignment % sizeof (void *) != 0
      || !powerof2 (alignment / sizeof (void *)) != 0 || alignment == 0)
    return EINVAL;

  mem = memalign (alignment, size);

  if (mem != NULL)
    {
      *memptr = mem;
      return 0;
    }
  return ENOMEM;
}


/*	crooked string functions..	*/
/*
 *	The  strcpy()  function  copies  the  string pointed to by src, including the terminating null byte
 *	to the buffer pointed to by dest. The strings may not overlap, and the destination string dest must
 *	be large  enough  to receive the copy.
 */
char *
strcpy (char *dst, const char *src)
{
  unsigned int str_len;
  int allowed;

  /*      no hook, bail out       */
  if (!_dlstrcpy)
    {
      _dlstrcpy =
	(char *(*)(char *dst, const char *src)) dlsym (RTLD_NEXT, "strcpy");
      if (!_dlstrcpy)
	abort ();
    }
#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "strcpy: from %p to %p of %d bytes\n", src,
	       dst, strlen (src));
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }
#endif /*  */

  /*      invalid buffers, proceed normal op      */
  if (!(src && dst))
    {
      return (*_dlstrcpy) (dst, src);
    }
  str_len = strlen (src);
  /*  check src buffer validity if its from heap regeion     */
  if (!_verify_heap ((void *) src))
    {
      if (_give_me_size ((void *) src) == _INVALID_BUFFER)
	{
	  _get_time ();
	  if (logfd)
	    {
	      _do_lock2 ();
	      sprintf (format,
		       "%s:%d:%sstrcpy-error: %p unallocated source buffer\n",
		       program_invocation_short_name, getpid (), caltime,
		       src);
	      write (logfd, format, strlen (format));
	      _undo_lock2 ();
	    }

	  else
	    printf
	      ("%s:%d:%sstrcpy-error: %p unallocated source buffer\n",
	       program_invocation_short_name, getpid (), caltime, src);
	  __bt (true);
	  return NULL;
	}
      else
	{
	  /*    sig found, check for uninit usage       */
	  char *temp_src = (char *) src;
	  unsigned int count = 0;
	  unsigned int n = str_len;

	  /* uninitialized reference. if the src buffer has 4 contiguious 'u'   */
	  while (str_len-- && (count < 4))
	    {
	      if (*temp_src++ == _UNDEFINED)
		count++;
	      else
		break;
	    }
	  if ((count == 4) || (n == count))
	    {
	      _get_time ();
	      if (logfd)
		{
		  _do_lock2 ();
		  sprintf (format,
			   "%s:%d:%sstrcpy-error: %p uninitialized source buffer\n",
			   program_invocation_short_name, getpid (),
			   caltime, src);
		  write (logfd, format, strlen (format));
		  _undo_lock2 ();
		}

	      else
		printf
		  ("%s:%d:%sstrcpy-error: %p uninitialized source buffer\n",
		   program_invocation_short_name, getpid (), caltime, src);
	      __bt (false);
	    }

	}

    }
  allowed = _give_me_size (dst);	// dst could be stack, heap, mmap
  /*      No sig, proceed normal op       */
  if (allowed == _SIG_NOT_FOUND)	// not from heap and not malloc(256KB)
    return (*_dlstrcpy) (dst, src);
#ifdef _UNDER_DEV
  printf ("strcpy: ptr %p, requested len %d, allowed len %d\n", dst,
	  str_len, allowed);
#endif
  /*      sig found and crossing the limit. */
  if ((int) str_len > allowed)
    {
      pid_t pid = getpid ();
      _get_time ();

      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%sstrcpy-error: %p Allowed %dB, Needs %dB\n",
		   program_invocation_short_name, pid, caltime, dst,
		   allowed, str_len);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}

      else
	printf ("%s:%d:%sstrcpy-error: %p Allowed %dB, Needs %dB\n",
		program_invocation_short_name, pid, caltime, dst,
		allowed, str_len);
      __bt (true);
      return NULL;
    }


  /*      safe op */
  return (*_dlstrcpy) (dst, src);
}


/*
 *  If the length of src is less than n, strncpy() pads the remainder of dest with null bytes.
 */
char *
strncpy (char *dst, const char *src, size_t len)
{
  int allowed;

  if (len == 0)
    return dst;
  if (!_dlstrncpy)
    {
      _dlstrncpy = (char *(*)(char *dst, const char *src, size_t len))
	dlsym (RTLD_NEXT, "strncpy");
      if (!_dlstrncpy)
	abort ();
    }
#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "strncpy: from %p to %p of %d bytes\n", src, dst, len);
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }
#endif /*  */
  if (!(src && dst))
    {
      return (*_dlstrncpy) (dst, src, len);
    }
  /*  check src buffer validity if its from heap regeion     */
  if (!_verify_heap ((void *) src))
    {
      //if (_give_me_size((void *) src) == _SIG_NOT_FOUND) {
      if (_give_me_size ((void *) src) == _INVALID_BUFFER)
	{
	  _get_time ();
	  if (logfd)
	    {
	      _do_lock2 ();
	      sprintf (format,
		       "%s:%d:%sstrncpy-error: %p unallocated source buffer\n",
		       program_invocation_short_name, getpid (), caltime,
		       src);
	      write (logfd, format, strlen (format));
	      _undo_lock2 ();
	    }

	  else
	    printf
	      ("%s:%d:%sstrncpy-error: %p unallocated source buffer\n",
	       program_invocation_short_name, getpid (), caltime, src);
	  __bt (true);
	  return NULL;
	}
      else
	{
	  /*    uninit check    */
	  char *temp_src = (char *) src;
	  unsigned int count = 0;
	  unsigned int str_len = len;

	  /* uninitialized reference. if the src buffer has 4 contiguious 'u'   */
	  while (str_len-- && (count < 4))
	    {
	      if (*temp_src++ == _UNDEFINED)
		count++;
	      else
		break;
	    }
	  if ((count == 4) || (len == count))
	    {
	      _get_time ();
	      if (logfd)
		{
		  _do_lock2 ();
		  sprintf (format,
			   "%s:%d:%sstrncpy-error: %p uninitialized source buffer\n",
			   program_invocation_short_name, getpid (),
			   caltime, src);
		  write (logfd, format, strlen (format));
		  _undo_lock2 ();
		}

	      else
		printf
		  ("%s:%d:%sstrncpy-error: %p uninitialized source buffer\n",
		   program_invocation_short_name, getpid (), caltime, src);
	      __bt (false);
	    }

	}

    }
  allowed = _give_me_size (dst);
#ifdef _UNDER_DEV
  printf ("strncpy: ptr %p, requested len %d, allowed len %d\n", dst, len,
	  allowed);
#endif
  /*    sig not found; no checks        */
  if (allowed == _SIG_NOT_FOUND)
    return (*_dlstrncpy) (dst, src, len);
  /*    limit check     */
  if ((int) len > allowed)
    {
      pid_t pid = getpid ();
      _get_time ();
      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%sstrncpy-error: %p Allowed %dB, Needs %dB\n",
		   program_invocation_short_name, pid, caltime, dst,
		   allowed, len);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}

      else
	printf
	  ("%s:%d:%sstrncpy-error: %p Allowed %dB, Needs %dB\n",
	   program_invocation_short_name, pid, caltime, dst, allowed, len);
      __bt (true);
      return NULL;
    }


  /*      safe op */
  return (*_dlstrncpy) (dst, src, len);
}


/*      If src contains n or more characters, strcat() writes n+1 characters to dest (n from src plus the
 *      terminating null byte).  Therefore, the size of dest must be at least strlen(dest)+n+1.
 *      This means -> size of the dest must be strlen(dest) + min of (strlen(src) and n) + 1         
 */
char *
strcat (char *dst, const char *src)
{
  size_t src_len, dst_len, op_len;
  int allowed;
  if (!_dlstrcat)
    {
      _dlstrcat =
	(char *(*)(char *dst, const char *src)) dlsym (RTLD_NEXT, "strcat");
      if (!_dlstrcat)
	abort ();
    }
#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format,
	       "strcat: from %p to %p of %d bytes. dst size is %d\n",
	       src, dst, strlen (src), strlen (dst));
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }
#endif /*  */
  if (!(src && dst))
    {
      return (*_dlstrcat) (dst, src);
    }
  src_len = strlen (src);
  dst_len = strlen (dst);
  /*  check src buffer validity if its from heap regeion     */
  if (!_verify_heap ((void *) src))
    {
      if (_give_me_size ((void *) src) == _INVALID_BUFFER)
	{
	  _get_time ();
	  if (logfd)
	    {
	      _do_lock2 ();
	      sprintf (format,
		       "%s:%d:%sstrcat-error: %p unallocated source buffer\n",
		       program_invocation_short_name, getpid (), caltime,
		       src);
	      write (logfd, format, strlen (format));
	      _undo_lock2 ();
	    }

	  else
	    printf
	      ("%s:%d:%sstrcat-error: %p unallocated source buffer\n",
	       program_invocation_short_name, getpid (), caltime, src);
	  __bt (true);
	}
      else
	{
	  /*    uninit check    */
	  char *temp_src = (char *) src;
	  unsigned int count = 0;
	  unsigned int str_len = src_len;

	  /* uninitialized reference. if the src buffer has 4 contiguious 'u'   */
	  while (str_len-- && (count < 4))
	    {
	      if (*temp_src++ == _UNDEFINED)
		count++;
	      else
		break;
	    }
	  if ((count == 4) || (src_len == count))
	    {
	      _get_time ();
	      if (logfd)
		{
		  _do_lock2 ();
		  sprintf (format,
			   "%s:%d:%sstrcat-error: uninitialized source buffer\n",
			   program_invocation_short_name, getpid (), caltime);
		  write (logfd, format, strlen (format));
		  _undo_lock2 ();
		}

	      else
		printf
		  ("%s:%d:%sstrcat-error: uninitialized source buffer\n",
		   program_invocation_short_name, getpid (), caltime);
	      __bt (false);
	    }

	}

    }
  allowed = _give_me_size (dst);
#ifdef _UNDER_DEV
  printf ("strcat: ptr %p, requested len %d, allowed len %d\n", dst,
	  src_len, allowed);
#endif
  /*    sig not found   */
  if (allowed == _SIG_NOT_FOUND)
    return (*_dlstrcat) (dst, src);
  op_len = src_len + dst_len + 1;
  /*    limit check     */
  if ((int) op_len > allowed)
    {
      pid_t pid = getpid ();
      _get_time ();
      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%sstrcat-error: %p Allowed %dB, Needs %dB\n",
		   program_invocation_short_name, pid, caltime, dst,
		   allowed, op_len);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}

      else
	printf ("%s:%d:%sstrcat-error: %p Allowed %dB, Needs %dB\n",
		program_invocation_short_name, pid, caltime, dst,
		allowed, op_len);
      __bt (true);
      return NULL;
    }

  return (*_dlstrcat) (dst, src);
}


/*
 *  The strncat() function is similar, except that
 *   it will use at most n characters from src; and
 *    src does not need to be null terminated if it contains n or more characters.
 *  As with strcat(), the resulting string in dest is always null terminated.
 */
char *
strncat (char *dst, const char *src, size_t len)
{
  size_t src_len, dst_len, op_len, total;
  int allowed;
  if (!len)
    return dst;
  if (!_dlstrncat)
    {
      _dlstrncat = (char *(*)(char *dst, const char *src, size_t len))
	dlsym (RTLD_NEXT, "strncat");
      if (!_dlstrncat)
	abort ();
    }
#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format,
	       "strncat: from %p to %p of %d bytes. dst size is %d\n",
	       src, dst, len, strlen (dst));
      _undo_lock2 ();
    }
#endif /*  */
  if (!(src && dst))
    {
      return (*_dlstrncat) (dst, src, len);
    }
  /*  check src buffer validity if its from heap regeion     */
  if (!_verify_heap ((void *) src))
    {
      //if (_give_me_size((void *) src) == _SIG_NOT_FOUND) {
      if (_give_me_size ((void *) src) == _INVALID_BUFFER)
	{
	  _get_time ();
	  if (logfd)
	    {
	      _do_lock2 ();
	      sprintf (format,
		       "%s:%d:%sstrncat-error: %p unallocated source buffer\n",
		       program_invocation_short_name, getpid (), caltime,
		       src);
	      write (logfd, format, strlen (format));
	      _undo_lock2 ();
	    }

	  else
	    printf
	      ("%s:%d:%sstrncat-error: %p unallocated source buffer\n",
	       program_invocation_short_name, getpid (), caltime, src);
	  __bt (true);
	}
      else
	{
	  /*    uninit check    */
	  char *temp_src = (char *) src;
	  unsigned int count = 0;
	  unsigned int str_len = len;

	  /* uninitialized reference. if the src buffer has 4 contiguious 'u'   */
	  while (str_len-- && (count < 4))
	    {
	      if (*temp_src++ == _UNDEFINED)
		count++;
	      else
		break;
	    }
	  if ((count == 4) || (len == count))
	    {
	      _get_time ();
	      if (logfd)
		{
		  _do_lock2 ();
		  sprintf (format,
			   "%s:%d:%sstrncat-error: uninitialized source buffer\n",
			   program_invocation_short_name, getpid (), caltime);
		  write (logfd, format, strlen (format));
		  _undo_lock2 ();
		}

	      else
		printf
		  ("%s:%d:%sstrncat-error: uninitialized source buffer\n",
		   program_invocation_short_name, getpid (), caltime);
	      __bt (false);
	    }

	}

    }
  src_len = strlen (src);
  dst_len = strlen (dst);
  allowed = _give_me_size (dst);
  /*    sig not found   */
  if (allowed == _SIG_NOT_FOUND)
    return (*_dlstrncat) (dst, src, len);

  /*      min of src len and len  */
  op_len = len > src_len ? src_len : len;
  total = op_len + dst_len + 1;
  /*    limit check     */
  if ((int) total > allowed)
    {
      pid_t pid = getpid ();
      _get_time ();
      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%sstrncat-error: %p Allowed %dB, Needs %dB\n",
		   program_invocation_short_name, pid, caltime, dst,
		   allowed, total);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}

      else
	printf
	  ("%s:%d:%sstrncat-error: %p Allowed %dB, Needs %dB\n",
	   program_invocation_short_name, pid, caltime, dst, allowed, total);
      __bt (true);
      return NULL;
    }

  return (*_dlstrncat) (dst, src, len);
}

/*
 * 	The  memcpy() function copies n bytes from memory area src to memory area dest.  The memory areas 
 * 	should not overlap.  Use memmove(3) if the memory areas do overlap.
 */
void *
internal_memcpy (void *dest, const void *src, size_t n)
{
  if (!n)
    return dest;
  if (!_dlmemcpy)
    {
      _dlmemcpy = (void *(*)(void *dest, const void *src, size_t n))
	dlsym (RTLD_NEXT, "memcpy");
      if (!_dlmemcpy)
	abort ();
    }
  return (*_dlmemcpy) (dest, src, n);
}

/*
 * 	The  memcpy() function copies n bytes from memory area src to memory area dest.  The memory areas 
 * 	should not overlap.  Use memmove(3) if the memory areas do overlap.
 */
void *
memcpy (void *dest, const void *src, size_t n)
{
  int allowed;
  if (!n)
    return dest;
  if (!_dlmemcpy)
    {
      _dlmemcpy = (void *(*)(void *dest, const void *src, size_t n))
	dlsym (RTLD_NEXT, "memcpy");
      if (!_dlmemcpy)
	abort ();
    }
#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "memcpy: from %p to %p of %d bytes\n", src, dest, n);
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }
#endif /*  */
  if (!(src && dest))
    {
      return (*_dlmemcpy) (dest, src, n);
    }
  /*  check src buffer validity if its from heap regeion     */
  if (!_verify_heap ((void *) src))
    {
      //if (_give_me_size((void *) src) == _SIG_NOT_FOUND) {
      if (_give_me_size ((void *) src) == _INVALID_BUFFER)
	{
	  _get_time ();
	  if (logfd)
	    {
	      _do_lock2 ();
	      sprintf (format,
		       "%s:%d:%smemcpy-error: %p unallocated source buffer\n",
		       program_invocation_short_name, getpid (), caltime,
		       src);
	      write (logfd, format, strlen (format));
	      _undo_lock2 ();
	    }

	  else
	    printf
	      ("%s:%d:%smemcpy-error: %p unallocated source buffer\n",
	       program_invocation_short_name, getpid (), caltime, src);
	  __bt (true);
	}
      else
	{
	  /*     uninit check    */
	  char *temp_src = (char *) src;
	  unsigned int count = 0;
	  unsigned int str_len = n;

	  /* uninitialized reference. if the src buffer has 4 contiguious 'u'   */
	  while (str_len-- && (count < 4))
	    {
	      if (*temp_src++ == _UNDEFINED)
		count++;
	      else
		break;
	    }
	  if ((count == 4) || (n == count))
	    {
	      _get_time ();
	      if (logfd)
		{
		  _do_lock2 ();
		  sprintf (format,
			   "%s:%d:%smemcpy-error: uninitialized source buffer\n",
			   program_invocation_short_name, getpid (), caltime);
		  write (logfd, format, strlen (format));
		  _undo_lock2 ();
		}

	      else
		printf
		  ("%s:%d:%smemcpy-error: uninitialized source buffer\n",
		   program_invocation_short_name, getpid (), caltime);
	      __bt (false);
	    }

	}

    }
  allowed = _give_me_size (dest);
#ifdef _UNDER_DEV
  printf ("memcpy: ptr %p, requested len %d, allowed len %d\n", dest, n,
	  allowed);
#endif
  /*    sig not found   */
  if (allowed == _SIG_NOT_FOUND)
    return (*_dlmemcpy) (dest, src, n);

  /*    builtin strcpy and strcat makes len+1 for const & *char */
  /*    No way for us to know type of the original *src */
  /*    live with it :( */
  if ((int) n > allowed)
    {
      pid_t pid = getpid ();
      _get_time ();
      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%smemcpy-error: %p Allowed %dB, Needs %dB\n",
		   program_invocation_short_name, pid, caltime, dest,
		   allowed, n);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}

      else
	printf ("%s:%d:%smemcpy-error: %p Allowed %dB, Needs %dB\n",
		program_invocation_short_name, pid, caltime, dest,
		allowed, n);
      __bt (true);
      return NULL;
    }


  return (*_dlmemcpy) (dest, src, n);
}


/*
 *	The  memmove()  function  copies  n bytes from memory area src to memory area dest.  The memory areas
 *	may overlap: copying takes place as though the bytes in src are first copied into a temporary array
 *	that does not  overlap  src or dest, and the bytes are then copied from the temporary array to dest.
 */
void *
memmove (void *dest, const void *src, size_t n)
{
  int allowed;
  if (!n)
    return dest;
  if (!_dlmemmove)
    {
      _dlmemmove = (void *(*)(void *dest, const void *src, size_t n))
	dlsym (RTLD_NEXT, "memmove");
      if (!_dlmemmove)
	abort ();
    }
#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "memmove: from %p to %p of %d bytes\n", src, dest, n);
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }
#endif /*  */
  if (!(src && dest))
    {
      return (*_dlmemmove) (dest, src, n);
    }
  /*  check src buffer validity if its from heap regeion     */
  if (!_verify_heap ((void *) src))
    {
      //if (_give_me_size((void *) src) == _SIG_NOT_FOUND) {
      if (_give_me_size ((void *) src) == _INVALID_BUFFER)
	{
	  _get_time ();
	  if (logfd)
	    {
	      _do_lock2 ();
	      sprintf (format,
		       "%s:%d:%smemmove-error: %p unallocated source buffer\n",
		       program_invocation_short_name, getpid (), caltime,
		       src);
	      write (logfd, format, strlen (format));
	      _undo_lock2 ();
	    }

	  else
	    printf
	      ("%s:%d:%smemmove-error: %p unallocated source buffer\n",
	       program_invocation_short_name, getpid (), caltime, src);
	  __bt (true);
	}
      else
	{
	  /*    uninit check    */
	  char *temp_src = (char *) src;
	  unsigned int count = 0;
	  unsigned int str_len = n;

	  /* uninitialized reference. if the src buffer has 4 contiguious 'u'   */
	  while (str_len-- && (count < 4))
	    {
	      if (*temp_src++ == _UNDEFINED)
		count++;
	      else
		break;
	    }
	  if ((count == 4) || (n == count))
	    {
	      _get_time ();
	      if (logfd)
		{
		  _do_lock2 ();
		  sprintf (format,
			   "%s:%d:%smemmove-error: uninitialized source buffer\n",
			   program_invocation_short_name, getpid (), caltime);
		  write (logfd, format, strlen (format));
		  _undo_lock2 ();
		}

	      else
		printf
		  ("%s:%d:%smemmove-error: uninitialized source buffer\n",
		   program_invocation_short_name, getpid (), caltime);
	      __bt (false);
	    }

	}

    }
  allowed = _give_me_size (dest);
  /*    sig not found   */
  if (allowed == _SIG_NOT_FOUND)
    return (*_dlmemmove) (dest, src, n);
  /*    limit check     */
  if ((int) n > allowed)
    {
      pid_t pid = getpid ();
      _get_time ();
      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%smemmove-error: %p Allowed %dB, Needs %dB\n",
		   program_invocation_short_name, pid, caltime, dest,
		   allowed, n);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}

      else
	printf
	  ("%s:%d:%smemmove-error: %p Allowed %dB, Needs %dB\n",
	   program_invocation_short_name, pid, caltime, dest, allowed, n);
      __bt (true);
      return NULL;
    }

  return (*_dlmemmove) (dest, src, n);
}

void *
internal_memset (dstpp, c, len)
     void *dstpp;
     int c;
     size_t len;

{
  long int dstp = (long int) dstpp;
  /*    do nothing      */
  if (!len)
    return dstpp;

  /*    start op        */
  if (len >= 8)
    {
      size_t xlen;
      shop_t cccc;
      cccc = (unsigned char) c;
      cccc |= cccc << 8;
      cccc |= cccc << 16;
      if (SHOPSIZ > 4)

	/* Do the shift in two steps to avoid warning if long has 32 bits.  */
	cccc |= (cccc << 16) << 16;

      /* There are at least some bytes to set.
       *         No need to test for LEN == 0 in this alignment loop.  */
      while (dstp % SHOPSIZ != 0)
	{
	  ((unsigned char *) dstp)[0] = c;
	  dstp += 1;
	  len -= 1;
	}
      /* Write 8 `op_t' per iteration until less than 8 `op_t' remain.  */
      xlen = len / (SHOPSIZ * 8);
      while (xlen > 0)
	{
	  ((shop_t *) dstp)[0] = cccc;
	  ((shop_t *) dstp)[1] = cccc;
	  ((shop_t *) dstp)[2] = cccc;
	  ((shop_t *) dstp)[3] = cccc;
	  ((shop_t *) dstp)[4] = cccc;
	  ((shop_t *) dstp)[5] = cccc;
	  ((shop_t *) dstp)[6] = cccc;
	  ((shop_t *) dstp)[7] = cccc;
	  dstp += 8 * SHOPSIZ;
	  xlen -= 1;
	}
      len %= SHOPSIZ * 8;

      /* Write 1 `op_t' per iteration until less than OPSIZ bytes remain.  */
      xlen = len / SHOPSIZ;
      while (xlen > 0)
	{
	  ((shop_t *) dstp)[0] = cccc;
	  dstp += SHOPSIZ;
	  xlen -= 1;
	}
      len %= SHOPSIZ;
    }

  /* Write the last few bytes.  */
  while (len > 0)
    {
      ((unsigned char *) dstp)[0] = c;
      dstp += 1;
      len -= 1;
    } return dstpp;
}


/*	load libc, get libc string funciton addresses	*/

void *
memset (dstpp, c, len)
     void *dstpp;
     int c;
     size_t len;

{
  long int dstp = (long int) dstpp;
  pid_t pid = getpid ();
  int allowed;

#ifdef _DEBUG_ON
  if (logfd)
    {
      _do_lock2 ();
      sprintf (format, "memset: %p of %d bytes\n", dstpp, len);
      write (logfd, format, strlen (format));
      _undo_lock2 ();
    }
#endif /*  */

  /*    do nothing      */
  if (!len)
    return dstpp;

  /*    raise sigseg    */
  if (!dstpp)
    {
      _get_time ();
      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format, "%s:%d:%smemset-error: dst is NULL\n",
		   program_invocation_short_name, pid, caltime);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}
      else
	printf ("%s:%d:%smemset-error: dst is NULL\n",
		program_invocation_short_name, pid, caltime);
      __bt (true);
    }
  allowed = _give_me_size (dstpp);

  /*    sig not found       */
  if (allowed == _SIG_NOT_FOUND)
    goto normal_op;

  /*    corssing the limit. raise sigsegv       */
  if ((int) len > allowed)
    {
      _get_time ();
      if (logfd)
	{
	  _do_lock2 ();
	  sprintf (format,
		   "%s:%d:%smemset-error: %p Allowed %dB, Needs %dB\n",
		   program_invocation_short_name, pid, caltime, dstpp,
		   allowed, len);
	  write (logfd, format, strlen (format));
	  _undo_lock2 ();
	}

      else
	printf ("%s:%d:%smemset-error: %p Allowed %dB, Needs %dB\n",
		program_invocation_short_name, pid, caltime, dstpp,
		allowed, len);
      __bt (true);
    }
normal_op:
  /*    start op        */
  if (len >= 8)
    {
      size_t xlen;
      shop_t cccc;
      cccc = (unsigned char) c;
      cccc |= cccc << 8;
      cccc |= cccc << 16;
      if (SHOPSIZ > 4)

	/* Do the shift in two steps to avoid warning if long has 32 bits.  */
	cccc |= (cccc << 16) << 16;

      /* There are at least some bytes to set.
       *         No need to test for LEN == 0 in this alignment loop.  */
      while (dstp % SHOPSIZ != 0)
	{
	  ((unsigned char *) dstp)[0] = c;
	  dstp += 1;
	  len -= 1;
	}
      /* Write 8 `op_t' per iteration until less than 8 `op_t' remain.  */
      xlen = len / (SHOPSIZ * 8);
      while (xlen > 0)
	{
	  ((shop_t *) dstp)[0] = cccc;
	  ((shop_t *) dstp)[1] = cccc;
	  ((shop_t *) dstp)[2] = cccc;
	  ((shop_t *) dstp)[3] = cccc;
	  ((shop_t *) dstp)[4] = cccc;
	  ((shop_t *) dstp)[5] = cccc;
	  ((shop_t *) dstp)[6] = cccc;
	  ((shop_t *) dstp)[7] = cccc;
	  dstp += 8 * SHOPSIZ;
	  xlen -= 1;
	}
      len %= SHOPSIZ * 8;

      /* Write 1 `op_t' per iteration until less than OPSIZ bytes remain.  */
      xlen = len / SHOPSIZ;
      while (xlen > 0)
	{
	  ((shop_t *) dstp)[0] = cccc;
	  dstp += SHOPSIZ;
	  xlen -= 1;
	}
      len %= SHOPSIZ;
    }

  /* Write the last few bytes.  */
  while (len > 0)
    {
      ((unsigned char *) dstp)[0] = c;
      dstp += 1;
      len -= 1;
    } return dstpp;
}


/*	load libc, get libc string funciton addresses	*/
int
__init (void)
{
  char *error;
  if (!handle)
    {
      handle = dlopen (SH_LIBC_VER, RTLD_LAZY);
      if (!handle)
	{
	  abort ();
	}
    }
  dlerror ();
  if (!_dlmemcpy)
    {
      (_dlmemcpy) = dlsym (handle, "memcpy");
      if ((error = dlerror ()) != NULL)
	{
	  fprintf (stderr, "dlsym(memcpy); %s\n", error);
	  abort ();
	}
    }
  if (!_dlmemmove)
    {
      (_dlmemmove) = dlsym (handle, "memmove");
      if ((error = dlerror ()) != NULL)
	{
	  fprintf (stderr, "dlsym(memmove); %s\n", error);
	  abort ();
	}
    }
  if (!_dlstrcpy)
    {
      (_dlstrcpy) = dlsym (handle, "strcpy");
      if ((error = dlerror ()) != NULL)
	{
	  fprintf (stderr, "dlsym(strcpy); %s\n", error);
	  abort ();
	}
    }
  if (!_dlstrncpy)
    {
      (_dlstrncpy) = dlsym (handle, "strncpy");
      if ((error = dlerror ()) != NULL)
	{
	  fprintf (stderr, "dlsym(strncpy); %s\n", error);
	  abort ();
	}
    }
  if (!_dlstrcat)
    {
      (_dlstrcat) = dlsym (handle, "strcat");
      if ((error = dlerror ()) != NULL)
	{
	  fprintf (stderr, "dlsym(strcat); %s\n", error);
	  abort ();
	}
    }
  if (!_dlstrncat)
    {
      (_dlstrncat) = dlsym (handle, "strncat");
      if ((error = dlerror ()) != NULL)
	{
	  fprintf (stderr, "dlsym(strncat); %s\n", error);
	  abort ();
	}
    }
  sprintf (logfile_name, "%s.%d", _SAFELOGFILE, getpid ());
  fp = fopen (logfile_name, "w");
  if (NULL == fp)
    {
      perror ("safeheap: log file open error: ");
      abort ();
    }
  fprintf (fp,
	   "###############################################################################################\n");
  fprintf (fp,
	   "Safeheap utility. Written by Ravi Sankar Guntur. Version %s, build on %s\n",
	   __VERSION, __DATE__);
  fprintf (fp, "Debugged program is %s, pid is %d. Time %s\n",
	   program_invocation_name, getpid (), caltime);
  fprintf (fp,
	   "###############################################################################################\n\n");
  fflush (fp);
  fclose (fp);
  /*    open log file   */
  logfd = open (logfile_name, O_RDWR | O_APPEND);
  if (logfd == -1)
    {
      logfd = 0;
      perror ("safeheap: log file open error: ");
      abort ();
    }

  return 0;
}

void
__deinit (void)
{
  _dlstrcpy = NULL;
  _dlstrncpy = NULL;
  _dlstrcat = NULL;
  _dlstrncat = NULL;
  _dlmemcpy = NULL;
  _dlmemmove = NULL;
  if (handle)
    dlclose (handle);
  handle = NULL;
  fp = NULL;
}


__attribute__ ((constructor))
     void init (void)
{
#ifdef _DEBUG_ON
  printf ("safeheap debug: init done\n");
#endif
  _get_time ();
  __init ();
}

/*	if bailout, then writes maps info to log file	*/
__attribute__ ((destructor))
     void deinit (void)
{
  int mapfd;
  char maps[1025] = { 0, };
  char file_name[100] = { 0, };

  /*    write maps info to log file before bail out     */
  if (_err_caught && logfd)
    {
	/*	sizeof -1 to remove the CTRL char in log files	*/
      write (logfd, _MAPS_LABEL, (sizeof (_MAPS_LABEL)-1));
      sprintf (file_name, "/proc/%d/maps", getpid ());
      mapfd = open (file_name, O_RDONLY);
      while (read (mapfd, maps, 1024))
	write (logfd, maps, 1024);
      close (logfd);
      close (mapfd);
    }
  /*      unlink the log file on clean exit       */
  else
    {
      if (logfd)
	close (logfd);
      unlink (logfile_name);
    }
  __deinit ();

#ifdef _DEBUG_ON
  printf ("safeheap debug: deinit done\n");
#endif
}

/*	eof	*/
