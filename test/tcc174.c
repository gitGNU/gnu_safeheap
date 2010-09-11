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

  This file is part of the test package for Safeheap
*/


/*	Author: Ravi Sankar Guntur; ravi.g@samsung.com
*	test case: allocate 16 Bytes and double free the allocated block
*	test result: pass
*/
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define BLOCK_SIZE 16
#define _TEST_TEXT "I am no more me" // 15

int tcp1_pmemalign(void)
{
	char *ptr = (char *)0x12000;
	int ret;
	memcpy(ptr, _TEST_TEXT, BLOCK_SIZE);
	printf("%s:\n", ptr);
	return 0;
}

int main(void)
{
	tcp1_pmemalign();
	return 0;
}
