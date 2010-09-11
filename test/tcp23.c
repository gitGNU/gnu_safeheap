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
*	test case: allocate 16 Bytes and free the allocated block
*	test result: pass
*/
#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#define BLOCK_SIZE 16
#define _TEST_TEXT "i am no more me" // 15 bytes + 1 terminating

int tcp1_malloc(void)
{
	char *src, *dst = NULL;
	src = malloc(sizeof(char)*BLOCK_SIZE);
	dst = malloc(sizeof(char)*BLOCK_SIZE);
	if(!src && !dst)
		printf("tcp1: malloc fail\n");
	strcpy(src, _TEST_TEXT);
	strcpy(dst, src);
	printf("%s:\n", dst);
	free(src);
	free(dst);
	return 0;
}

int tcp1_calloc(void)
{
	char *src, *dst = NULL;
	src = calloc(sizeof(char), BLOCK_SIZE);
	dst = calloc(sizeof(char), BLOCK_SIZE);
	if(!src && !dst)
		printf("tcp1: malloc fail\n");
	strcpy(src, _TEST_TEXT);
	strcpy(dst, src);
	printf("%s:\n", dst);
	free(src);
	free(dst);
	return 0;
}

int tcp1_realloc(void)
{
	char *src, *dst = NULL;

	src = realloc(NULL, sizeof(char)*BLOCK_SIZE);
	dst = realloc(NULL, sizeof(char)*BLOCK_SIZE);
	
	if(!src && !dst)
		printf("tcp1: realloc new fail\n");
	
	src = realloc(src, sizeof(int)*BLOCK_SIZE);
	dst = realloc(dst, sizeof(int)*BLOCK_SIZE);
	if(!src && !dst)
		printf("tcp1: relloc resize-grow fails");

	src = realloc(src, sizeof(char)*BLOCK_SIZE);
	dst = realloc(dst, sizeof(char)*BLOCK_SIZE);
	if(!src && !dst)
		printf("tcp1: relloc resize-shrink fails");

	strcpy(src, _TEST_TEXT);
	strcpy(dst, src);
	printf("%s:\n", dst);

	src = realloc(src, 0);
	dst = realloc(dst, 0);
	
	return 0;
}

int main(void)
{
	tcp1_malloc();
	tcp1_calloc();
	tcp1_realloc();
	return 0;
}
