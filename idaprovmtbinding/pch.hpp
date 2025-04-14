#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>
#pragma intrinsic(memset, memcpy, memcmp, strcat, strcmp, strcpy, strlen)

#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#pragma warning(push)
#pragma warning(disable:4244) // "conversion from 'ssize_t' to 'int', possible loss of data"
#pragma warning(disable:4267) // "conversion from 'size_t' to 'uint32', possible loss of data"
#include <ida.hpp>
#include <bytes.hpp>
#include <allins.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#pragma warning(pop)

#define MSG_TAG "VMT Binder: "

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 1, 0, 0)
