/*
 * Gargoyle Client Software. Tools to read, analyze and manage Argus data.
 * Copyright (c) 2000-2019 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 */

/*
 * Argus json parsing routines.  Adapted from HarryDC / JsonParser
 *     Copyright (c) 2017, Harald Scheirich
 *     All rights reserved.
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/*
 * $Id: //depot/gargoyle/clients/common/argus_json.c#20 $
 * $DateTime: 2016/10/24 12:10:50 $
 * $Change: 3226 $
 */

#include <ctype.h>
#include <stddef.h>

#include "argus_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int json_parse_value(const char **cursor, ArgusJsonValue *parent);
static int json_print_value(ArgusJsonValue *parent);

// Allocate the data structure for the vector
void
vector_init(vector* v, size_t data_size) {
   if (v == NULL) return;
   
   v->data = malloc(data_size);
   if (v->data != NULL)
   {
      v->capacity = 1;
        v->data_size = data_size;
        v->size = 0; 
   }
}

// Free the memory of the vector, the pointer to the vector is invalid after this
void
vector_free(vector* v) {
    if (v)
    {
        free(v->data);
      v->data = NULL;
    }
}

// Return the element at index, does not do a range check
void *
vector_get(const vector* v, size_t index) {
   return &(v->data[index * v->data_size]);
}

// Return the element at index, return NULL if index is out of range for the vector
void *
vector_get_checked(const vector* v, size_t index) {
   return (index < v->size) ? &(v->data[index * v->data_size]) : NULL;
}

// if capacity < new_capacity realloc up to new_capacity
void
vector_reserve(vector* v, size_t new_capacity) {
   if (new_capacity <= v->capacity) return;
    void* new_data = realloc(v->data, new_capacity*v->data_size);
    if (new_data) {
        v->capacity = new_capacity;
        v->data = new_data;
    }
    else {
        abort();
    }
}

// Puts an element data[size * data_size], will reserve more space if size == capacity
void
vector_push_back(vector* v, void* data) {
    if (v->size >= v->capacity) {
      size_t new_capacity = (v->capacity > 0) ? (size_t)(v->capacity * 2) : 1;
      vector_reserve(v, new_capacity);
    }
    memcpy(vector_get(v,v->size), data, v->data_size);
    ++v->size;
}

void
vector_foreach_data(const vector* v, vector_foreach_data_t fp, void* data) {
   if (v == NULL) return;
   char* item = v->data;
   size_t i;

   if (item != NULL) {
      for (i = 0; i < v->size; i++) {
         if (! fp(item, (void *)data)) break;
         item += v->data_size;
      }
   }
}

void
vector_foreach(const vector* v, vector_foreach_t fp) {
   if (v == NULL) return;
   char* item = v->data;
   size_t i;
   if (item != NULL) {
      for (i = 0; i < v->size; i++) {
         fp(item);
         if (fp == (vector_foreach_t) json_print_value) {
         }
         item += v->data_size;
      }
   }
}

static void
skip_whitespace(const char** cursor) {
   if (**cursor == '\0') return;
   while (iscntrl(**cursor) || isspace(**cursor)) ++(*cursor);
}

static int
has_char(const char** cursor, char character) {
   skip_whitespace(cursor);
   int retn = **cursor == character;
   if (retn) ++(*cursor);
   return retn;
}

static int
json_parse_object(const char** cursor, ArgusJsonValue *parent) {
   ArgusJsonValue result = { .type = ARGUS_TYPE_OBJECT };
   vector_init(&result.value.object, sizeof(ArgusJsonValue));

   int retn = 1;
   while (retn && !has_char(cursor, '}')) {
      ArgusJsonValue key = { .type = ARGUS_TYPE_KEY };
      ArgusJsonValue value = { .type = ARGUS_TYPE_NULL };
      retn = json_parse_value(cursor, &key);
      retn = retn && has_char(cursor, ':');
      retn = retn && json_parse_value(cursor, &value);

      if (retn) {
         vector_push_back(&result.value.object, &key);
         vector_push_back(&result.value.object, &value);
      }
      else {
         json_free_value(&key);
         break;
      }
      skip_whitespace(cursor);
      if (has_char(cursor, '}')) break;
      else if (has_char(cursor, ',')) continue;
      else retn = 0;
   }

   if (retn) {
      *parent = result;
   }
   else {
      json_free_value(&result);
   }

   return retn;
   return 1;
}

static int
json_parse_array(const char** cursor, ArgusJsonValue *parent) {
   int retn = 1;
   if (**cursor == ']') {
      ++(*cursor);
      return retn;
   }
   while (retn) {
      ArgusJsonValue new_value = { .type = ARGUS_TYPE_NULL };
      retn = json_parse_value(cursor, &new_value);
      if (!retn) break;
      skip_whitespace(cursor);
      vector_push_back(&parent->value.array, &new_value);
      skip_whitespace(cursor);
      if (has_char(cursor, ']')) break;
      else if (has_char(cursor, ',')) continue;
      else retn = 0;
   }
   return retn;
}


void
json_free_value(ArgusJsonValue *val) {
   if (!val) return;

   switch (val->type) {
      case ARGUS_TYPE_STRING:
         free(val->value.string);
         val->value.string = NULL;
         break;
      case ARGUS_TYPE_ARRAY:
      case ARGUS_TYPE_OBJECT:
         vector_foreach(&(val->value.array), (void(*)(void*))json_free_value);
         vector_free(&(val->value.array));
         break;
   }

   val->type = ARGUS_TYPE_NULL;
}

int
json_is_literal(const char** cursor, const char* literal) {
   size_t cnt = strlen(literal);
   if (strncmp(*cursor, literal, cnt) == 0) {
      *cursor += cnt;
      return 1;
   }
   return 0;
}

static int
json_parse_value(const char** cursor, ArgusJsonValue *parent) {
   // Eat whitespace
   int retn = 0;
   skip_whitespace(cursor);
   switch (**cursor) {
      case '\0':
         // If parse_value is called with the cursor at the end of the string
         // that's a failure
         retn = 0;
         break;
      case '"':
         ++*cursor;
         const char* start = *cursor;
         char* end = strchr(*cursor, '"');
         if (end) {
            size_t len = end - start;
            char* new_string = malloc((len + 1) * sizeof(char));
            memcpy(new_string, start, len);
            new_string[len] = '\0';

            if (parent->type != ARGUS_TYPE_KEY) {
               parent->type = ARGUS_TYPE_STRING;
            }
            parent->value.string = new_string;

            *cursor = end + 1;
            retn = 1;
         }
         break;
      case '{':
         ++(*cursor);
         skip_whitespace(cursor);
         retn = json_parse_object(cursor, parent);
         break;
      case '[':
         parent->type = ARGUS_TYPE_ARRAY;
         vector_init(&parent->value.array, sizeof(ArgusJsonValue));
         ++(*cursor);
         skip_whitespace(cursor);
         retn = json_parse_array(cursor, parent);
         if (!retn) {
            vector_free(&parent->value.array);
         }
         break;
      case 't': {
         retn = json_is_literal(cursor, "true");
         if (retn) {
            parent->type = ARGUS_TYPE_BOOL;
            parent->value.boolean = 1;
         }
         break;
      }
      case 'f': {
         retn = json_is_literal(cursor, "false");
         if (retn) {
            parent->type = ARGUS_TYPE_BOOL;
            parent->value.boolean = 0;
         }
         break;
      }
      case 'n':
         retn = json_is_literal(cursor, "null");
         break;
      default: {
         char* end;
         double number = strtod(*cursor, &end);
         if (*cursor != end) {
            if (number == (int) number) {
               parent->type = ARGUS_TYPE_INTEGER;
            } else {
               parent->type = ARGUS_TYPE_DOUBLE;
            }
            parent->value.number = number;
            *cursor = end;
            retn = 1;
         }
      }
   }
   return retn;
}

static int
json_print_value(ArgusJsonValue *parent) {
   int retn = 0;

   switch (parent->type) {
      case ARGUS_TYPE_BOOL:
         printf ("%s", parent->value.boolean ? "true" : "false");
         break;
      case ARGUS_TYPE_INTEGER:
         printf ("%d", (int)parent->value.number);
         break;
      case ARGUS_TYPE_DOUBLE:
         printf ("%f", parent->value.number);
         break;
      case ARGUS_TYPE_KEY: {
         printf ("\"%s\":", parent->value.string);
         break;
      }
      case ARGUS_TYPE_STRING: {
         printf ("%s", parent->value.string);
         break;
      }
      case ARGUS_TYPE_ARRAY: {
         printf ("[");
         vector_foreach(&(parent->value.array), (void(*)(void*))json_print_value);
         printf ("]");
         break;
      }
      case ARGUS_TYPE_OBJECT: {
         printf ("{");
         vector_foreach(&(parent->value.array), (void(*)(void*))json_print_value);
         printf ("}");
         break;
         }
   }

   return retn;
}

ArgusJsonValue *
ArgusJsonParse(const char* input, ArgusJsonValue *result) {
   ArgusJsonValue *retn = NULL;
   
   if (json_parse_value(&input, result)) {
      retn = result;
   }
   return (retn);
}

int
ArgusJsonPrint(ArgusJsonValue *result) {
   int retn = json_print_value(result);
   printf ("\n");
   fflush(stdout);
   return retn;
}

char *
json_value_to_string(ArgusJsonValue *value)
{
   return (char *)value->value.string;
}

double
json_value_to_double(ArgusJsonValue *value) {
   return value->value.number;
}

int
json_value_to_bool(ArgusJsonValue *value) {
   return value->value.boolean;
}

vector *
json_value_to_array(ArgusJsonValue *value) {
   return &value->value.array;
}

vector *
json_value_to_object(ArgusJsonValue *value) {
   return &value->value.object;
}

ArgusJsonValue *
json_value_at(const ArgusJsonValue *root, size_t index) {
   if (root->value.array.size < index) {
      return vector_get_checked(&root->value.array,index);
   }
   else {
      return NULL;
   }
}

ArgusJsonValue *
json_value_with_key(const ArgusJsonValue *root, const char* key) {
   ArgusJsonValue *data = (ArgusJsonValue*)root->value.object.data;
   size_t i, size = root->value.object.size;
   for (i = 0; i < size; i += 2) {
      if (strcmp(data[i].value.string, key) == 0) {
         return &data[i + 1];
      }
   }
   return NULL;
}
