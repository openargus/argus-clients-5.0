#ifndef HS_JSON_H
#define HS_JSON_H

typedef struct {
   size_t capacity;
   size_t data_size;
   size_t size;
   char* data;
} vector;

void vector_init(vector* v, size_t data_size);
void vector_free(vector* v);
void* vector_get(const vector* v, size_t index);
void* vector_get_checked(const vector* v, size_t index);
void vector_reserve(vector* v, size_t new_capacity);
void vector_push_back(vector* v, void* data);

typedef void(*vector_foreach_t)(void*);
void vector_foreach(const vector* v, vector_foreach_t fp);
typedef int(*vector_foreach_data_t)(void*, void*);
void vector_foreach_data(const vector* v, vector_foreach_data_t fp, void* data);

enum json_value_type {
    ARGUS_TYPE_NULL,
    ARGUS_TYPE_BOOL,
    ARGUS_TYPE_INTEGER,
    ARGUS_TYPE_DOUBLE,
    ARGUS_TYPE_OBJECT, // Is a vector with pairwise entries, key, value
    ARGUS_TYPE_ARRAY,  // Is a vector, all entries are plain 
    ARGUS_TYPE_STRING,
    ARGUS_TYPE_KEY
};

typedef struct {
    int type;
    union {
        int boolean;
        double number;
        char* string;
        char* key;
        vector array;
        vector object;
    } value;
} ArgusJsonValue;

// Parse string into structure of json elements and values
// return 1 if successful.

ArgusJsonValue *ArgusJsonParse(const char* input, ArgusJsonValue* root);
int ArgusJsonPrint(ArgusJsonValue *);

// Free the structure and all the allocated values
void json_free_value(ArgusJsonValue* val);

// Convert value to string if possible, asserts if not
char* json_value_to_string(ArgusJsonValue* value);

// Convert value to double if possible asserts if not
double json_value_to_double(ArgusJsonValue* value);

// Convert value to bool if possible asserts if not
int json_value_to_bool(ArgusJsonValue* value);

// Convert value to vector if it's an array asserts if not
vector* json_value_to_array(ArgusJsonValue* value);

// Convert value to vector if it's an object, asserts if not
vector* json_value_to_object(ArgusJsonValue* value);

// Fetch the value with given index from root, asserts if root is not array
ArgusJsonValue* json_value_at(const ArgusJsonValue* root, size_t index);

// Fetche the value with the given key from root, asserts if root is not object
ArgusJsonValue * json_value_with_key(const ArgusJsonValue * root, const char * key);

int json_is_literal(const char** cursor, const char* literal);

#endif
