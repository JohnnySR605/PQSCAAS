#ifndef CSV_WRITER_H
#define CSV_WRITER_H

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    FILE *fp;
    int first_column;
} csv_t;

int  csv_open(csv_t *c, const char *path);
void csv_close(csv_t *c);

/* Write a header row: csv_header(&c, "x", "PQSCAAS_mean", "PQSCAAS_std", NULL) */
void csv_header(csv_t *c, ...);

/* Begin a new row */
void csv_new_row(csv_t *c);

/* Append values to current row */
void csv_write_int(csv_t *c, long v);
void csv_write_double(csv_t *c, double v);
void csv_write_str(csv_t *c, const char *s);

#ifdef __cplusplus
}
#endif

#endif /* CSV_WRITER_H */
