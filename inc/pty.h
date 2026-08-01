/* Unix98 PTY — /dev/ptmx + /dev/pts/N (Linux layout). */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <fs.h>
#include <stat.h>

#define PTY_MAX 32

int pty_open_ptmx(struct fs_file **out);
int pty_open_slave(int index, struct fs_file **out);
int pty_is_file(struct fs_file *f);
int pty_is_master(struct fs_file *f);
int pty_get_index(struct fs_file *f);

ssize_t pty_read(struct fs_file *f, void *buf, size_t n);
ssize_t pty_write(struct fs_file *f, const void *buf, size_t n);
void pty_release_handle(struct fs_file *f);

int pty_available(struct fs_file *f);
int pty_set_locked(struct fs_file *f, int locked);
int pty_get_locked(struct fs_file *f);

uint32_t pty_get_lflag(struct fs_file *f);
void pty_set_termios(struct fs_file *f, uint32_t lflag, uint8_t vtime, uint8_t vmin);
void pty_get_winsize(struct fs_file *f, uint16_t *row, uint16_t *col);
void pty_set_winsize(struct fs_file *f, uint16_t row, uint16_t col);
int pty_get_fg_pgrp(struct fs_file *f);
int pty_set_fg_pgrp(struct fs_file *f, int pgid);
int pty_get_controlling_sid(struct fs_file *f);
void pty_set_controlling_sid(struct fs_file *f, int sid);
void pty_flush_input(struct fs_file *f);

/* Fill /dev/pts readdir names: writes up to max names into out_names[]. */
int pty_list_slaves(char out_names[][16], int max);

int pty_fill_stat(struct fs_file *f, struct stat *st);
