#include <string.h>
#include <stdint.h>
#include <heap.h>

size_t strlen(const char *str)
{
    size_t len = 0;

    while (str[len] != '\0')
        len++;
    return len;
}

char *strcpy(char *dest, const char *src)
{
    char *ptr = dest;

    while (*src != '\0') {
        *ptr = *src;
        ptr++;
        src++;
    }
    *ptr = '\0';
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n)
{
    char *ptr = dest;
    size_t i = 0;

    while (i < n && *src != '\0') {
        *ptr = *src;
        ptr++;
        src++;
        i++;
    }
    while (i < n) {
        *ptr = '\0';
        ptr++;
        i++;
    }
    return dest;
}

int strcmp(const char *str1, const char *str2)
{
    while (*str1 != '\0' && *str2 != '\0') {
        if (*str1 != *str2)
            return (*str1 < *str2) ? -1 : 1;
        str1++;
        str2++;
    }
    if (*str1 == '\0' && *str2 == '\0')
        return 0;
    return (*str1 == '\0') ? -1 : 1;
}

int strncmp(const char *str1, const char *str2, size_t n)
{
    size_t i = 0;

    while (i < n && *str1 != '\0' && *str2 != '\0') {
        if (*str1 != *str2)
            return (*str1 < *str2) ? -1 : 1;
        str1++;
        str2++;
        i++;
    }
    if (i == n)
        return 0;
    if (*str1 == '\0' && *str2 == '\0')
        return 0;
    return (*str1 == '\0') ? -1 : 1;
}

char *strcat(char *dest, const char *src)
{
    char *ptr = dest + strlen(dest);

    while (*src != '\0') {
        *ptr = *src;
        ptr++;
        src++;
    }
    *ptr = '\0';
    return dest;
}

char *strncat(char *dest, const char *src, size_t n)
{
    char *ptr = dest + strlen(dest);
    size_t i = 0;

    while (i < n && *src != '\0') {
        *ptr = *src;
        ptr++;
        src++;
        i++;
    }
    *ptr = '\0';
    return dest;
}

char *strchr(const char *str, int c)
{
    while (*str != '\0') {
        if (*str == (char)c)
            return (char *)str;
        str++;
    }
    if (c == '\0')
        return (char *)str;
    return NULL;
}

char *strrchr(const char *str, int c)
{
    char *last = NULL;

    while (*str != '\0') {
        if (*str == (char)c)
            last = (char *)str;
        str++;
    }
    if (c == '\0')
        return (char *)str;
    return last;
}

char *strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0')
        return (char *)haystack;

    while (*haystack != '\0') {
        const char *h = haystack;
        const char *n = needle;

        while (*h != '\0' && *n != '\0' && *h == *n) {
            h++;
            n++;
        }
        if (*n == '\0')
            return (char *)haystack;
        haystack++;
    }
    return NULL;
}

/* Large copies: rep movsb on x86_64 (ERMS); small copies stay in a loop. */
void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

#if defined(__x86_64__)
    if (n >= 128) {
        size_t cnt = n;
        __asm__ __volatile__(
            "cld\n\t"
            "rep movsb"
            : "+D"(d), "+S"(s), "+c"(cnt)
            :
            : "memory", "cc");
        return dest;
    }
#endif
    for (size_t i = 0; i < n; i++)
        d[i] = s[i];
    return dest;
}

void *memmove(void *dest, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;

    if (d < s) {
        /*
         * Forward overlap is safe with memcpy's forward ERMS copy. This is
         * the hot direction for framebuffer and tty scrolling.
         */
        return memcpy(dest, src, n);
    } else if (d > s) {
        /* Copy backwards using native words; unaligned accesses are valid on
         * x86-64 and avoid a byte loop for insert-line/down-scroll paths. */
        while (n >= sizeof(uint64_t)) {
            n -= sizeof(uint64_t);
            *(uint64_t *)(void *)(d + n) =
                *(const uint64_t *)(const void *)(s + n);
        }
        while (n > 0) {
            n--;
            d[n] = s[n];
        }
    }
    return dest;
}

void *memset(void *ptr, int value, size_t n)
{
    uint8_t *p = (uint8_t *)ptr;

#if defined(__x86_64__)
    if (n >= 128) {
        size_t cnt = n;
        uint8_t val = (uint8_t)value;
        __asm__ __volatile__(
            "rep stosb"
            : "+D"(p), "+c"(cnt)
            : "a"(val)
            : "memory"
        );
        return ptr;
    }
#endif
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)value;
    return ptr;
}

int memcmp(const void *ptr1, const void *ptr2, size_t n)
{
    const uint8_t *p1 = (const uint8_t *)ptr1;
    const uint8_t *p2 = (const uint8_t *)ptr2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i])
            return (p1[i] < p2[i]) ? -1 : 1;
    }
    return 0;
}

void reverse(char *str, size_t length)
{
    size_t start = 0;
    size_t end = length - 1;

    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
}

void itoa(int value, char *str, int base)
{
    int i = 0;
    bool isNegative = false;

    if (value == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return;
    }
    if (value < 0 && base == 10) {
        isNegative = true;
        value = -value;
    }
    while (value != 0) {
        int rem = value % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        value = value / base;
    }
    if (isNegative)
        str[i++] = '-';
    str[i] = '\0';
    reverse(str, i);
}

void utoa(uint32_t value, char *str, int base)
{
    int i = 0;

    if (value == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return;
    }
    while (value != 0) {
        uint32_t rem = value % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        value = value / base;
    }
    str[i] = '\0';
    reverse(str, i);
}

int atoi(const char *str)
{
    int result = 0;
    int sign = 1;
    int i = 0;

    while (str[i] == ' ' || str[i] == '\t' || str[i] == '\n')
        i++;
    if (str[i] == '-' || str[i] == '+') {
        sign = (str[i] == '-') ? -1 : 1;
        i++;
    }
    while (str[i] >= '0' && str[i] <= '9') {
        result = result * 10 + (str[i] - '0');
        i++;
    }
    return sign * result;
}

int trim(char *str)
{
    char *end;

    if (!str)
        return 0;
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r')
        str++;
    if (*str == '\0')
        return 0;

    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        end--;
    *(end + 1) = '\0';
    return 1;
}

static char *strtok_save;

char *strtok(char *str, const char *delim)
{
    if (!str && !strtok_save)
        return NULL;
    if (str)
        strtok_save = str;
    if (!strtok_save)
        return NULL;

    while (*strtok_save && strchr(delim, *strtok_save))
        strtok_save++;
    if (*strtok_save == '\0') {
        strtok_save = NULL;
        return NULL;
    }

    char *token_start = strtok_save;
    while (*strtok_save && !strchr(delim, *strtok_save))
        strtok_save++;
    if (*strtok_save) {
        *strtok_save = '\0';
        strtok_save++;
    } else {
        strtok_save = NULL;
    }
    return token_start;
}

size_t strnlen(const char *s, size_t maxlen)
{
    size_t i = 0;

    if (!s)
        return 0;
    while (i < maxlen && s[i] != '\0')
        i++;
    return i;
}

static int is_delim(char c, const char *delim)
{
    for (const char *d = delim; *d; ++d) {
        if (c == *d)
            return 1;
    }
    return 0;
}

char **split(const char *str, char *delim, int *n)
{
    if (!str || !delim) {
        char **empty = (char **)kmalloc(sizeof(char *));
        if (empty)
            empty[0] = NULL;
        if (n)
            *n = 0;
        return empty;
    }

    size_t count = 0;
    const char *p = str;
    while (*p) {
        while (*p && is_delim(*p, delim))
            p++;
        if (!*p)
            break;
        count++;
        while (*p && !is_delim(*p, delim))
            p++;
    }

    char **out = (char **)kmalloc((count + 1) * sizeof(char *));
    if (!out)
        return NULL;
    out[count] = NULL;
    if (n)
        *n = (int)count;

    p = str;
    size_t idx = 0;
    while (*p) {
        while (*p && is_delim(*p, delim))
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && !is_delim(*p, delim))
            p++;
        size_t len = (size_t)(p - start);
        char *token = (char *)kmalloc(len + 1);
        if (!token) {
            out[idx] = NULL;
            return out;
        }
        for (size_t i = 0; i < len; i++)
            token[i] = start[i];
        token[len] = '\0';
        out[idx++] = token;
    }
    return out;
}
