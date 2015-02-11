/* The functions included here are useful for text manipulation.  They
 * replace or augment the standard C string library.  These functions
 * are either safer replacements, or they provide services not included
 * with the standard C string library.
 */

#include "compatible.h"
#include "errno.h"
#include "text.h"
#include "xctype.h"


#ifndef HAVE_VSNPRINTF
/*
 * 'vsnprintf()' - Format a string into a fixed size buffer.
 */

int             /* O - Number of bytes formatted */
vsnprintf(char       *buffer,   /* O - Output buffer */
          size_t     bufsize,   /* O - Size of output buffer */
          const char *format,   /* I - printf-style format string */
          va_list    ap)    /* I - Pointer to additional arguments */
{
    char      *bufptr,    /* Pointer to position in buffer */
              *bufend,    /* Pointer to end of buffer */
              sign,       /* Sign of format width */
              size,       /* Size character (h, l, L) */
              type;       /* Format type character */
    const char    *bufformat; /* Start of format */
    int       width,      /* Width of field */
              prec;       /* Number of characters of precision */
    char      tformat[100],   /* Temporary format string for sprintf() */
              temp[1024]; /* Buffer for formatted numbers */
    int       *chars;     /* Pointer to integer for %p */
    char      *s;     /* Pointer to string */
    int       slen;       /* Length of string */


    /*
     * Loop through the format string, formatting as needed...
     */

    bufptr = buffer;
    bufend = buffer + bufsize - 1;

    while (*format && bufptr < bufend)
    {
        if (*format == '%')
        {
            bufformat = format;
            format ++;

            if (*format == '%')
            {
                *bufptr++ = *format++;
                continue;
            }
            else if (strchr(" -+#\'", *format))
                sign = *format++;
            else
                sign = 0;

            width = 0;
            while (isdigit(*format))
                width = width * 10 + *format++ - '0';

            if (*format == '.')
            {
                format ++;
                prec = 0;

                while (isdigit(*format))
                    prec = prec * 10 + *format++ - '0';
            }
            else
                prec = -1;

            if (*format == 'l' && format[1] == 'l')
            {
                size = 'L';
                format += 2;
            }
            else if (*format == 'h' || *format == 'l' || *format == 'L')
                size = *format++;

            if (!*format)
                break;

            type = *format++;

            switch (type)
            {
                case 'E' : /* Floating point formats */
                case 'G' :
                case 'e' :
                case 'f' :
                case 'g' :
                    if ((format - bufformat + 1) > sizeof(tformat) ||
                        (width + 2) > sizeof(temp))
                        break;

                    strncpy(tformat, bufformat, format - bufformat);
                    tformat[format - bufformat] = '\0';

                    sprintf(temp, tformat, va_arg(ap, double));

                    if ((bufptr + strlen(temp)) > bufend)
                    {
                        strncpy(bufptr, temp, bufend - bufptr);
                        bufptr = bufend;
                        break;
                    }
                    else
                    {
                        strcpy(bufptr, temp);
                        bufptr += strlen(temp);
                    }
                    break;

                case 'B' : /* Integer formats */
                case 'X' :
                case 'b' :
                case 'd' :
                case 'i' :
                case 'o' :
                case 'u' :
                case 'x' :
                    if ((format - bufformat + 1) > sizeof(tformat) ||
                        (width + 2) > sizeof(temp))
                        break;

                    strncpy(tformat, bufformat, format - bufformat);
                    tformat[format - bufformat] = '\0';

                    sprintf(temp, tformat, va_arg(ap, int));

                    if ((bufptr + strlen(temp)) > bufend)
                    {
                        strncpy(bufptr, temp, bufend - bufptr);
                        bufptr = bufend;
                        break;
                    }
                    else
                    {
                        strcpy(bufptr, temp);
                        bufptr += strlen(temp);
                    }
                    break;

                case 'p' : /* Pointer value */
                    if ((chars = va_arg(ap, int *)) != NULL)
                        *chars = bufptr - buffer;
                    break;

                case 'c' : /* Character or character array */
                    if (width <= 1)
                        *bufptr++ = va_arg(ap, int);
                    else
                    {
                        if ((bufptr + width) > bufend)
                            width = bufend - bufptr;

                        memcpy(bufptr, va_arg(ap, char *), width);
                        bufptr += width;
                    }
                    break;

                case 's' : /* String */
                    if ((s = va_arg(ap, char *)) == NULL)
                        s = "(null)";

                    slen = strlen(s);
                    if (slen > width && prec != width)
                        width = slen;

                    if ((bufptr + width) > bufend)
                        width = bufend - bufptr;

                    if (slen > width)
                        slen = width;

                    if (sign == '-')
                    {
                        strncpy(bufptr, s, slen);
                        memset(bufptr + slen, ' ', width - slen);
                    }
                    else
                    {
                        memset(bufptr, ' ', width - slen);
                        strncpy(bufptr + width - slen, s, slen);
                    }

                    bufptr += width;
                    break;

                case 'n' : /* Output number of chars so far */
                    if ((format - bufformat + 1) > sizeof(tformat) ||
                        (width + 2) > sizeof(temp))
                        break;

                    strncpy(tformat, bufformat, format - bufformat);
                    tformat[format - bufformat] = '\0';

                    sprintf(temp, tformat, va_arg(ap, int));

                    if ((bufptr + strlen(temp)) > bufend)
                    {
                        strncpy(bufptr, temp, bufend - bufptr);
                        bufptr = bufend;
                        break;
                    }
                    else
                    {
                        strcpy(bufptr, temp);
                        bufptr += strlen(temp);
                    }
                    break;
            }
        }
        else
            *bufptr++ = *format++;
    }

    /*
     * Nul-terminate the string and return the number of characters in it.
     */

    *bufptr = '\0';
    return (bufptr - buffer);
}
#endif /* !HAVE_VSNPRINT */


/*
 * Removes any new-line or carriage-return characters from the end of the
 * string. This function is named after the same function in Perl.
 * "length" should be the number of characters in the buffer, not including
 * the trailing NULL.
 *
 * Returns the number of characters removed from the end of the string.  A
 * negative return value indicates an error.
 */
ssize_t chomp (char *buffer, size_t length)
{
    size_t chars;

    assert (buffer != NULL);
    assert (length > 0);

    /* Make sure the arguments are valid */
    if (buffer == NULL)
        return -EFAULT;
    if (length < 1)
        return -ERANGE;

    chars = 0;

    --length;
    while (buffer[length] == '\r' || buffer[length] == '\n')
    {
        buffer[length] = '\0';
        chars++;

        /* Stop once we get to zero to prevent wrap-around */
        if (length-- == 0)
            break;
    }

    return chars;
}

int             /* O - Result of comparison (-1, 0, or 1) */
proxy_strcasecmp(const char *s,   /* I - First string */
           const char *t)   /* I - Second string */
{
	char S, T;

    while (*s != '\0' && *t != '\0')
    {
    	S = tolower(*s);
		T = tolower(*t);
        if (S < T) 
			return (-1);
        else 
			if (S > T) return (1);

        s ++;
        t ++;
    }

    if (*s == '\0' && *t == '\0')
        return (0);
    else if (*s != '\0')
        return (1);
    else
        return (-1);
}

/*
 * 'strncasecmp()' - Do a case-insensitive comparison on up to N chars.
 */

int             /* O - Result of comparison (-1, 0, or 1) */
proxy_strncasecmp(const char *s,  /* I - First string */
            const char *t,  /* I - Second string */
            size_t     n)   /* I - Maximum number of characters to compare */
{
	char S, T;
    while (*s != '\0' && *t != '\0' && n > 0)
    {
    	S = tolower(*s);
		T = tolower(*t);
        if (S < T) 
			return (-1);
        else 
			if (S > T) return (1);

        s ++;
        t ++;
        n --;
    }

    if (n == 0)
        return (0);
    else if (*s == '\0' && *t == '\0')
        return (0);
    else if (*s != '\0')
        return (1);
    else
        return (-1);
}

