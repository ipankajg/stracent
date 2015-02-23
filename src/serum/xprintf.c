/*--------------------------------------------------------------------------/
/
/ Copyright(C) 2011, ChaN, all right reserved.
/
/ *This software is a free software and there is NO WARRANTY.
/ *No restriction on use.You can use, modify and redistribute it for
/ personal, non - profit or commercial products UNDER YOUR RESPONSIBILITY.
/ *Redistributions of source code must retain the above copyright notice.
/
/--------------------------------------------------------------------------*/

typedef char*  x_va_list;
#define x_va_start      _x_va_start
#define x_va_arg        _x_va_arg
#define x_va_end        _x_va_end

#define _X_ADDRESSOF(v)     (&(v))
#define _X_INTSIZEOF(n)     ((sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1))

#define _x_va_start(ap,v)   (ap = (x_va_list)_X_ADDRESSOF(v) + _X_INTSIZEOF(v))
#define _x_va_arg(ap,t)     (*(t *)((ap += _X_INTSIZEOF(t)) - _X_INTSIZEOF(t)))
#define _x_va_end(ap)       (ap = (x_va_list)0)

typedef struct _xout {
    char *outptr;
} xout, *pxout;

void
xputc(pxout xo, char c)
{
    *xo->outptr++ = (unsigned char)c;
}

void
xputs(pxout xo, const char *str)
{
    while (*str)
        xputc(xo, *str++);
}

static void
xvprintf(pxout xo, const char *fmt, x_va_list arp)
{
    unsigned int r, i, j, w, f;
    unsigned long v;
    char s[16], c, d, *p;


    for (;;) {
        c = *fmt++;             /* Get a char */
        if (!c)
            break;
        if (c != '%') {         /* Pass through it if not a % sequense */
            xputc(xo, c);
            continue;
        }
        f = 0;
        c = *fmt++;             /* Get first char of the sequense */
        if (c == '0') {         /* Flag: '0' padded */
            f = 1;
            c = *fmt++;
        }
        else {
            if (c == '-') {     /* Flag: left justified */
                f = 2;
                c = *fmt++;
            }
        }
        for (w = 0; c >= '0' && c <= '9'; c = *fmt++)   /* Minimum width */
            w = w * 10 + c - '0';
        if (c == 'l' || c == 'L') { /* Prefix: Size is long int */
            f |= 4;
            c = *fmt++;
        }
        if (!c)
            break;              /* End of format? */
        d = c;
        if (d >= 'a')
            d -= 0x20;
        switch (d) {            /* Type is... */
        case 'S':              /* String */
            p = x_va_arg(arp, char *);
            for (j = 0; p[j]; j++);
            while (!(f & 2) && j++ < w)
                xputc(xo, ' ');
            xputs(xo, p);
            while (j++ < w)
                xputc(xo, ' ');
            continue;
        case 'C':              /* Character */
            xputc(xo, (char)x_va_arg(arp, int));
            continue;
        case 'B':              /* Binary */
            r = 2;
            break;
        case 'O':              /* Octal */
            r = 8;
            break;
        case 'D':              /* Signed decimal */
        case 'U':              /* Unsigned decimal */
            r = 10;
            break;
        case 'X':              /* Hexdecimal */
            r = 16;
            break;
        default:               /* Unknown type (passthrough) */
            xputc(xo, c);
            continue;
        }

        /* Get an argument and put it in numeral */
        v = (f & 4) ? 
                x_va_arg(arp, long) :
                ((d == 'D') ? 
                    (long)x_va_arg(arp, int) :
                    (long)x_va_arg(arp, unsigned int));

        if (d == 'D' && (v & 0x80000000)) {
            v = 0 - v;
            f |= 8;
        }
        i = 0;
        do {
            d = (char)(v % r);
            v /= r;
            if (d > 9)
                d += (c == 'x') ? 0x27 : 0x07;
            s[i++] = d + '0';
        }
        while (v && i < sizeof(s));
        if (f & 8)
            s[i++] = '-';
        j = i;
        d = (f & 1) ? '0' : ' ';
        while (!(f & 2) && j++ < w)
            xputc(xo, d);
        do
            xputc(xo, s[--i]);
        while (i);
        while (j++ < w)
            xputc(xo, ' ');
    }
}

void
xsprintf(char *buff, const char *fmt, ...)
{
    x_va_list arp;
    xout xo;

    xo.outptr = buff;

    x_va_start(arp, fmt);
    xvprintf(&xo, fmt, arp);
    x_va_end(arp);

    *xo.outptr = 0;    /* Terminate output string with a \0 */
}

