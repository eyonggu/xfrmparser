/*
 * We don't use input, so don't generate code for it.
 */
%option noinput

/*
 * We don't use unput, so don't generate code for it.
 */
%option nounput


%option noyywrap

%{
extern void read_byte(char *byte);
%}

byte [0-9A-Fa-f][0-9A-Fa-f]
/* byte_eol [0-9A-Fa-f][0-9A-Fa-f]\r?\n */
eol \r?\n\r?

%%

{byte} { read_byte(yytext); }
[ \t]  { /* ignore whitespace */ }
{eol}  { /* ignore eol */ }

%%

