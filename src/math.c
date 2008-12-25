/* math.c - Mathematics functions for chanserv.calc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.  Important limitations are
 * listed in the COPYING file that accompanies this software.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, email srvx-maintainers@srvx.net.
 *
 * $Id$
 */

#include "conf.h"
#include "helpfile.h"
#include "nickserv.h"
#include "modcmd.h"
#include "saxdb.h"
#include "timeq.h"

#ifndef HAVE_MATH_H
  #include <math.h>
  #include <complex.h>
#else
  #include <tgmath.h>
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#define strcasecmp stricmp
#endif

enum MathType {
	mEnd,
	mPlus,
	mMinus,
	mMult,
	mDiv,
	mPower,
	mLt,
	mRt,
	mOp,
	mOpEnd,
	mNumber
};

enum MathOpType {
	otExp,
	otLog,
	otSin,
	otASin,
	otSinH,
	otCos,
	otACos,
	otCosH,
	otTan,
	otATan,
	otTanH,
	otSqrt,
	otAbs,
	otCeil,
	otFloor
};

/* This table is needed for the translation from infix to postfix. 	*/
static const int TranslateTable[][10] = {
/*List:  _  +  -  *  /  ^  (  )  [  ]					*/
/*Stack:								*/
/* _ */	{4, 1, 1, 1, 1, 1, 1, 5, 1, 5},
/* + */	{2, 2, 2, 1, 1, 1, 1, 2, 1, 2},
		{2, 2, 2, 1, 1, 1, 1, 2, 1, 2},
		{2, 2, 2, 2, 2, 1, 1, 2, 1, 2},
		{2, 2, 2, 2, 2, 1, 1, 2, 1, 2},
		{2, 2, 2, 2, 2, 2, 1, 2, 1, 2},
		{5, 1, 1, 1, 1, 1, 1, 3, 1, 5},
		{5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		{5, 1, 1, 1, 1, 1, 1, 5, 1, 6},
		{5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
};

typedef struct MathToken {
	enum MathType Type;
	double Value;
	enum MathOpType OpType;
	struct MathToken *Next;
	struct MathToken *Previous;		/* Previous is used in the stack */
} *MathList;

typedef struct Values {
	double Value;
	struct Values *Next;
	struct Values *Previous;
} *ValueList;

void do_math(char *Buffer, char *Math)
{
	int HasDot;
	double Value = 0.0;
	double Floating;	/* = 10^number of digits after the dot */
	int ValueExpected = 1;
	char Identifier[512];

	MathList ListFirst = NULL;
	MathList StackFirst = NULL;
	MathList PostFixFirst = NULL;
	ValueList TheValuesFirst = NULL;
	MathList List;
	MathList Stack;
	MathList PostFix;
	ValueList TheValues;
	int Minus = 0;

	void *Temp;
	int Index;
	int OEndExpected;


	  /* This is a HACK to insert * before ( so multiplication takes place
	   * in things such as 3(3) instead of ignoring the first 3. Submitted
	   * by Osiris.
	   * I spent some time tlooking at calc.c and I didnt see an easy way
	   * to do this there... and that file gives me a headache.. so.. -Rubin
	   */
	  char newMath[MAXLEN];
	  char *ptr;
	  char lastNumber = false;
	  char lastBracket = false;


	  ptr = newMath;
	  while(*Math && ptr < newMath+MAXLEN-1)
	  {
	      switch(*Math)
	      {
		case '1': case '2':
		case '3': case '4':
		case '5': case '6':
		case '7': case '8':
		case '9': case '0':
		  lastNumber = true;
		  if(lastBracket == true)
		  {
		      *ptr = '*';
		      ptr++;
		  }
		  *ptr = *Math;
		  lastBracket = false;
		  break;
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': 
                case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n': 
                case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u': 
                case 'v': case 'w': case 'x': case 'y': case 'z': 
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': 
                case 'H': case 'I': case 'J': case 'K': case 'L': case 'M': case 'N': 
                case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T': case 'U': 
                case 'V': case 'W': case 'X': case 'Y': case 'Z': 
                 case ')': case ']': /* Support sin[12](3) also */
		  lastNumber = true;
		  lastBracket = true;
		  *ptr = *Math;
		  break;
		case '(': case '[':
		  if (lastNumber == true)
		  {
		    *ptr = '*';
		    ptr++;
		  }
		  *ptr = *Math;
		  lastNumber = false;
		  lastBracket = false;
		  break;
		default:
		  if(isalpha(*Math))
		  {
		    if(lastNumber == true)
		    {
		      *ptr = '*';
		      ptr++;
		    }
		  }
		  *ptr = *Math;
		  lastNumber = false;
		  lastBracket = false;
		  break;
	      }
	      Math++;
	      ptr++;
	    }
	    *ptr = '\0';
	    Math = newMath;

	if (!(List = ListFirst = malloc(sizeof(struct MathToken)))) goto MemError;
	if (!(Stack = StackFirst = malloc(sizeof(struct MathToken)))) goto MemError;
	if (!(PostFix = PostFixFirst = malloc(sizeof(struct MathToken)))) goto MemError;
	if (!(TheValues = TheValuesFirst = malloc(sizeof(struct Values)))) goto MemError;

	List->Next = NULL;
	Stack->Next = NULL;
	PostFix->Next = NULL;
	TheValues->Next = NULL;

	StackFirst->Type = mEnd;

	/* First tokenize the buffer */

	while (*Math) {
		if (isdigit(*Math) || *Math == '.') {
			if (!ValueExpected) {
				strcpy(Buffer, "Unexpected value");
				goto End;
			}
			HasDot = 0;
			Value = 0;
			Floating = 1;
			while (isdigit(*Math) || *Math == '.') {
				if (*Math == '.')
					if (HasDot) {
						strcpy(Buffer, "Error in constant");
						goto End;
					}
					else
						HasDot = 1;
				else
					if (!HasDot)
						Value = Value * 10 + *Math - '0';
					else {
						Floating = Floating * 10;
						Value = Value + (*Math - '0') / Floating;
					}
				++Math;
			}
			if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
			List->Next = NULL;
			List->Type = mNumber;
			List->Value = Value;
			if (Minus) {
				List->Value = -Value;
				Minus = 0;
			}
			ValueExpected = 0;
		}
		else switch (*Math) {
			case ' ': case '\t':
				++Math;
				break;
			case '+':	case '-':
			case '*':	case '/':
			case '^':	case '(':
			case ')':	case ']':
				if (*Math == '-' && ValueExpected) {
					Minus = !Minus;
					++Math;
					break;
				}
				if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto End;
				List->Next = NULL;
				switch (*Math) {
					case '+':	List->Type = mPlus;		break;
					case '-':	List->Type = mMinus;	break;
					case '*':	List->Type = mMult;		break;
					case '/':	List->Type = mDiv;		break;
					case '^':	List->Type = mPower;	break;
					case '(':	List->Type = mLt;		break;
					case ')':	List->Type = mRt;		break;
					case ']':	List->Type = mOpEnd;	break;
				}
				if (*Math != '(' && ValueExpected) {
					strcpy(Buffer, "Value expected");
					goto End;
				}
				if (*Math != ')' && *Math != ']')
					ValueExpected = 1;
				++Math;
				break;
			default:
				if (isalpha(*Math)) {
					Index = 0;
					while (isalpha(*Math))
						Identifier[Index++] = *Math++;
					Identifier[Index] = '\0';
					OEndExpected = 0;
					if (!ValueExpected) {
						strcpy(Buffer, "Unexpected value");
						goto End;
					}
					if (!strcasecmp(Identifier, "e")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mNumber;
						List->Value = exp(1);
						ValueExpected = 0;
					}
					else if (!strcasecmp(Identifier, "pi")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mNumber;
						List->Value = 4 * atan(1);
						ValueExpected = 0;
					}
					else if (!strcasecmp(Identifier, "rand")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mNumber;
						List->Value = (double)rand() / (double)RAND_MAX;
						ValueExpected = 0;
					}
					else if (!strcasecmp(Identifier, "exp")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otExp;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "log")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otLog;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "sin")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otSin;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "asin")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otASin;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "sinh")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otSinH;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "cos")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otCos;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "acos")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otACos;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "cosh")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otCosH;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "tan")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otTan;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "atan")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otATan;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "tanh")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otTanH;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "sqrt")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otSqrt;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "abs")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otAbs;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "ceil")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otCeil;
						OEndExpected = 1;
					}
					else if (!strcasecmp(Identifier, "floor")) {
						if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
						List->Next = NULL;
						List->Type = mOp;
						List->OpType = otFloor;
						OEndExpected = 1;
					}
					else {
						strcpy(Buffer, "Unexpected Identifier");
						goto End;
					}
					if (OEndExpected) {
						while (*Math == ' ' || *Math == '\t')
							++Math;
						if (*Math != '[') {
							strcpy(Buffer, "'[' expected");
							goto End;
						}
						++Math;
					}
				}
				else {
					strcpy(Buffer, "Unknown character in expression");
					goto End;
				}
		}
	}
	if (ValueExpected) {
		strcpy(Buffer, "Value expected");
		goto End;
	}
	if (!(List = List->Next = malloc(sizeof(struct MathToken)))) goto MemError;
	List->Next = NULL;
	List->Type = mEnd;

	/* We've got them tokenized now... now convert it
		from infix notation to postfix notation */

	List = ListFirst->Next;
	while (List) {
		if (List->Type == mNumber) {
			PostFix = PostFix->Next = List;
			ListFirst = List = List->Next;
			PostFix->Next = NULL;
		}
		else switch (TranslateTable[Stack->Type][List->Type]) {
			case 1:
				List->Previous = Stack;
				Stack = Stack->Next = List;
				ListFirst = List = List->Next;
				Stack->Next = NULL;
				break;
			case 2:
				PostFix = PostFix->Next = Stack;
				Stack = Stack->Previous;
				Stack->Next = NULL;
				break;
			case 3:
				Stack = Stack->Previous;
				free(Stack->Next);
				Stack->Next = NULL;
				Temp = List;
				ListFirst = List = List->Next;
				free(Temp);
				break;
			case 4:
				PostFix = PostFix->Next = List;
				ListFirst = List = List->Next;
				break;
			case 5:
				strcpy(Buffer, "Error in expression");
				goto End;
			case 6:
				PostFix = PostFix->Next = Stack;
				Stack = Stack->Previous;
				Stack->Next = NULL;
				Temp = List;
				ListFirst = List = List->Next;
				free(Temp);
				break;
			default:
				strcpy(Buffer, "Internal error");
				goto End;
		}
	}

	/* Now we've got everything in Postfix notation... calculate it now */

	PostFix = PostFixFirst->Next;
	while (PostFix) {
		switch (PostFix->Type) {
			case mNumber:
				if (!(TheValues->Next = malloc(sizeof(struct Values)))) goto MemError;
				TheValues->Next->Previous = TheValues;
				TheValues = TheValues->Next;
				TheValues->Next = NULL;
				TheValues->Value = PostFix->Value;
				break;
			case mPlus:
				TheValues->Previous->Value += TheValues->Value;
				TheValues = TheValues->Previous;
				free(TheValues->Next);
				TheValues->Next = NULL;
				break;
			case mMinus:
				TheValues->Previous->Value -= TheValues->Value;
				TheValues = TheValues->Previous;
				free(TheValues->Next);
				TheValues->Next = NULL;
				break;
			case mMult:
				TheValues->Previous->Value *= TheValues->Value;
				TheValues = TheValues->Previous;
				free(TheValues->Next);
				TheValues->Next = NULL;
				break;
			case mDiv:
				if (TheValues->Value == 0) {
					strcpy(Buffer, "Division by zero error!");
					goto End;
				}
				TheValues->Previous->Value /= TheValues->Value;
				TheValues = TheValues->Previous;
				free(TheValues->Next);
				TheValues->Next = NULL;
				break;
			case mPower:
				TheValues->Previous->Value = pow(TheValues->Previous->Value, TheValues->Value);
				TheValues = TheValues->Previous;
				free(TheValues->Next);
				TheValues->Next = NULL;
				break;
			case mEnd:
				Value = TheValues->Value;
				break;
			case mOp:
				switch (PostFix->OpType) {
                    case otExp:
                        TheValues->Value = exp(TheValues->Value);
                        break;
					case otLog:
						if (TheValues->Value <= 0) {
							strcpy(Buffer, "Log of non-positive value error");
							goto End;
						}
						TheValues->Value = log(TheValues->Value);
						break;
					case otSin:
						TheValues->Value = sin(TheValues->Value);
						break;
					case otASin:
						if (TheValues->Value < -1 || TheValues->Value > 1) {
							strcpy(Buffer, "Domain error");
							goto End;
						}
						TheValues->Value = asin(TheValues->Value);
						break;
					case otSinH:
						TheValues->Value = sinh(TheValues->Value);
					case otCos:
						TheValues->Value = cos(TheValues->Value);
						break;
					case otACos:
						if (TheValues->Value < -1 || TheValues->Value > 1) {
							strcpy(Buffer, "Domain error");
							goto End;
						}
						TheValues->Value = acos(TheValues->Value);
						break;
					case otCosH:
						TheValues->Value = cosh(TheValues->Value);
						break;
					case otTan:
						TheValues->Value = tan(TheValues->Value);
						break;
					case otATan:
						TheValues->Value = atan(TheValues->Value);
						break;
					case otTanH:
						TheValues->Value = tanh(TheValues->Value);
						break;
					case otSqrt:
						if (TheValues->Value < 0) {
							strcpy(Buffer, "Sqrt from number < 0");
							goto End;
						}
						TheValues->Value = sqrt(TheValues->Value);
						break;
					case otAbs:
						TheValues->Value = fabs(TheValues->Value);
						break;
					case otCeil:
						TheValues->Value = ceil(TheValues->Value);
						break;
					case otFloor:
						TheValues->Value = floor(TheValues->Value);
						break;
				}
				break;
			/* The following three do not occur. They are here to prevent compiler warnings */
			case mLt:
			case mRt:
			case mOpEnd:
				break;
		}
		PostFix = PostFix->Next;
	}

	if (fabs(Value) < 1000000 && (fabs(Value) > 0.001 || Value == 0.0)) 
	{
		if (fabs(Value - floor(Value + 0.5)) < 0.00001) {
			sprintf(Buffer, "%.0f", Value);
		}
		else {
			sprintf(Buffer, "%f", Value);
		}
	}
	else {
		sprintf(Buffer, "%E", Value);
	}
End:
	/* Free up memory here */

	List = ListFirst;
	while (List) {
		Temp = List;
		List = List->Next;
		free(Temp);
	}

	Stack = StackFirst;
	while (Stack) {
		Temp = Stack;
		Stack = Stack->Next;
		free(Temp);
	}

	PostFix = PostFixFirst;
	while (PostFix) {
		Temp = PostFix;
		PostFix = PostFix->Next;
		free(Temp);
	}

	TheValues = TheValuesFirst;
	while (TheValues) {
		Temp = TheValues;
		TheValues = TheValues->Next;
		free(Temp);
	}

	return;

MemError:
	strcpy(Buffer, "Couldn't allocate enough memory");
	goto End;
}
