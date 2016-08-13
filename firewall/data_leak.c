#include "data_leak.h"


int ignore_whitespace_from_location(char *data, int position){
	char ch;
	int length = strlen(data);
	int counter = 0;

	while(position < length){
		ch = *(data+position);

		if (ch == ' '){
			position++;
			counter++;
		}
		else{
			break;
		}
	}
	return counter;
}

int check_for_if_or_while(char* data, char* word, int size_of_word){
	char* position;
	char* new_pos;

	position = strstr(data, word);
	while (position != NULL){
		if (position > data){
			// if it's a part of a different word
			if (!isspace(*(position - 1))){
				position = strstr(position+1, word);
				continue;
			}
		}
		// if it's not space and not "(", then we're in the middle of the word
		if (!isspace(*(position+size_of_word)) && *(position+size_of_word)!='('){
			position = strstr(position+1, word);
			continue;
		}
		// got good condition, which means we found just the word "word"
		break;
	}

	if(position == NULL)
		return 0;

	position = position+size_of_word;

	//skip spaces till the next char, hopefully its "("
	position += ignore_whitespace_from_location(position, 0);

	if (*(position) != '(')
		return 0;

	// "(" is the next char.
	new_pos = strstr(position + 1,")");
	if (new_pos == NULL)
		return 0;
	new_pos +=1;
	new_pos += ignore_whitespace_from_location(new_pos, 0);
	
	if(*(new_pos) != '{')
		return 0;

	if (strstr(new_pos, "}") != NULL)
		return 1;

	return 0;
}

int check_for_for(char* data){
	char* position;
	char* first;
	char* second;
	char* new_pos;

	position = strstr(data, "for");
	if (position == NULL)
		return 0;

	while (position != NULL){
		if (position > data){
			// if it's a part of a different word
			if (!isspace(*(position - 1))){
				position = strstr(position+1, "for");
				continue;
			}
		}
		// if it's not space and not "(", then we're in the middle of the word
		if (!isspace(*(position+3)) && *(position+3)!='('){
			position = strstr(position+1, "for");
			continue;
		}
		// got good condition, which means we found just the word "for"
		break;
	}

	// advance to next "token"
	position+=3;
	//skip white spaces
	position+=ignore_whitespace_from_location(position, 0);

	if (*(position) != '(')
		return 0;

	position+=1;
	// first ;
	first = strstr(position, ";");
	if (first == NULL)
		return 0;
	//second ;, must come after first
	second = strstr(first + 1, ";");
	if (second == NULL)
		return 0;


	new_pos = strstr(second, ")");
	if (new_pos == NULL)
		return 0;

	new_pos+=1;
	new_pos += ignore_whitespace_from_location(new_pos, 0);

	if (*(new_pos) != '{')
		return 0;

	if (strstr(new_pos, "}") != NULL)
		return 1;

	return 0;
}

int check_for_main(char* data){
	char* main_position;
	int position;
	char *new_pos;
	char *new_pos2;
	char ch;

	main_position = strstr(data, "main");

	if (main_position == NULL)
		return 0;

	if (isspace(*(main_position - 1))){
		position = main_position - data;
		while (position > 0){
			//going over position is easier than on main_position
			ch = *(data + position - 1);
			if(isspace(ch)){
				position--;
			}
			else{
				break;
			}
		}

		// this is too little for "void" or "int"
		if (position < 3) {
			return 0;
		}

		if (strncmp((data + (position-3)),"int", 3) == 0 ){
			//jump to end of main word
			main_position += 4;
			//fast forward through the whitespaces
			main_position += ignore_whitespace_from_location(data, main_position - data);

			if (*(main_position) == '('){
				main_position += 1;
				new_pos = strstr(main_position, ")");
				if (new_pos == NULL)
					return 0;

				new_pos2 = strstr(new_pos, "{");
				if (new_pos2 == NULL)
					return 0;

				if (strstr(new_pos2, "}") != NULL)
					return 1;
			}
		}
	}


	return 0;
}

int check_for_brackets_at_end(char *data){
	char* point;

	point = strstr(data, "()");	

	if (point == NULL){
		return 0;
	}

	if (((point[-1] >= 'a') && (point[-1] <= 'z')) || ((point[-1] >= 'A') && (point[-1] <= 'Z'))){
		return 1;
	}
	return 0;
}

int check_for_comments(char* data){
	if (strstr(data, "/*") != NULL && strstr(data, "*/") != NULL){
		return 1;
	}
	return 0;
}

int check_for_keyword(char* data){
	if (strstr(data, "char*") != NULL || strstr(data, "char *") != NULL)
		return 1;

	if (strstr(data, "#define") != NULL){
		return 1;
	}

	if (strstr(data, "#include") != NULL){
		return 1;
	}
	return 0;
}

int check_for_special_char(char* data){
	if (strstr(data, "&&") !=NULL || strstr(data, "==") !=NULL){
		return 1;
	}
	return 0;
}

int check_for_pointers(char* data){
	char* point;
	char* point_before;

	// Clean up the "<mail.com>" line
	point_before = strstr(data, ">");
	if (point_before == NULL){
		return 0;
	}

	point = strstr(point_before, ".");
	if (point == NULL)
		return 0;

	while(point != NULL){
		if (((point[-1] >= 'a') && (point[-1] <= 'z')) || ((point[-1] >= 'A') && (point[-1] <= 'Z'))){
			if (((point[1] >= 'a') && (point[1] <= 'z')) || ((point[1] >= 'A') && (point[1] <= 'Z'))){
				if(point[1] != 'Q')
					return 1;
			}
		}
		point = strstr(point+1, ".");
	}

	point = strstr(data, "->");
	if (point == NULL){
		return 0;
	}

	if (((point[-1] >= 'a') && (point[-1] <= 'z')) || ((point[-1] >= 'A') && (point[-1] <= 'Z'))){
		if (((point[1] >= 'a') && (point[1] <= 'z')) || ((point[1] >= 'A') && (point[1] <= 'Z'))){
			return 1;
		}
	}

	return 0;
}

int check_for_brackets(char* data){
	int length = strlen(data);
	int roundb = 0, squareb = 0, curlb = 0, overall = 0, curly_overall=0, square_overall=0, roverall=0;
	char ch;

	// This counts brackets.
	// there are 5 usual brackets in every protocol
	// any other bracket is counted
	int position = 0;
	while (position < length){
		ch = data[position];
		switch(ch){
			case '(':
				roundb++;
				overall++;
				roverall++;
				break;
			case ')':
				roundb--;
				break;
			case '[':
				squareb++;
				overall++;
				break;
			case ']':
				squareb--;
				break;
			case '{':
				curlb++;
				overall++;
				curly_overall++;
				break;
			case '}':
				curlb--;
				break;
			default:
				break;
		}
		// if there are too many types of one side brackets, not code.
		if (roundb < 0 || squareb < 0 || curlb < 0){
			return 0;
		}
		//next char
		// printk("%d, %d, %d, %d\n",roverall ,square_overall, curly_overall, overall);
		position++;
	}

	// check threshould and other conds:
	// to much brackets - suspicious, drop.
	if (curly_overall > CBRACKETS_THEESHOLD || overall > BRACKETS_THEESHOLD || square_overall > SRACKETS_THEESHOLD){
		return 1;
	}
	return 0;
}


int search_for_data_leak(char* data){

	//check if data is an empty string
	if (strcmp(data, "") == 0){
		return 0;
	}

	// cound number of brackets
	if (check_for_brackets(data)){
		printk("Code Detection: found too many brackets, drop\n");
		return 1;
	}

	if (check_for_brackets_at_end(data)){
		printk("Code Detection: Found function call, drop\n");
		return 1;
	}

	if (check_for_special_char(data)){
		printk("Code Detection: Special character found, drop\n");
		return 1;
	}

	if (check_for_keyword(data)){
		printk("Code Detection: Found known keywords. drop.\n");
		return 1;
	}

	if (check_for_comments(data)){
		printk("Code Detection: found comments special sign, drop\n");
		return 1;
	}

	if (check_for_pointers(data)){
		printk("Code Detection: found pointer refrence, drop\n");
		return 1;
	}

	if (check_for_main(data)){
		printk("found main function, drop\n");
		return 1;
	}

	if (check_for_if_or_while(data, "if", 2)){
		printk("Found if stmnt, drop\n");
		return 1;
	}

	if (check_for_if_or_while(data, "while", 5)){
		printk("found while stmnt, drop\n");
		return 1;
	}

	if (check_for_for(data)){
		printk("found for stmnt, drop\n");
		return 1;
	}

	return 0;
}