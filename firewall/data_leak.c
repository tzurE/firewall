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

int check_for_if(char* data){

	return 0;
}

int check_for_while(char* data){

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

int check_for_semicolon(char* data){

	// START CHECK FROM "from" keyword
	// char* point;

	// point = strstr(data, ";");

	// if (point == NULL)
	// 	return 0;

	// if ((point[1] == '\0') || (point[1] == '\n') || (point[1] == ' ')){
	// 	return 1;
	// }
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
	printk("In DLP.");

	//check if data is an empty string
	if (strcmp(data, "") == 0){
		printk("Empty\n");
		return 0;
	}

	if (check_for_brackets(data)){
		printk("found too many brackets, drop\n");
		return 1;
	}

	if (check_for_semicolon(data)){
		printk("Found semicolon, dropping\n");
		return 1;
	}

	if (check_for_brackets_at_end(data)){
		printk("Found brackets, dropping\n");
		return 1;
	}

	if (check_for_special_char(data)){
		printk("Special character found, drop\n");
		return 1;
	}

	if (check_for_keyword(data)){
		printk("Found keyword. dropping.\n");
		return 1;
	}

	if (check_for_comments(data)){
		printk("found comments\n");
		return 1;
	}

	if (check_for_pointers(data)){
		printk("found pointer plays, drop\n");
		return 1;
	}

	if (check_for_main(data)){
		printk("found main! dropping\n");
		return 1;
	}

	if (check_for_if(data)){
		printk("Found if stmnt! drop\n");
		return 1;
	}

	if (check_for_while(data)){
		printk("found while stmnt! drop\n");
		return 1;
	}

	return 0;
}