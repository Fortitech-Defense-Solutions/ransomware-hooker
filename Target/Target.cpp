// Target.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <fstream>
#include <Windows.h>

int _tmain(int argc, _TCHAR* argv[])
{
    int choice;
    std::string filepath = "C:\\Users\\nunes\\Desktop\\";
    std::string content;
    std::string filename;

    while (true) {
        std::cout << "1. Create a new file\n";
        std::cout << "2. Append to an existing file\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        if (choice == 3) {
            break;  // Exit the loop
        }

        std::cout << "Enter the filename: ";
        std::cin >> filename;


        std::cout << "Enter the content to write to the file: ";
        std::cin.ignore();  // Ignore the newline character from the previous input
        std::getline(std::cin, content);

        std::ofstream file;

        if (choice == 1) {
            file.open(filepath+filename, std::ios::out);  // Open the file in write mode, which will create a new file
        }
        else if (choice == 2) {
            file.open(filepath+filename, std::ios::app);  // Open the file in append mode
        }
        else {
            std::cout << "Invalid choice\n";
            continue;  // Skip the rest of this iteration and go back to the start of the loop
        }

        if (!file) {
            std::cout << "Error opening file\n";
            continue;  // Skip the rest of this iteration and go back to the start of the loop
        }

        file << content << "\n";  // Write the content to the file

        file.close();
    }
	return 0;
}

