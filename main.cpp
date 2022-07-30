/////////////////////////////////////////////////////////////
// Seguranca Computacional - 2022/1
// Prof. Joao Gondim
// Moises Felipe Jaco Andrade de Lima - 190018364
// Tong Zhou - 190038764
// Trabalho 1 - Cifra de Vigenere
/////////////////////////////////////////////////////////////

//Includes
#include <bits/stdc++.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include <float.h>

//Defines
#define ALPHABETSIZE 26
#define NGRAPHLENGTH 3

//Funções
void Init();//sets initial values to their standard
void RoutineManager(); //Controls the main menu of the program
void Settings();//Controls the settings menu
void Encryption();//Controls the encryption routine
void DecryptionWithKey();//Controls the decryption routine, given a certain key
void DecryptionWithoutKey();//Attacks the text and tries to find a password based on the length suggestion
void Line();//prints a pretty cool line used to separate stuff
std::string ReadFile(std::string);//Turns .txt into a string
bool WriteToFile(std::string, std::string);//Turns string into .txt
std::string TextCleaner(std::string);//removes characters that might ruin the character analysis
std::string VigenereEncrypt(std::string, std::string);//encryption algorythm
std::string VigenereDecrypt(std::string, std::string);//decryption algorythm
int NGraphAnalysis(std::string);//Checks the trigraphs of the cypher text
std::string KeyAnalysis(int, std::string);//Checks the character frequencies and find suitable passwords

//Global variables
int LENGTHCHOICES = 0;//suggestions of key length
int MAXKEYLENGTH = 0;//max size of key to be checked
float *LANGUAGEFREQ = 0;//pointer to the vector of probabilities for english or portuguese characters

char ALPHABET[26] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
char ALPHABETUP[26] = {'A','B','B','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};

float PTBRFREQ[ALPHABETSIZE] = {0.1463, 0.0104, 0.0388, 0.0499, 0.1257, 0.0102, 0.0130,
                    0.0128, 0.0618, 0.0040, 0.0002, 0.0278, 0.0474, 0.0505,
                    0.1073, 0.0252, 0.0120, 0.0653, 0.0780, 0.0434, 0.0463,
                    0.0167, 0.0001, 0.0021, 0.0001, 0.0047};
float ENUSFREQ[ALPHABETSIZE] = {0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0201,
                    0.0609, 0.0697, 0.0015, 0.0077, 0.0402, 0.0241, 0.0675,
                    0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276,
                    0.0098, 0.0236, 0.0015, 0.0197, 0.0007};

int main(){
    Init();//Read preset values
    RoutineManager(); //starts program
    return 0;//see ya
}

void Init(){
    LENGTHCHOICES = 5;
    MAXKEYLENGTH = 20;
    LANGUAGEFREQ = ENUSFREQ;
}

void RoutineManager(){
    bool RunProgram = true;
    while(RunProgram){
        Line();
        std::cout << "\nV.C.U. - Vigenere Cypher Utilities\nWhat would you like to do?\n\n"<<
        "1- Encrypt text\n2- Decrypt Text with key\n3- Decypher key\n4- Settings\n"<<
        "Any other number- Exit\n\nType your choice and press enter: ";
        int Selection;
        std::cin >> Selection;
        switch(Selection)
        {
            case 1:
                //Run Encryption
                Encryption();
                break;
            case 2:
                //Run Decryption with password
                DecryptionWithKey();
                break;
            case 3:
                //Run Decypher key tool
                DecryptionWithoutKey();
                break;
            case 4:
                //Run Settings
                Settings();
                break;
            default:
                RunProgram = false;
        }
    }
}

void Line()
{
    std::cout << "\n_________________________________________________\n";
}

void Settings()
{
    bool RunSettings = true;
    bool LangChoice = true;
    while(RunSettings)
    {
        Line();
        std::cout << "\n\nWhich settings do you wanna change?\n\n"<<
        "1- Maximum key length\n2- Number of key size suggestions" <<
        "\n3- Text language (for decryption without password)\n"<<
        "Any other number- Return to menu\n\nType your choice and press enter: ";

        int Selection;
        std::cin >> Selection;
        switch(Selection)
        {
            case 1:
                //Set Length
                std::cout << "Actual size is " << MAXKEYLENGTH <<".\nType the new maximum key size: ";
                std::cin >> Selection;
                MAXKEYLENGTH = Selection;
                break;
            case 2:
                //Set Suggestions

                std::cout << "Actual key size suggestions are "<< LENGTHCHOICES << ".\nType the key size suggestions number: ";
                std::cin >> Selection;
                LENGTHCHOICES = Selection;
                break;
            case 3:
                //Select language
                LangChoice = true;
                while(LangChoice)
                {
                    Line();
                    std::cout << "Actual Language is "<< (LANGUAGEFREQ == ENUSFREQ ? "English" : "Portuguese")
                    << ".\nType 1 for English, 2 for Portuguese: ";
                    std::cin >> Selection;
                    switch(Selection)
                    {
                        case 1:
                            LANGUAGEFREQ = ENUSFREQ;
                            LangChoice = false;
                            break;
                        case 2:
                            LANGUAGEFREQ = PTBRFREQ;
                            LangChoice = false;
                            break;
                        default:
                            std::cout << "Invalid choice.\n";
                    }
                }
                break;
            default:
                RunSettings = false;
        }
    }
}

void Encryption()
{
    Line();
    std::string Key, Filename;
    std::cout << "\nType the filename of the archive to be encrypted: ";
    std::cin >> Filename;
    std::cout << "\nType the wished encryption key: ";
    std::cin >> Key;
    std::string Result = VigenereEncrypt(ReadFile(Filename), Key);

    std::cout << "\nThe result is: "<< Result;

    bool SavingLoop = true;
    while(SavingLoop)
    {
        std::cout << "\n\nType the filename for the destination archive: ";
        std::cin >> Filename;
        if (WriteToFile(Result, Filename))
        {
            std::cout << "\nSaved successfully";
            SavingLoop = false;
        }
        else
        {
            std::cout << "\nError! Try saving with another filename.";
        }
    }
}

void DecryptionWithKey()
{
    Line();
    std::string Key, Filename;
    std::cout << "\nType the filename of the archive to be decrypted: ";
    std::cin >> Filename;
    std::cout << "\nType the decryption key: ";
    std::cin >> Key;
    std::string Result = VigenereDecrypt(ReadFile(Filename), Key);

    std::cout << "\nThe result is: "<< Result;

    bool SavingLoop = true;
    while(SavingLoop)
    {
        std::cout << "\n\nType the filename for the destination archive: ";
        std::cin >> Filename;
        if (WriteToFile(Result, Filename))
        {
            std::cout << "\nSaved successfully";
            SavingLoop = false;
        }
        else
        {
            std::cout << "\nError! Try saving with another filename.";
        }
    }
}

void DecryptionWithoutKey()
{
    Line();
    std::string Filename;
    std::cout << "\nType the filename of the archive to be decrypted: ";
    std::cin >> Filename;

    std::string Text = ReadFile(Filename);
    std::string CleanText = TextCleaner(Text);
    int ChosenLength = NGraphAnalysis(CleanText);
    std::string FoundKey = KeyAnalysis(ChosenLength, CleanText);

    std::cout << "\nPassword found is: "<< FoundKey;

    std::string Result = VigenereDecrypt(ReadFile(Filename), FoundKey);

    std::cout << "\n\nThe result is: "<< Result;

    bool SavingLoop = true;
    while(SavingLoop)
    {
        std::cout << "\n\nType the filename for the destination archive: ";
        std::cin >> Filename;
        if (WriteToFile(Result, Filename))
        {
            std::cout << "\nSaved successfully";
            SavingLoop = false;
        }
        else
        {
            std::cout << "\nError! Try saving with another filename.";
        }
    }
}

using std::find;

// Indice de coincidencia
float IndexCoincidence(std::string Text) 
{
   float sum = 0.0;

    for (int i = 0; i < 26; i++) 
    {
        float num = count(Text.begin(), Text.end(), ALPHABET[i]); 
        num = num + count(Text.begin(), Text.end(), ALPHABETUP[i]); 
        sum += (num * ( num - 1)) ;
    }

    return sum/(Text.length()*(Text.length()-1));
}


int NGraphAnalysis(std::string Text) 
{
    int Choice = 0;
    float dif = 100.0;
    
    // Assume key length n, starting with 2
    for(int i = 1; i <= MAXKEYLENGTH; i++) //lenght
    {
        int count = 0;
        float sum = 0.0, mid = 0.0;

        //split ciphertext into n groups
        while(count < i)
        {
            std::string characters = "";

            for(int j = 0; j < Text.length() - count; j=j+i)
            {
                characters += Text[count+j];
            }
            
            if(characters.length() >= 2)
            {
                sum += IndexCoincidence(characters); 
            }
            count++;
        }
        
        //calculate the average index of coincidence
        mid = sum / (float) i;

        //test the closest IC to value 0.072723 (portugues)
        // IC to value 0.0667 (ingles)

        float ic_def = 0.072723;

        float sub = mid - ic_def;
        
        if(sub < 0)
        {
            sub = sub * -1;
        }

        if(sub < dif)
        {
            dif = sub;
            std::cout << sub << "\n";
            Choice = i;
        }
    }

    return Choice;
}

std::string KeyAnalysis(int Length, std::string Text)
{
    std::string KeyFound;

    for(int i = 0; i < Length; i++)//For each character that must be found
    {
        int CharOccurrencies[ALPHABETSIZE];
        for(int z = 0; z < ALPHABETSIZE; z++)
        {
            CharOccurrencies[z] = 0; //initializes vector
        }

        int TotalOccurrencies = 0;

        for(int k = i; k < Text.length(); k+=Length)//Checks characters present on the empty spaces
        {
            CharOccurrencies[(Text[k]-'A')]+=1;
            TotalOccurrencies++;
        }

        //Convert occurrency numbers to percentages
        float OccurrencyPercentage[ALPHABETSIZE];
        for(int z = 0; z < ALPHABETSIZE; z++)//Calcula
        {
            OccurrencyPercentage[z] = static_cast<float>(CharOccurrencies[z])/static_cast<float>(TotalOccurrencies);//Casts integers to float and gets percentage
        }

        char PossibleCharacter = ' ';
        float SmallerDistance = FLT_MAX;//places a high value so it can be substituted easily, as we're looking for smaller values
        //Finds most suitable character through distance comparison

        for(int p = 0; p < ALPHABETSIZE; p++)
        {
            float Distance = 0;
            for(int q = 0; q < ALPHABETSIZE; q++)
            {
                float Temp = LANGUAGEFREQ[q]- OccurrencyPercentage[(p+q)%ALPHABETSIZE];
                if(Temp < 0)
                {
                    Temp = Temp * (-1.0);//Turns distance into positive number
                }
                Distance+=Temp;
            }

            if(Distance < SmallerDistance)
            {
                SmallerDistance = Distance;//Updates the character with higher chance of being correct
                PossibleCharacter = p + 'a';
            }
        }
        KeyFound.push_back(PossibleCharacter);
    }
    return KeyFound;
}

std::string VigenereEncrypt(std::string Text, std::string Key)//OK
{
    std::string Cypher;
    int CypherIndex = 0;;
    //do encryption
    for(int i = 0; i < Text.length(); i++)
    {
        if(Text[i] >= 'a' && Text[i] <= 'z')
        {
            //Turn chars into numbers, operate and turn back into a character
            char Encryption = (((Text[i]-'a') + (Key[CypherIndex%Key.length()]-'a'))% ALPHABETSIZE)+'a';
            CypherIndex++;
            Cypher.push_back(Encryption);
        }
        else if (Text[i] >= 'A' && Text[i] <= 'Z')
        {
            //Turn chars into numbers, operate and turn back into a character
            char Encryption = (((Text[i]-'A') + (Key[CypherIndex%Key.length()]-'a'))% ALPHABETSIZE)+'a';
            CypherIndex++;
            Cypher.push_back(Encryption);
        }
        else
        {
            Cypher.push_back(Text[i]);
        }
    }
    return Cypher;
}

std::string VigenereDecrypt(std::string Text, std::string Key)//OK
{
    std::string Translation;
    int TranslationIndex = 0;;
    //do decryption
    for(int i = 0; i < Text.length(); i++)
    {
        if(Text[i] >= 'a' && Text[i] <= 'z')
        {
            //Turn chars into numbers, add 26 to prevent underflow, operate and turn back into a character
            char Decryption = (((Text[i]-'a'+ ALPHABETSIZE) - (Key[TranslationIndex%Key.length()]-'a'))% ALPHABETSIZE)+'a';
            TranslationIndex++;
            Translation.push_back(Decryption);
        }
        else if (Text[i] >= 'A' && Text[i] <= 'Z')
        {
            //Turn chars into numbers, add 26 to prevent underflow, operate and turn back into a character
            char Decryption = (((Text[i]-'A'+ ALPHABETSIZE) - (Key[TranslationIndex%Key.length()]-'a'))% ALPHABETSIZE)+'a';
            TranslationIndex++;
            Translation.push_back(Decryption);
        }
        else
        {
            Translation.push_back(Text[i]);
        }
    }
    return Translation;
}

std::string TextCleaner(std::string RawText)//OK
{
    std::string CleanText;
    for(int i = 0; i< RawText.length(); i++)
    {
        if(RawText[i] >= 'a' && RawText[i] <= 'z')
        {
            CleanText.push_back(RawText[i] + 'A' - 'a');//Creates a string only with alphabet characters
        }
        else if(RawText[i] >= 'A' && RawText[i] <= 'Z')
        {
            CleanText.push_back(RawText[i]);
        }
    }
    return CleanText;
}

std::string ReadFile(std::string FileName)//OK
{
    std::string Content;
    std::ifstream Source(FileName);//Open txt
    if (Source.is_open())
    {
        std::string Line;
        while (Source.good())
        {
            getline(Source, Line);//Read text line
            Content+=Line;//stores read content
            Content+=' ';//Adds spaces at the end
        }
    }
    Source.close();//Close txt
    return Content;
}

bool WriteToFile(std::string Text, std::string Filename)
{
    std::ofstream Destiny(Filename);
    Destiny << Text;
    Destiny.close();

    return true;
}
