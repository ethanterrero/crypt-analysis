#include <iostream> 
#include <fstream> 
#include <string>
#include <filesystem>

namespace fs = std::filesystem; 

typedef struct fileMetaData {
    std::string fileName; 
    std::uintmax_t fileSize; 
    bool isValid; 
} fileMetaData; 

class f_Handler {
public: 
    // Accessor to let main.cpp see the metadata since f_summary is private
    fileMetaData getSummary() { return f_summary; }

    std::uintmax_t getFileSize(); 
    void openFilePath(); 
    void updatePath(const std::string& newPath); // Pass by reference for speed
    void closeFile(); 
    bool isOpen(); 
    bool isReadable(); 

    f_Handler(const std::string& path) {
        updatePath(path); // calling this function upon construction of the object
    }

    ~f_Handler() {
        if (fileObject.is_open()) {
            fileObject.close();
        }
    }

private: 
    fileMetaData f_summary; 
    std::string path; 
    std::ifstream fileObject; 
    fs::path pathObject; 
}; 

std::uintmax_t f_Handler::getFileSize() {
    return this->f_summary.fileSize; 
}

void f_Handler::closeFile(){
    this->fileObject.close(); 
}

bool f_Handler::isOpen(){
    if (this->fileObject.is_open()){
        return true; 
    } else {
        return false; 
    }
}

bool f_Handler::isReadable() {

    if (!fs::is_regular_file(this->path)){
        return false;
    }
    // returnign the rwx permissions which is a 9 bit sequence
    // goes owner, group and other (each category gets 3 bits each for rwx)
    fs::file_status s = fs::status(this->path);
    fs::perms p = s.permissions();
    
    // Check if Read is enabled for Owner, Group, OR Others
    return (p & (fs::perms::owner_read | 
                 fs::perms::group_read | 
                 fs::perms::others_read)) != fs::perms::none;
}

void f_Handler::openFilePath() {
    // apparently openSSL will work with the raw binary of the file, not its characters
    // needed to add in this second argument std::ios::binary for for the conversion
    this->fileObject.open(this->f_summary.fileName, std::ios::binary); 

    if (this->fileObject.fail()){
        std::cout << "[ERROR] File Failed to Open" << std::endl; 
        this->f_summary.isValid = false; 
        return; 
    }
    // DONT CLOSE, leave file open 
}

void f_Handler::updatePath(const std::string& newPath) {
    // Update the internal string path
    this->path = newPath;

    // make sure its a path valid and it leads to a file, not a folder
    if (fs::exists(newPath) && fs::is_regular_file(newPath)) {
        fs::path fsPath(newPath); 
        this->f_summary.fileName = fsPath.filename().string();         
        this->f_summary.fileSize = fs::file_size(fsPath); 
        this->f_summary.isValid = true; 
        this->pathObject = fsPath; 
    } else {
        this->f_summary.isValid = false; 
        std::cout << "[ERROR] Invalid File Path: " << newPath << std::endl; 
    }
}