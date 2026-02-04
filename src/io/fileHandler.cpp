
#include "fileHandler.h"
#include <iostream>

f_Handler::f_Handler(const std::string& path) : internalBuffer(CHUNK_SIZE) {
    updatePath(path);
}

f_Handler::~f_Handler() {
    closeFile();
}

std::uintmax_t f_Handler::getFileSize() const {
    return this->f_summary.fileSize; 
}

void f_Handler::closeFile(){
    this->fileObject.close(); 
}

bool f_Handler::isOpen() const {
    return this->fileObject.is_open();
}

bool f_Handler::isReadable() const {
    if (!fs::exists(this->path) || !fs::is_regular_file(this->path)){
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
    // FIX: Using full 'path' instead of just 'fileName' to handle different directories
    this->fileObject.open(this->path, std::ios::binary); 

    if (this->fileObject.fail()){
        std::cerr << "[ERROR] File Failed to Open: " << this->path << std::endl; 
        this->f_summary.isValid = false; 
        return; 
    }
    // DONT CLOSE, leave file open 
}

void f_Handler::updatePath(const std::string& newPath) {
    // Safety: Close the current file before changing paths
    if (this->isOpen()) {
        this->closeFile();
    }

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
        std::cerr << "[ERROR] Invalid File Path: " << newPath << std::endl; 
    }
}

// std::streamsize because files can be bigger than what an int or a long can account for 
std::streamsize f_Handler::readChunk(unsigned char* buffer) {
    if (!fileObject.is_open()){
        return 0;
    }
    fileObject.read(reinterpret_cast<char*>(buffer), CHUNK_SIZE); // same as (char*)buffer
    return fileObject.gcount();
}

std::streamsize f_Handler::readNextChunk() {
    if (!fileObject.is_open()) return 0;
    
    fileObject.read(reinterpret_cast<char*>(internalBuffer.data()), CHUNK_SIZE);
    return fileObject.gcount();
}