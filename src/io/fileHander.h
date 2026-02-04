#include <iostream> 
#include <fstream> 
#include <string>
#include <filesystem>
#include <vector> 

namespace fs = std::filesystem; 

typedef struct fileMetaData {
    std::string fileName; 
    std::uintmax_t fileSize; 
    bool isValid; 
} fileMetaData; 

class f_Handler {
public: 
    // Accessor to let main.cpp see the metadata since f_summary is private
    /* GETTING FILE DATA HERE*/
    fileMetaData getSummary() const { return f_summary; }
    std::uintmax_t getFileSize() const; 
    void openFilePath(); 
    void updatePath(const std::string& newPath); // Pass by reference for speed
    void closeFile(); 
    bool isOpen() const; 
    bool isReadable() const; 

    /* READING FILE DATA/USING BUFFER */
    std::streamsize readChunk(unsigned char* buffer); // read in a block into our buffer 
    std::streamsize readNextChunk(); 
    
    // Accessor for OpenSSL to get the pointer to the data
    unsigned char* getBuffer() { return internalBuffer.data(); }

    static constexpr size_t CHUNK_SIZE = 4096; // static -> belongs to class itself, constexpr tells compiler the value wont change so it can be optimzed, the value itself is "sweet spot" for performance 

    /* CONSTRUCTORS HERE */
    f_Handler(const std::string& path) : internalBuffer(CHUNK_SIZE) {
        updatePath(path); // calling this function upon construction of the object
        // use list initializer to set internalBuffer to the CHUNK_SIZE 
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
    std::vector<unsigned char> internalBuffer; // our buffer for reading in chunks 
}; 

// --- Implementation ---

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