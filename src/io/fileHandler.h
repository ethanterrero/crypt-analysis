#pragma once
#include <iostream> 
#include <fstream> 
#include <string>
#include <filesystem>
#include <vector> 

namespace fs = std::filesystem; 

typedef struct fileMetaData {
    std::string fileName;
    std::uintmax_t fileSize = 0;
    bool isValid = false;
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
    f_Handler(const std::string& path);
    ~f_Handler();

private: 
    fileMetaData f_summary; 
    std::string path; 
    std::ifstream fileObject; 
    fs::path pathObject; 
    std::vector<unsigned char> internalBuffer; // our buffer for reading in chunks 
}; 