#pragma once

#include <libaudit.h>

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace phosphor::auditlog
{

/** @class ALParseFile
 *  @brief Creation of temporary file for parsed audit log
 */
class ALParseFile
{
  public:
    ALParseFile(const ALParseFile&) = delete;
    ALParseFile& operator=(const ALParseFile&) = delete;
    ALParseFile(ALParseFile&&) = delete;
    ALParseFile& operator=(ALParseFile&&) = delete;

    ~ALParseFile()
    {
        if (!pathName.empty() && !keepFile)
        {
            lg2::debug("Removing {FILE}", "FILE", pathName);
            std::filesystem::remove(pathName);
        }
    }

    /** @brief Create empty temporary file
     */
    ALParseFile()
    {
        std::string tempFile = std::filesystem::temp_directory_path() /
                               "auditLogJson-XXXXXX";

        lg2::debug("Constructing ALParseFile template={NAME}", "NAME",
                   tempFile);

        int fd = mkstemp(tempFile.data());
        if (fd == -1)
        {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }

        // Store path to temporary file
        pathName = tempFile;

        // Close file descriptor
        if (close(fd) == -1)
        {
            // Delete temporary file.  The destructor won't be called because
            // the exception below causes this constructor to exit without
            // completing.
            std::filesystem::remove(pathName);
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }
    }

    /** @brief Create parsed file that is not removed on destruction
     *  @details Used for debug only
     *  @param[in] filePath Path to file to be created. File will be truncated
     *             if it exists.
     */
    explicit ALParseFile(const std::string& filePath)
    {
        std::ofstream parsedStream;
        std::error_code ec;

        // Create/Open file using trunc
        parsedStream.open(filePath, std::ios::trunc);
        if (parsedStream.fail())
        {
            lg2::error("Failed to open {FILE}", "FILE", filePath);
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
        }

        // Set permissions on file created to match audit.log, 600
        std::filesystem::perms permission = std::filesystem::perms::owner_read |
                                            std::filesystem::perms::owner_write;
        std::filesystem::permissions(filePath, permission);

        pathName = filePath;
        keepFile = true;
    }

    /**
     * @brief Return path of file
     */
    const std::string& getPath() const
    {
        return pathName;
    }

  private:
    std::string pathName;
    bool keepFile = false; // Don't remove file on destruction
};

} // namespace phosphor::auditlog
