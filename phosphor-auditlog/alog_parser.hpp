#pragma once

#include "alog_utils.hpp"

#include <auparse.h>
#include <libaudit.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Logging/AuditLog/server.hpp>

#include <fstream>
#include <list>
#include <string>

namespace phosphor::auditlog
{

/** @class ALParser
 *  @brief Parsing audit log using auparse library services
 *  @details Provides abstraction to auparse library services
 */
class ALParser
{
  public:
    ALParser(const ALParser&) = delete;
    ALParser& operator=(const ALParser&) = delete;
    ALParser(ALParser&&) = delete;
    ALParser& operator=(ALParser&&) = delete;

    /** @brief Constructor to initialize parsing of audit log files
     *  @details Prepares parsedFile for writing of audit events
     *  @param[in] parsedFile Initialized file for holding parsed log events
     */
    explicit ALParser(ALParseFile& parsedFile)
    {
        if (!openParsedFile(parsedFile.getPath()))
        {
            throw sdbusplus::xyz::openbmc_project::Common::File::Error::Write();
        }
    }

    ~ALParser()
    {
        auparse_destroy(au);
    }

    /**
     * @brief Process audit events from initialized au source
     */
    virtual void doParse();

    /**
     * @brief Process audit events from initialized au source
     */
    void processEvents();

  protected:
    /**
     * @brief Format audit entries into raw JSON
     * @param[in,out] parsedEntry Filled in with parsed audit entry.
     * @return bool True if parsing succeeded, false otherwise.
     */
    virtual bool formatEntry(nlohmann::json& parsedEntry)
    {
        return formatRaw(parsedEntry);
    };

    /**
     * @brief Formats next record into JSON format using message registry
     * @param[in,out] parsedEntry Filled in with parsed audit entry.
     * @return bool True if parsing succeeded, false otherwise.
     */
    bool formatMsgReg(nlohmann::json& parsedEntry);

    /**
     * @brief Formats next record into JSON general format
     * @param[in,out] parsedEntry Filled in with parsed audit entry.
     * @return bool True if parsing succeeded, false otherwise.
     */
    bool formatGeneral(nlohmann::json& parsedEntry);

    /**
     * @brief Formats next record into JSON raw format
     * @param[in,out] parsedEntry Filled in with parsed audit entry.
     * @return bool True if parsing succeeded, false otherwise.
     */
    bool formatRaw(nlohmann::json& parsedEntry);

    auparse_state_t* au = nullptr;
    std::ofstream parsedStream;

  private:
    /**
     * @brief Moves parser to point to next event
     *
     * @return false when no more events exist, or on error
     */
    bool getNextEvent();

    /**
     * @brief Parses next event and each of its records into JSON format
     * @details Writes the audit log events to parsedStream.
     */
    void parseEvent();

    /**
     * @brief Parses and writes next record into JSON format
     */
    virtual void parseRecord();

    /**
     * @brief Parses general audit entry into JSON format
     * @details Used with audit entries without specific handling. Text of audit
     * log message is written as-is.
     */
    void fillAuditEntry(nlohmann::json& parsedEntry);

    /**
     * @brief Parses AUDIT_USYS_CONFIG audit entry into JSON format
     * @details Expected fields from audit log entry are split into MessageArgs
     * @return bool True entry was filled in, false otherwise.
     */
    bool fillUsysEntry(nlohmann::json& parsedEntry);

    /**
     * @brief Opens and truncates specified file
     * @param[in] filePath Path of file to open. File should exist.
     * @return bool True if stream was established to file, false otherwise.
     */
    bool openParsedFile(const std::string& filePath);
};

/** @class ALParseLatest
 *  @brief Parsing audit log using auparse library services
 *  @details Provides means to parse only latest entries
 */
class ALParseLatest : public ALParser
{
  public:
    ALParseLatest(const ALParseLatest&) = delete;
    ALParseLatest& operator=(const ALParseLatest&) = delete;
    ALParseLatest(ALParseLatest&&) = delete;
    ALParseLatest& operator=(ALParseLatest&&) = delete;

    /** @brief Constructor to initialize parsing of audit log files
     *  @param[in] maxEvents Maximum number of events to return.
     *  @param[in] parsedFile Initialized file for holding parsed log events
     */
    ALParseLatest(uint32_t maxEvents, ALParseFile& parsedFile) :
        ALParser(parsedFile)
    {
        lg2::debug("Constructing ALParseLatest: {MAXCOUNT}", "MAXCOUNT",
                   maxEvents);

        initNextLog();
        maxCount = maxEvents;
        maxLeftCount = maxEvents;

        if (au == nullptr)
        {
            lg2::error("Failed to init auparse");
            throw sdbusplus::xyz::openbmc_project::Common::Error::
                InternalFailure();
        }
    }

    /**
     * @brief Process audit events from initialized au source
     * @details Limits number of entries written to maxCount.
     */
    void doParse() override;

  protected:
    /**
     * @brief Format audit entries into JSON using message registry form
     * @param[in,out] parsedEntry Filled in with parsed audit entry.
     * @return bool True if parsing succeeded, false otherwise.
     */
    bool formatEntry(nlohmann::json& parsedEntry) override
    {
        return formatMsgReg(parsedEntry);
    };

  private:
    size_t maxCount = 0;
    size_t maxLeftCount = 0;
    unsigned int logFileIdx = 0;
    std::list<std::string> parsedEntries;

    /**
     * @brief Parses next record into JSON format and adds to list
     */
    void parseRecord() override;

    /**
     * @brief Initializes parser to next audit log available
     * @details Initializes with the latest audit log first. Each subsequent
     *         call will initialize with the next oldest audit log file until
     *         a file cannot be found.
     * @return bool True if initialization succeeded, false otherwise.
     */
    bool initNextLog();

    /**
     * @brief Writes parsedEntries to parsedStream
     * @details parsedEntries is cleared after entries are written.
     * @return size_t Number of entries written.
     */
    size_t writeParsedEntries();
};

/** @class ALParseAll
 *  @brief Parsing audit log using auparse library services
 *  @details Provides means to parse all entries
 */
class ALParseAll : public ALParser
{
  public:
    ALParseAll(const ALParseAll&) = delete;
    ALParseAll& operator=(const ALParseAll&) = delete;
    ALParseAll(ALParseAll&&) = delete;
    ALParseAll& operator=(ALParseAll&&) = delete;

    /** @brief Constructor to initialize parsing of audit log files
     *  @details Initializes au to parse all audit logs.
     *  @param[in] parsedFile Initialized file for holding parsed log events
     */
    explicit ALParseAll(ALParseFile& parsedFile) : ALParser(parsedFile)
    {
        lg2::debug("Constructing ALParseAll");
        au = auparse_init(AUSOURCE_LOGS, nullptr);
        if (au == nullptr)
        {
            lg2::error("Failed to init auparse");
            throw sdbusplus::xyz::openbmc_project::Common::Error::
                InternalFailure();
        }
    }

  protected:
    /**
     * @brief Format audit entries into general JSON
     * @param[in,out] parsedEntry Filled in with parsed audit entry.
     * @return bool True if parsing succeeded, false otherwise.
     */
    bool formatEntry(nlohmann::json& parsedEntry) override
    {
        return formatGeneral(parsedEntry);
    };
};

} // namespace phosphor::auditlog
