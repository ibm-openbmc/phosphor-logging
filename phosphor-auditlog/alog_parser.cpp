#include "alog_parser.hpp"

#include "alog_manager.hpp"

#include <auparse.h>
#include <libaudit.h>

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cstring>
#include <filesystem>
#include <format>
#include <list>
#include <map>
#include <string>
#include <string_view>

namespace phosphor::auditlog
{

bool ALParser::getNextEvent()
{
    bool haveEvent = false;
    int rc;

    rc = auparse_next_event(au);
    switch (rc)
    {
        case 1:
            /* Success, pointing to next event */
            haveEvent = true;
            break;
        case 0:
            /* No more events */
            haveEvent = false;
            break;
        case -1:
        default:
            /* Failure */
            lg2::error("Failed to parse next event");
            haveEvent = false;
            break;
    }

    return haveEvent;
}

void ALParser::parseEvent()
{
    unsigned int nRecords = auparse_get_num_records(au);

    // The event itself is a record. It may be the only one.
    parseRecord();

    /* Handle any additional records for this event */
    for (unsigned int iter = 1; iter < nRecords; iter++)
    {
        auto rc = auparse_next_record(au);

        switch (rc)
        {
            case 1:
            {
                /* Success finding record, parse it! */
                parseRecord();
            }
            break;
            case 0:
                /* No more records, something is confused! */
                lg2::error(
                    "Record count ({NRECS}) and records out of sync ({ITER})",
                    "NRECS", nRecords, "ITER", iter);
                throw sdbusplus::xyz::openbmc_project::Common::Error::
                    InternalFailure();

                break;
            case -1:
            default:
                /* Error */
                lg2::error("Failed on record: {ITER}", "ITER", iter);
                throw sdbusplus::xyz::openbmc_project::Common::Error::
                    InternalFailure();
                break;
        }
    }
}

void ALParser::fillAuditEntry(nlohmann::json& parsedEntry)
{
    parsedEntry["MessageId"] = "OpenBMC.0.5.AuditLogEntry";

    /* MessageArgs: msg */
    auto recMsg = auparse_get_record_text(au);
    auto messageArgs = nlohmann::json::array({recMsg});

    parsedEntry["MessageArgs"] = std::move(messageArgs);
}

/**
 * @brief Strips '"' from beginning and end of value field
 */
inline std::string_view getValue(std::string_view fieldText)
{
    if (fieldText.starts_with('\"'))
    {
        auto endQuote = fieldText.find('\"', 1);

        if (endQuote != std::string::npos)
        {
            return fieldText.substr(1, endQuote - 1);
        }
    }

    return fieldText;
}

bool ALParser::fillUsysEntry(nlohmann::json& parsedEntry)
{
    /* Map audit fields to JSON name
     * Audit records contain fields not returned for admin use. E.g. the pid of
     * the auditd daemon that recorded the entry is part of the record.
     */
    std::map<std::string, std::string>::const_iterator mapEntry;
    const std::map<std::string, std::string> msgArgMap(
        {{"type", "Type"},
         {"op", "Operation"},
         {"acct", "Account"},
         {"exe", "Executable"},
         {"hostname", "Hostname"},
         {"addr", "IPAddress"},
         {"terminal", "Terminal"},
         {"res", "Result"}});

    /* Walk the fields and insert mapped fields into parsedEntry */
    int fieldIdx = 0;
    size_t nFields = 0; // Used to confirm all expected fields found
    do
    {
        fieldIdx++;

        // Can return nullptr
        const char* fieldName = auparse_get_field_name(au);
        std::string_view fieldTxt = auparse_get_field_str(au);

        if ((fieldName == nullptr) || (fieldTxt.empty()))
        {
            lg2::debug("Unexpected field:{FIELDIDX}", "FIELDIDX", fieldIdx);
            continue;
        }

        /* Map the field to the JSON name, not all fields are mapped */
        mapEntry = msgArgMap.find(fieldName);
        if (mapEntry != msgArgMap.end())
        {
            if (parsedEntry[mapEntry->second] != nullptr)
            {
                /* Field is being repeated. This is a sign of corruption of the
                 * raw audit log entry. Warn about this and skip it.
                 */
                lg2::warning(
                    "Skipping entry with repeated field:{FIELDNAME} for ID:{ID}",
                    "FIELDNAME", fieldName, "ID", parsedEntry.value("ID", ""));
                auto recMsg = auparse_get_record_text(au);
                lg2::debug("{RECTEXT}", "RECTEXT", recMsg);
                return false;
            }

            /* Remove '"' from fieldTxt */
            parsedEntry[mapEntry->second] = getValue(fieldTxt);
            nFields++;
#ifdef AUDITLOG_FULL_DEBUG
            lg2::debug(
                "Field {NFIELD} : {FIELDNAME} = {FIELDSTR} argIdx = {ARGIDX}",
                "NFIELD", fieldIdx, "FIELDNAME", fieldName, "FIELDSTR",
                fieldTxt, "ARGIDX", mapEntry->second);
#endif // AUDITLOG_FULL_DEBUG
        }
    } while (auparse_next_field(au) == 1);

    /* Error handling, make sure all the fields we care about
     * exist. If any are missing set to null string.
     */
    if (nFields != msgArgMap.size())
    {
#ifdef AUDITLOG_FULL_DEBUG
        lg2::debug("Incorrect nFields = {NFIELDS}", "NFIELDS", nFields);
#endif // AUDITLOG_FULL_DEBUG

        // Set missing fields to empty string
        for (const auto& [key, name] : msgArgMap)
        {
            if (parsedEntry[name] == nullptr)
            {
#ifdef AUDITLOG_FULL_DEBUG
                lg2::debug("Missing {NAME} initialized", "NAME", name);
#endif // AUDITLOG_FULL_DEBUG
                parsedEntry[name] = "";
                nFields++;
            }
        }

#ifdef AUDITLOG_FULL_DEBUG
        lg2::debug("nFields = {NFIELDS}", "NFIELDS", nFields);
#endif // AUDITLOG_FULL_DEBUG
    }

    return true;
}

bool ALParser::formatMsgReg(nlohmann::json& parsedEntry)
{
    /* Fill common fields for any record type */
    auto fullTimestamp = auparse_get_timestamp(au);
    if (fullTimestamp == nullptr)
    {
        lg2::error("Failed to parse timestamp");
        throw sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure();
    }
    parsedEntry["EventTimestamp"] = fullTimestamp->sec;
    parsedEntry["ID"] = std::format("{}.{}:{}", fullTimestamp->sec,
                                    fullTimestamp->milli,
                                    fullTimestamp->serial);

    /* Fill varied args fields based on record type */
    int recType = auparse_get_type(au);

    switch (recType)
    {
        case AUDIT_USYS_CONFIG:
            if (!fillUsysEntry(parsedEntry))
            {
                return false;
            }
            break;

        default:
            /* Skip these entries */
            return false;
            break;
    }

#ifdef AUDITLOG_FULL_DEBUG
    lg2::debug("parsedEntry = {PARSEDENTRY}", "PARSEDENTRY",
               parsedEntry.dump());
#endif // AUDITLOG_FULL_DEBUG

    return true;
}

bool ALParser::formatGeneral(nlohmann::json& parsedEntry)
{
    auto fullTimestamp = auparse_get_timestamp(au);
    if (fullTimestamp == nullptr)
    {
        lg2::error("Failed to parse timestamp");
        throw sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure();
    }
    parsedEntry["EventTimestamp"] = fullTimestamp->sec;
    parsedEntry["ID"] = std::format("{}.{}:{}", fullTimestamp->sec,
                                    fullTimestamp->milli,
                                    fullTimestamp->serial);

    auto recMsg = auparse_get_record_text(au);
    parsedEntry["Event"] = recMsg;

#ifdef AUDITLOG_FULL_DEBUG
    lg2::debug("parsedEntry = {PARSEDENTRY}", "PARSEDENTRY",
               parsedEntry.dump());
#endif // AUDITLOG_FULL_DEBUG

    return true;
}

bool ALParser::formatRaw(nlohmann::json& parsedEntry)
{
    auto recMsg = auparse_get_record_text(au);
    parsedEntry["Event"] = recMsg;

#ifdef AUDITLOG_FULL_DEBUG
    lg2::debug("parsedEntry = {PARSEDENTRY}", "PARSEDENTRY",
               parsedEntry.dump());
#endif // AUDITLOG_FULL_DEBUG

    return true;
}

void ALParser::parseRecord()
{
    nlohmann::json parsedEntry;

    if (formatEntry(parsedEntry))
    {
        // Dump JSON object to parsedStream
        parsedStream << parsedEntry.dump() << '\n';
    }

    return;
}

bool ALParser::openParsedFile(const std::string& filePath)
{
    std::error_code ec;

    /* Expect the file has already been created */
    if (!std::filesystem::exists(filePath, ec))
    {
        lg2::error("File {FILE} doesn't already exist.", "FILE", filePath);
        return false;
    }

    // Create/Open file using truncate
    parsedStream.open(filePath, std::ios::out);
    if (parsedStream.fail())
    {
        lg2::error("Failed to open {FILE}", "FILE", filePath);
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }

    return true;
}

void ALParser::processEvents()
{
    // Loop over all the events
    while (getNextEvent())
    {
        parseEvent();
    }
}

void ALParser::doParse()
{
    lg2::debug("Parsing All");
    processEvents();
}

void ALParseLatest::parseRecord()
{
    nlohmann::json parsedEntry;

    if (formatEntry(parsedEntry))
    {
        // Keep list limited to maxLeftCount
        if (parsedEntries.size() >= maxLeftCount)
        {
            parsedEntries.pop_back();
        }

        parsedEntries.emplace_front(parsedEntry.dump());
    }

    return;
}

size_t ALParseLatest::writeParsedEntries()
{
    /* Add newest events to the file */
    for (const auto& iter : parsedEntries)
    {
        parsedStream << iter << '\n';
    }

    auto parsedCount = parsedEntries.size();
    parsedEntries.clear();

    lg2::debug("maxLeftCount: {MAXCOUNT} parsedCount: {PARSED}", "MAXCOUNT",
               maxLeftCount, "PARSED", parsedCount);

    return parsedCount;
}

void ALParseLatest::doParse()
{
    lg2::debug("Parsing maxCount: {MAXCOUNT}", "MAXCOUNT", maxCount);
    if (maxCount > 0)
    {
        processEvents();

        auto parsedCount = writeParsedEntries();

        // Process next file if needed to reach desired # entries
        while (parsedCount < maxLeftCount)
        {
            maxLeftCount -= parsedCount;

            if (!initNextLog())
            {
                // No more files to parse
                break;
            }

            processEvents();

            /* Add newest events to the file */
            parsedCount = writeParsedEntries();
        }
    }
}

bool ALParseLatest::initNextLog()
{
    if (au != nullptr)
    {
        lg2::debug("initNextLog: destroying existing au");
        auparse_destroy(au);
        au = nullptr;
    }

    /* Determine path of next log file to process.
     * Newest file has no extension and matches 0 index value.
     */
    std::string logFilePath = "/var/log/audit/audit.log";

    if (logFileIdx)
    {
        logFilePath = std::format("/var/log/audit/audit.log.{}",
                                  std::to_string(logFileIdx));
    }

    lg2::debug("initNextLog: Initialize for {FILE}", "FILE", logFilePath);
    au = auparse_init(AUSOURCE_FILE, logFilePath.c_str());

    if (au != nullptr)
    {
        logFileIdx++;
        return true;
    }

    // No more files to process
    return false;
}

} // namespace phosphor::auditlog
