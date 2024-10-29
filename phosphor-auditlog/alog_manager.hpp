#pragma once

#include "alog_utils.hpp"

#include <libaudit.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/event.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Logging/AuditLog/server.hpp>

#include <string>

namespace phosphor::auditlog
{

using ALIface = sdbusplus::xyz::openbmc_project::Logging::server::AuditLog;
using ALObject = sdbusplus::server::object_t<ALIface>;

/** @class ALManager
 *  @brief Configuration for AuditLog server
 *  @details A concrete implementation of the
 *  xyz.openbmc_project.Logging.AuditLog API, in order to
 *  provide audit log support.
 */
class ALManager : public ALObject
{
  public:
    ALManager() = delete;
    ALManager(const ALManager&) = delete;
    ALManager& operator=(const ALManager&) = delete;
    ALManager(ALManager&&) = delete;
    ALManager& operator=(ALManager&&) = delete;
    ~ALManager() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    ALManager(sdbusplus::bus_t& bus, const std::string& path) :
        ALObject(bus, path.c_str()) {};

    /**
     * @brief Parses all audit log events into JSON format.
     * @details Entries are sorted oldest to newest.
     * @return unix_fd A read-only file descriptor to the parsed file.
     */
    sdbusplus::message::unix_fd getAuditLog() override;

    /**
     * @brief Parses subset of audit log events into JSON format.
     * @details Entries are sorted newest to oldest.
     * @param[in] maxCount - The maximum number of entries to return. Minimum
     *            value of 1.
     * @return unix_fd A read-only file descriptor to the parsed file.
     */
    sdbusplus::message::unix_fd getLatestEntries(uint32_t maxCount) override;

  private:
    /**
     * @brief Opens previously created file in read-only mode.
     * @param[in] parsedFile - Path to file to open
     * @return int A file descriptor to the opened file.
     */
    int openParseFD(const ALParseFile& parsedFile);

    /**
     * @brief The event source for closing the file descriptor after it
     *        has been returned from the getAuditLog or getLatestEntries
     *        D-Bus method.
     * @details This is shared for multiple methods. The Defer action is called
     * before the event loop processes another event so there should not be any
     * collisions between the multiple uses.
     */
    std::unique_ptr<sdeventplus::source::Defer> fdCloseEventSource;

    /**
     * @brief Closes the file descriptor passed in.
     * @details This is called from the event loop to close FDs returned from
     * getAuditLog() or getLatestEntries()
     * @param[in] fd - The file descriptor to close
     * @param[in] source - The event source object used
     */
    void closeFD(int fd, sdeventplus::source::EventBase& source);
};

} // namespace phosphor::auditlog
