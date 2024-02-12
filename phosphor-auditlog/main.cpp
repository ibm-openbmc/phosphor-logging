#include "config.h"

#include "config_main.h"

#include "alog_manager.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

// AUDITLOG_PATH
constexpr auto auditLogMgrRoot = "/xyz/openbmc_project/logging/auditlog";
// AUDITLOG_INTERFACE
constexpr auto auditLogBusName = "xyz.openbmc_project.Logging.AuditLog";

int main(int /*argc*/, char* /*argv*/[])
{
    auto bus = sdbusplus::bus::new_default();
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    sdbusplus::server::manager_t objManager{bus, auditLogMgrRoot};

    // Reserve the dbus service name
    bus.request_name(auditLogBusName);

    phosphor::auditlog::ALManager alMgr(bus, auditLogMgrRoot);

    // Handle dbus processing forever.
    event.loop();

    return 0;
}
