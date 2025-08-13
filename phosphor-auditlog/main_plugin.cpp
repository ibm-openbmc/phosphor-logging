#include <auparse.h>
#include <libaudit.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/server.hpp>
#include <xyz/openbmc_project/Logging/Create/server.hpp>

static void handleEvent(auparse_state_t* au, auparse_cb_event_t eventType,
                        void* /*data*/)
{
    if (eventType != AUPARSE_CB_EVENT_READY)
    {
        return;
    }

    auparse_first_record(au);

    do
    {
        auto type = auparse_get_type(au);

        // Handle events of type INTEGRITY
        if ((type >= AUDIT_INTEGRITY_FIRST_MSG) &&
            (type <= AUDIT_INTEGRITY_LAST_MSG))
        {
            // Create informational log
            using Create =
                sdbusplus::server::xyz::openbmc_project::logging::Create;
            constexpr auto logSeverity =
                "xyz.openbmc_project.Logging.Entry.Level.Informational";
            constexpr auto logMessage =
                "xyz.openbmc_project.Software.Version.Info.IntegrityEvent";
            try
            {
                auto bus = sdbusplus::bus::new_default();
                auto method = bus.new_method_call(Create::default_service,
                                                  Create::instance_path,
                                                  Create::interface, "Create");
                std::map<std::string, std::string> additionalData;
                additionalData["RECORD"] = auparse_get_record_text(au);
                method.append(logMessage, logSeverity, additionalData);
                bus.call_noreply(method);
            }
            catch (const sdbusplus::exception_t& e)
            {
                lg2::error("Error creating log: {ERROR}", "ERROR", e);
            }
        }
    } while (auparse_next_record(au) > 0);
}

int main(int /*argc*/, char* /*argv*/[])
{
    char buf[MAX_AUDIT_MESSAGE_LENGTH];

    auparse_state_t* au = NULL;
    au = auparse_init(AUSOURCE_FEED, 0);
    if (au == nullptr)
    {
        lg2::error("Failed to init auparse feed");
        return 1;
    }

    auparse_add_callback(au, handleEvent, NULL, NULL);

    do
    {
        auto r = read(STDIN_FILENO, buf, sizeof(buf));
        if (r == 0)
        {
            break;
        }
        else if (r < 0)
        {
            lg2::error("Error reading from stdin: errno = {ERRNO}", "ERRNO",
                       errno);
            break;
        }

        // Send data to parser
        auparse_feed(au, buf, r);

        // Flush events from queue
        auparse_flush_feed(au);

    } while (1);

    auparse_flush_feed(au);
    auparse_destroy(au);

    return 0;
}
