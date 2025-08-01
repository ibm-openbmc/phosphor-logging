#include <auparse.h>
#include <libaudit.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>

static void handleEvent(auparse_state_t* /*au*/,
                        auparse_cb_event_t /*eventType*/, void* /*data*/)
{
    lg2::info("Handling audit event");
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
