#include "response_engine.h"
#include <signal.h>
#include <iostream>

void trigger_response(int pid) {
    std::cout << "Response Engine: Killing PID " << pid << std::endl;
    kill(pid, SIGKILL);
}
