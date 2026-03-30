#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

// The response engine will be largely handled by Python backend,
// but the C++ engine can still trigger manual kills if needed directly.
void trigger_response(int pid);

#endif
