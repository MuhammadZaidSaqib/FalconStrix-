#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

// The response engine reads response commands from a FIFO and kills targets.
// This makes FSM→LOCKED fully OS-engine driven (C++ performs termination).

void trigger_response(int pid);

// Thread entry: arg is a pointer to the child's shutdown flag.
void* start_response_engine(void* arg);

#endif
