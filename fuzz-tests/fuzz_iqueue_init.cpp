#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
  #include "lib_iso15765.h"
}

DEBUG_FINDING(spectacular_vulture)

// One-time initialization tasks
FUZZ_TEST_SETUP() {
  // No specific one-time setup required for this fuzz test
}

// Entry point for the fuzzing harness
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);

  // Initialize an instance of iso15765_t
  iso15765_t instance;
  memset(&instance, 0, sizeof(iso15765_t));

  // Set up the instance with fuzzed values
  instance.fr_id_type = static_cast<cbus_id_type>(fdp.ConsumeIntegralInRange<uint8_t>(0, 1));
  instance.addr_md = static_cast<addr_md>(fdp.ConsumeIntegralInRange<uint8_t>(0, 1));

  // Set up callback functions
  instance.clbs.send_frame = [](cbus_id_type, uint32_t, cbus_fr_format, uint8_t, uint8_t*) -> uint8_t { return 0; };
  instance.clbs.get_ms = []() -> uint32_t { return 0; };
  instance.clbs.indn = [](n_indn_t*) {};
  instance.clbs.ff_indn = [](n_ff_indn_t*) {};
  instance.clbs.cfm = [](n_cfm_t*) {};
  instance.clbs.cfg_cfm = [](n_chg_param_cfm_t*) {};
  instance.clbs.on_error = [](n_rslt) {};

  // Call iso15765_init with the initialized instance
  iso15765_init(&instance);

  // Create and enqueue a canbus_frame_t with fuzzed values
  canbus_frame_t frame;
  frame.id = fdp.ConsumeIntegral<uint32_t>();
  frame.dlc = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
  frame.fr_format = static_cast<cbus_fr_format>(fdp.ConsumeIntegralInRange<uint8_t>(0, 1));
  fdp.ConsumeData(frame.dt, sizeof(frame.dt));

  iso15765_enqueue(&instance, &frame);

  // Create and send a n_req_t with fuzzed values
  n_req_t req;
  req.fr_fmt = static_cast<cbus_fr_format>(fdp.ConsumeIntegralInRange<uint8_t>(0, 1));
  req.msg_sz = fdp.ConsumeIntegralInRange<uint16_t>(0, I15765_MSG_SIZE);
  fdp.ConsumeData(req.msg, req.msg_sz);
  req.n_ai.n_pr = fdp.ConsumeIntegral<uint8_t>();
  req.n_ai.n_ta = fdp.ConsumeIntegral<uint8_t>();
  req.n_ai.n_sa = fdp.ConsumeIntegral<uint8_t>();
  req.n_ai.n_tt = static_cast<ta_type>(fdp.ConsumeIntegral<uint8_t>());

  iso15765_send(&instance, &req);

  // Process the instance
  iso15765_process(&instance);
}
