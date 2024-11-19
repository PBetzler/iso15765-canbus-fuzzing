#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string.h>

extern "C" {
  #include "lib_iso15765.h"
}

FUZZ_TEST_SETUP() {
  // One-time initialization tasks if needed
}

DEBUG_FINDING(flying_anemone)

FUZZ_TEST(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Create an instance of iso15765_t and initialize it with fuzzed data
  iso15765_t instance;
  memset(&instance, 0, sizeof(iso15765_t));

  // Fuzz the instance's fields with correct types
  instance.fr_id_type = static_cast<cbus_id_type>(fdp.ConsumeIntegralInRange<uint8_t>(CBUS_ID_T_STANDARD, CBUS_ID_T_EXTENDED));
  instance.addr_md = static_cast<addr_md>(fdp.ConsumeIntegral<uint8_t>());
  instance.clbs.send_frame = nullptr;  // Set to null to trigger the check in iso15765_init
  instance.clbs.get_ms = nullptr;  // Set to null to trigger the check in iso15765_init

  // Initialize the instance
  iso15765_init(&instance);

  // Create a canbus_frame_t and initialize it with fuzzed data
  canbus_frame_t frame;
  memset(&frame, 0, sizeof(canbus_frame_t));
  frame.fr_format = static_cast<cbus_fr_format>(fdp.ConsumeIntegral<uint8_t>());
  frame.id = fdp.ConsumeIntegral<uint32_t>();
  frame.dlc = fdp.ConsumeIntegral<uint8_t>();
  fdp.ConsumeData(frame.dt, sizeof(frame.dt));

  // Enqueue the frame
  // iso15765_enqueue(&instance, &frame);

  // Create a n_req_t and initialize it with fuzzed data
  n_req_t req;
  memset(&req, 0, sizeof(n_req_t));
  req.fr_fmt = static_cast<cbus_fr_format>(fdp.ConsumeIntegral<uint8_t>());
  req.msg_sz = fdp.ConsumeIntegralInRange<uint16_t>(0, I15765_MSG_SIZE);
  fdp.ConsumeData(req.msg, req.msg_sz);
  req.n_ai.n_pr = fdp.ConsumeIntegral<uint8_t>();
  req.n_ai.n_ta = fdp.ConsumeIntegral<uint8_t>();
  req.n_ai.n_sa = fdp.ConsumeIntegral<uint8_t>();
  req.n_ai.n_tt = static_cast<ta_type>(fdp.ConsumeIntegral<uint8_t>());

  // Send the request
  iso15765_send(&instance, &req);

  for (int i = 0; i < fdp.ConsumeIntegralInRange(1,500); i++) {
    // Process the instance
    iso15765_process(&instance);
  }
  
}
