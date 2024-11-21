#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

extern "C" {
  #include "lib_iso15765.h"
}
static FuzzedDataProvider *gFDP;

void SetFDP(FuzzedDataProvider *fuzzed_data_provider) {
  gFDP = fuzzed_data_provider;
}

FuzzedDataProvider *GetFDP() { return gFDP; }

static iso15765_t sender_instance;
static iso15765_t reciever_instance;
static uint32_t last_ms_value;

FUZZ_TEST_SETUP() {
  // One-time initialization tasks if needed
  last_ms_value = 0;
}

static uint8_t sender_send_frame(cbus_id_type id_type, uint32_t id, cbus_fr_format fr_fmt, uint8_t dlc, uint8_t* dt)
{
  canbus_frame_t frame = { .id = id, .dlc = dlc, .id_type = id_type, .fr_format= (uint16_t) fr_fmt };
  memmove(frame.dt, dt, dlc);
  iso15765_enqueue(&reciever_instance, &frame);
  return 0;
}

static uint8_t receiver_send_frame(cbus_id_type id_type, uint32_t id, cbus_fr_format fr_fmt, uint8_t dlc, uint8_t* dt)
{
  canbus_frame_t frame = { .id = id, .dlc = dlc, .id_type = id_type, .fr_format= (uint16_t)fr_fmt };
  memmove(frame.dt, dt, dlc);
  iso15765_enqueue(&sender_instance, &frame);
  return 0;
}

static uint32_t getms()
{

  // TODO check if this implementation is really better then just getting the data from the FDP
  
  uint32_t new_value = GetFDP()->ConsumeIntegral<uint32_t>();

  if (new_value > last_ms_value) {

    last_ms_value = new_value;
    return new_value;
  } else {
    return last_ms_value;
  }
  // struct timeval tv;
  // gettimeofday(&tv, NULL);
  // return (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

static void on_error(n_rslt err_type) {
    //printf("ERROR OCCURRED!: %04x\n", err_type);
}

static void indn1(n_indn_t* info) {
}

//  Set up the target input to debug.
DEBUG_FINDING(focused_fly)

FUZZ_TEST(const uint8_t *data, size_t size) {
  std::cerr << "Starting Fuzz Test " <<std::endl;
  last_ms_value = 0;
  FuzzedDataProvider fdp(data, size);
  SetFDP(&fdp);

  // Create a sender instance of iso15765_t and initialize it with fuzzed data
 
  memset(&sender_instance, 0, sizeof(iso15765_t));

  // Fuzz the instance's fields with correct types
  sender_instance.fr_id_type = fdp.PickValueInArray({CBUS_ID_T_STANDARD,	CBUS_ID_T_EXTENDED});
  sender_instance.addr_md = fdp.PickValueInArray({N_ADM_UNKN, N_ADM_NORMAL,	N_ADM_FIXED,	N_ADM_MIXED11,	N_ADM_EXTENDED,	N_ADM_MIXED29});
  sender_instance.clbs.send_frame = sender_send_frame;
  sender_instance.clbs.get_ms = getms;
  sender_instance.clbs.indn = indn1;
  sender_instance.clbs.on_error = on_error;

  // Initialize the sender instance
  iso15765_init(&sender_instance);





  // Create a receiver instance of iso15765_t and initialize it with fuzzed data

  memset(&reciever_instance, 0, sizeof(iso15765_t));

  // Fuzz the instance's fields with correct types
  reciever_instance.fr_id_type = fdp.PickValueInArray({CBUS_ID_T_STANDARD,	CBUS_ID_T_EXTENDED});
  reciever_instance.addr_md = fdp.PickValueInArray({N_ADM_UNKN, N_ADM_NORMAL,	N_ADM_FIXED,	N_ADM_MIXED11,	N_ADM_EXTENDED,	N_ADM_MIXED29});
  reciever_instance.clbs.send_frame = receiver_send_frame;
  reciever_instance.clbs.get_ms = getms;
  reciever_instance.clbs.indn = indn1;
  reciever_instance.clbs.on_error = on_error;

  // Initialize the receiver instance
  iso15765_init(&reciever_instance);

  int repetitions = fdp.ConsumeIntegralInRange(1,500);
  for (int i = 0; i < repetitions; i++) {
    std::cerr << "In repetition: " << i <<std::endl;
    switch (fdp.ConsumeIntegralInRange(0,3)) {
      case 0: {
        //send
        // Create a n_req_t and initialize it with fuzzed data
        n_req_t req;
        memset(&req, 0, sizeof(n_req_t));
        req.fr_fmt = static_cast<cbus_fr_format>(fdp.PickValueInArray({CBUS_FR_FRM_STD,	CBUS_FR_FRM_FD}));
        req.msg_sz = fdp.ConsumeIntegralInRange<uint16_t>(0, I15765_MSG_SIZE);
        fdp.ConsumeData(req.msg, req.msg_sz);
        req.n_ai.n_pr = fdp.ConsumeIntegral<uint8_t>();
        req.n_ai.n_ta = fdp.ConsumeIntegral<uint8_t>();
        req.n_ai.n_sa = fdp.ConsumeIntegral<uint8_t>();
        req.n_ai.n_tt = static_cast<ta_type>(fdp.PickValueInArray({N_TA_T_PHY, N_TA_T_FUNC}));

        // Send the request
        iso15765_send(&sender_instance, &req);
        break;
      }
      default: {
        // Process the instance
        iso15765_process(&sender_instance);
        iso15765_process(&reciever_instance);
        break;
      } 
    }
  }  
}
