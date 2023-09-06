#include <gtest/gtest.h>
#include <stdint.h>
#include <stdlib.h>

#include "depktbuilder.h"

using namespace std;

TEST(builder, EtherType) {
  string t = "ETHER(type=0x800)/IP(proto=17)/UDP(dst=7787)/RAW:SAMPLE";
  uint8_t *d = (uint8_t *)depkt_build((char *)t.c_str());
  EXPECT_EQ(d[13] << 8| d[12], 0x0800);
  EXPECT_EQ(d[14], 0x45);
  EXPECT_EQ(d[23], 17);
}
