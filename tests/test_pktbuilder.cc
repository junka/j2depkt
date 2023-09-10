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

TEST(builder, EtherSrc) {
  string t = "ETHER(dst=aa:bb:cc:dd:ee:ff,src=11:22:33:44:55:66)/IP(proto=17)/UDP(dst=7787)/RAW:SAMPLE";
  uint8_t *d = (uint8_t *)depkt_build((char *)t.c_str());
  EXPECT_EQ(d[0], 0xaa);
  EXPECT_EQ(d[1], 0xbb);
  EXPECT_EQ(d[2], 0xcc);
  EXPECT_EQ(d[3], 0xdd);
  EXPECT_EQ(d[4], 0xee);
  EXPECT_EQ(d[5], 0xff);
  
  EXPECT_EQ(d[6], 0x11);
  EXPECT_EQ(d[7], 0x22);
  EXPECT_EQ(d[8], 0x33);
  EXPECT_EQ(d[9], 0x44);
  EXPECT_EQ(d[10], 0x55);
  EXPECT_EQ(d[11], 0x66);

  EXPECT_EQ(d[14], 0x45);
  EXPECT_EQ(d[23], 17);
}

TEST(builder, IPSrc) {
  string t = "ETHER()/IP(proto=17,src=192.168.0.1)/"
             "UDP(dst=7787)/RAW:SAMPLE";
  uint8_t *d = (uint8_t *)depkt_build((char *)t.c_str());
  
  EXPECT_EQ(d[14], 0x45);
  EXPECT_EQ(d[23], 17);
  EXPECT_EQ((uint32_t)d[29] << 24 | d[28] << 16 | d[27] << 8 | d[26], 0xc0a80001);
}
