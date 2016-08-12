/************
 *
 * $Id$
 *
 * Filename:  spicommon.c
 *
 * Purpose:   Common files for spi driver package
 *            
 *
 * Copyright: (c) 2009 Sierra Wireless, Inc.
 *            All rights reserved
 *
 ************/

/* Include files */
#include <platform/spiudefs.h>
#include <reg.h>
#include "qtimer.h"
#include "gpio.h"
#include <platform/clock.h>

/* Local constants and enumerated types */
/* QUP - SPI register offset */
#define QUP_CONFIG                     (0x0000) /* N & NO_INPUT/NO_OUPUT bits */
#define QUP_STATE                      (0x0004)
#define QUP_IO_MODES                   (0x0008)
#define QUP_SW_RESET                   (0x000C)
#define QUP_OPERATIONAL                (0x0018)
#define QUP_ERROR_FLAGS                (0x001C)
#define QUP_ERROR_FLAGS_EN             (0x0020)
#define QUP_OPERATIONAL_MASK           (0x0028)
#define QUP_MX_OUTPUT_COUNT            (0x0100)
#define QUP_MX_OUTPUT_CNT_CURRENT      (0x0104)
#define QUP_OUTPUT_FIFO_WORD_CNT       (0x010C)
#define QUP_OUTPUT_FIFO                (0x0110)
#define QUP_MX_WRITE_COUNT             (0x0150)
#define QUP_MX_WRITE_CNT_CURRENT       (0x0154)
#define QUP_MX_INPUT_COUNT             (0x0200)
#define QUP_MX_INPUT_CNT_CURRENT       (0x0204)
#define QUP_MX_READ_COUNT              (0x0208)
#define QUP_MX_READ_CNT_CURRENT        (0x020C)
#define QUP_INPUT_FIFO_WORD_CNT        (0x0214)
#define QUP_INPUT_FIFO                 (0x0218)
#define SPI_CONFIG                     (0x0300)
#define SPI_IO_CONTROL                 (0x0304)
#define SPI_ERROR_FLAGS                (0x0308)
#define SPI_DEASSERT_WAIT              (0x0310)


/* QUP_CONFIG fields */
#define SPI_CFG_N                     0x0000001F
#define SPI_NO_INPUT                  0x00000080
#define SPI_NO_OUTPUT                 0x00000040
#define SPI_MINI_CORE                 0x00000100
#define SPI_EN_EXT_OUT_FLAG           0x00010000

/* SPI_CONFIG fields */
#define SPI_CFG_LOOPBACK              0x00000100
#define SPI_CFG_INPUT_FIRST           0x00000200
#define SPI_CFG_HS_MODE               0x00000400

/* SPI_IO_CONTROL fields */
#define SPI_IO_C_FORCE_CS             0x00000800
#define SPI_IO_C_CLK_IDLE_HIGH        0x00000400
#define SPI_IO_C_MX_CS_MODE           0x00000100
#define SPI_IO_C_CS_N_POLARITY        0x000000F0
#define SPI_IO_C_CS_N_POLARITY_0      0x00000010
#define SPI_IO_C_CS_SELECT            0x0000000C
#define SPI_IO_C_TRISTATE_CS          0x00000002
#define SPI_IO_C_NO_TRI_STATE         0x00000001

/* SPI_IO_MODES fields */
#define SPI_IO_M_OUTPUT_BIT_SHIFT_EN   (0x00010000)
#define SPI_IO_M_PACK_EN              (0x00008000)
#define SPI_IO_M_UNPACK_EN            (0x00004000)
#define SPI_IO_M_INPUT_MODE           (0x00003000)
#define SPI_IO_M_OUTPUT_MODE          (0x00000C00)
#define SPI_IO_M_INPUT_FIFO_SIZE      (0x00000380)
#define SPI_IO_M_INPUT_BLOCK_SIZE     (0x00000060)
#define SPI_IO_M_OUTPUT_FIFO_SIZE     (0x0000001C)
#define SPI_IO_M_OUTPUT_BLOCK_SIZE    (0x00000003)

/* SPI_OPERATIONAL fields */
#define SPI_OP_MAX_INPUT_DONE_FLAG    0x00000800
#define SPI_OP_MAX_OUTPUT_DONE_FLAG   0x00000400
#define SPI_OP_INPUT_SERVICE_FLAG     0x00000200
#define SPI_OP_OUTPUT_SERVICE_FLAG    0x00000100
#define SPI_OP_INPUT_FIFO_FULL        0x00000080
#define SPI_OP_OUTPUT_FIFO_FULL       0x00000040
#define SPI_OP_IP_FIFO_NOT_EMPTY      0x00000020
#define SPI_OP_OP_FIFO_NOT_EMPTY      0x00000010
#define SPI_OP_STATE_VALID            0x00000004
#define SPI_OP_STATE                  0x00000003

#define SPI_OP_STATE_CLEAR_BITS       0x2

#define SPI_CLK_SRC_DIV_BYPASS      0x00
#define SPI_CLK_SRC_DIV_1_0         0x01
#define SPI_CLK_SRC_DIV_1_5         0x02
#define SPI_CLK_SRC_DIV_2_0         0x03
#define SPI_CLK_SRC_DIV_2_5         0x04
#define SPI_CLK_SRC_DIV_3_0         0x05
#define SPI_CLK_SRC_DIV_3_5         0x06
#define SPI_CLK_SRC_DIV_4_0         0x07
#define SPI_CLK_SRC_DIV_4_5         0x08
#define SPI_CLK_SRC_DIV_5_0         0x09
#define SPI_CLK_SRC_DIV_5_5         0x0A
#define SPI_CLK_SRC_DIV_6_0         0x0B
#define SPI_CLK_SRC_DIV_6_5         0x0C
#define SPI_CLK_SRC_DIV_7_0         0x0D
#define SPI_CLK_SRC_DIV_7_5         0x0E
#define SPI_CLK_SRC_DIV_8_0         0x0F
#define SPI_CLK_SRC_DIV_8_5         0x10
#define SPI_CLK_SRC_DIV_9_0         0x11
#define SPI_CLK_SRC_DIV_9_5         0x12
#define SPI_CLK_SRC_DIV_10_0        0x13
#define SPI_CLK_SRC_DIV_10_5        0x14
#define SPI_CLK_SRC_DIV_11_0        0x15
#define SPI_CLK_SRC_DIV_11_5        0x16
#define SPI_CLK_SRC_DIV_12_0        0x17
#define SPI_CLK_SRC_DIV_12_5        0x18
#define SPI_CLK_SRC_DIV_13_0        0x19
#define SPI_CLK_SRC_DIV_13_5        0x1A
#define SPI_CLK_SRC_DIV_14_0        0x1B
#define SPI_CLK_SRC_DIV_14_5        0x1C
#define SPI_CLK_SRC_DIV_15_0        0x1D
#define SPI_CLK_SRC_DIV_15_5        0x1E
#define SPI_CLK_SRC_DIV_16_0        0x1F

#define SPI_GPIOS_COUNTS            4
#define SPI_WORD_TO_BYTES           4
#define SPI_BITS_PER_BYTE           8

enum msm_spi_state {
  SPI_OP_STATE_RESET = 0x00000000,
  SPI_OP_STATE_RUN   = 0x00000001,
  SPI_OP_STATE_PAUSE = 0x00000003,
};

/* SPI driver globe configuration begin:
  * Developer should modify these item to adapt SPI register and clock of MDM9x40 */

/* #define SPI_USE_BLSP_QUP2 */

#ifdef SPI_USE_BLSP_QUP2
/* We use QUP2 config, real index is 3 in QC's HW document*/

/* Range of BLSP_QUP_QUP_CONFIG: 
  * BLSP_QUP0_QUP_CONFIG,
  * BLSP_QUP1_QUP_CONFIG,
  * BLSP_QUP2_QUP_CONFIG,
  * BLSP_QUP3_QUP_CONFIG */
unsigned int qup_register = 0x78B7000;  /* Now we use BLSP_QUP2_QUP_CONFIG: 0x78B7000, real index 3 */

/* GPIOs configuration for SPI */
/* Real index for BLSP_QUP2_QUP_CONFIG is index 3 */
#define GPIO_BLSP_QUP_GPIO_CNF_ID GPIO_BLSP_QUP2_GPIO_CNF_ID

#define SPI_CLOCK_ID 1
#else
/* We use QUP3 config, real index is 4 in QC's HW document */

/* Range of BLSP_QUP_QUP_CONFIG: 
  * BLSP_QUP0_QUP_CONFIG,
  * BLSP_QUP1_QUP_CONFIG,
  * BLSP_QUP2_QUP_CONFIG,
  * BLSP_QUP3_QUP_CONFIG */
unsigned int qup_register = 0x78B8000;  /* Now we use BLSP_QUP3_QUP_CONFIG: 0x78B8000, real index 4 */

/* GPIOs configuration for SPI */
/* Real index for BLSP_QUP3_QUP_CONFIG is index 4 */
#define GPIO_BLSP_QUP_GPIO_CNF_ID GPIO_BLSP_QUP3_GPIO_CNF_ID

#define SPI_CLOCK_ID 2
#endif

#define QUP_REGISTER_BASE qup_register

/* Clock rate supported:
  * 960000;
  * 4800000;
  * 9600000; 
  * 19200000
*/
#define SPI_CLOCK_RATE 9600000

/* SPI_BYTES_PER_WORD should be 1 ~ 4 */
#define SPI_BYTES_PER_WORD          4

/* Refer to Kernel, set SPI_DEASSERT_WAIT to 42 ticks */
#define SPI_DEASSERT_WAIT_TICKS     0x14

#define SPI_MX_CHECK_VALID_COUNT    100

#define SPI_COMMON_TIME_INTERVAL    1   /*ns*/

/* SPI driver globe configuration end */


/* Local structures */


/* Functions */
#define inpdw(a) readl(a)
#define outpdw(a, v) writel(v, a)


/************
 *
 * Name:      spiWaitTicks
 *
 * Purpose:   This function wait some interval and kick watchdog
 *
 * Params:    
 *
 * Return:    None
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
void spiWaitTicks()
{
  udelay(SPI_COMMON_TIME_INTERVAL);
}

/************
 *
 * Name:      msm_spi_is_valid_state
 *
 * Purpose:   This function check if SPI STATE register valid
 *
 * Params:    
 *
 * Return:    TRUE when valid, FALSE when invalid
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
boolean msm_spi_is_valid_state()
{
  if (inpdw(QUP_REGISTER_BASE + QUP_STATE) & SPI_OP_STATE_VALID)
  {
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

/************
 *
 * Name:      spi_wait_valid
 *
 * Purpose:   This function wait SPI STATE register till valid
 *
 * Params:    
 *
 * Return:    TRUE when success, FALSE when fail
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
boolean spi_wait_valid()
{
  int checkount = 0;

  while (!(inpdw(QUP_REGISTER_BASE + QUP_STATE) & SPI_OP_STATE_VALID))
  {
    spiWaitTicks();
    if (checkount++ >= SPI_MX_CHECK_VALID_COUNT)
    {
      /* Wait too long time, return FALSE to caller */
      return FALSE;
    }
  }

  return TRUE;
}

/************
 *
 * Name:      spi_set_states
 *
 * Purpose:   This function set State to SPI STATE register
 *
 * Params:    state - The state want to set by app
 *
 * Return:    TRUE when success, FALSE when fail
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
boolean spi_set_states(unsigned int state)
{
  unsigned int cur_state;
  
  if (spi_wait_valid() == FALSE)
  {
    return FALSE;
  }
  else
  {
    cur_state = inpdw(QUP_REGISTER_BASE + QUP_STATE);
    if (((cur_state & SPI_OP_STATE) == SPI_OP_STATE_PAUSE) && (state == SPI_OP_STATE_RESET))
    {
      outpdw(QUP_REGISTER_BASE + QUP_STATE, SPI_OP_STATE_CLEAR_BITS);
      outpdw(QUP_REGISTER_BASE + QUP_STATE, SPI_OP_STATE_CLEAR_BITS);
    }
    else
    {
      outpdw(QUP_REGISTER_BASE + QUP_STATE, (cur_state & ~SPI_OP_STATE) | state);
    }
    
    if (spi_wait_valid() == FALSE)
    {
      return FALSE;
    }
    else
    {
      return TRUE;
    }
  }
}

/************
 *
 * Name:      spi_init
 *
 * Purpose:   This function init spi register
 *
 * Params:    None
 *
 * Return:    TRUE when success, FALSE when fail
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
boolean spi_init(void)
{
  gpio_config_spi(GPIO_BLSP_QUP_GPIO_CNF_ID);

  clock_config_spi(SPI_CLOCK_ID, SPI_CLOCK_RATE);

  /*  SW reset*/
  outpdw(QUP_REGISTER_BASE + QUP_SW_RESET, 0x1);

  if (FALSE == spi_set_states(SPI_OP_STATE_RESET))
  {
    return FALSE;
  }
  
  /* Refer to Kernel, set SPI_DEASSERT_WAIT to 42 ticks */
  outpdw(QUP_REGISTER_BASE + SPI_DEASSERT_WAIT, SPI_DEASSERT_WAIT_TICKS);

  /* Disable IRQ when MAX_READ, MX_WRITE, MX_INPUT, MX_OUTPUT */
  outpdw(QUP_REGISTER_BASE + QUP_MX_READ_COUNT, 0x0);
  outpdw(QUP_REGISTER_BASE + QUP_MX_WRITE_COUNT, 0x0);
  outpdw(QUP_REGISTER_BASE + QUP_MX_INPUT_COUNT, 0x0);
  outpdw(QUP_REGISTER_BASE + QUP_MX_OUTPUT_COUNT, 0x0);

  /* SPI_CFG_INPUT_FIRST */
  outpdw(QUP_REGISTER_BASE + SPI_CONFIG, SPI_CFG_INPUT_FIRST);
  
  /* SPI core, xBytes_Bits transfer */
  outpdw(QUP_REGISTER_BASE + QUP_CONFIG, SPI_MINI_CORE | (SPI_BYTES_PER_WORD * SPI_BITS_PER_BYTE - 1));

  /* FORCE_CS, MX_CS_MODE, NO_TRI_STATE */
  outpdw(QUP_REGISTER_BASE + SPI_IO_CONTROL, SPI_IO_C_FORCE_CS | SPI_IO_C_MX_CS_MODE | SPI_IO_C_NO_TRI_STATE);

  /* Enable INPUT_SERVICE_MASK, OUTPUT_SERVICE_MASK */
  outpdw(QUP_REGISTER_BASE + QUP_OPERATIONAL_MASK, 0x0);

  if (FALSE == spi_set_states(SPI_OP_STATE_RUN))
  {
    return FALSE;
  }
  else
  {
    return TRUE;
  }
}

/************
 *
 * Name:      spi_write
 *
 * Purpose:   This function write data to SPI FIFO
 *
 * Params:    wbuf - point data buf to be written
 *                 wbuf_len - length of data buf
 *
 * Return:    Send data length or -1 when failed.
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
int spi_write(unsigned char *wbuf, int wbuf_len)
{
  volatile unsigned int word;
  int i, B_index_in_word = 1;
  unsigned char byte_i;

  if (wbuf == NULL)
  {
    return -1;
  }

  if (inpdw(QUP_REGISTER_BASE + QUP_ERROR_FLAGS) 
       || inpdw(QUP_REGISTER_BASE + SPI_ERROR_FLAGS))
  {
    return -1;
  }

  if (FALSE == spi_set_states(SPI_OP_STATE_PAUSE))
  {
    return -1;
  }
  
  outpdw(QUP_REGISTER_BASE + QUP_OPERATIONAL, SPI_OP_OUTPUT_SERVICE_FLAG);

  i = 0;
  while (!(inpdw(QUP_REGISTER_BASE + QUP_OPERATIONAL) & SPI_OP_OUTPUT_FIFO_FULL))
  {
    word = 0;
    for (B_index_in_word = 1; (B_index_in_word <= SPI_BYTES_PER_WORD) && (i < wbuf_len); B_index_in_word++)
    {
      byte_i = wbuf[i++];
      word |= (byte_i << (SPI_BITS_PER_BYTE * (SPI_WORD_TO_BYTES - B_index_in_word)));
    }
     
    outpdw(QUP_REGISTER_BASE + QUP_OUTPUT_FIFO, word);
    if (i >= wbuf_len)
    {
      break;
    }
  }
  
  if (FALSE == spi_set_states(SPI_OP_STATE_RUN))
  {
    return -1;
  }
  else
  {
    return i;
  }
}

/************
 *
 * Name:      spi_read
 *
 * Purpose:   This function read data from SPI FIFO
 *
 * Params:    rbuf - point buf to receive data from SPI FIFO
 *                 rbuf_len - length of buf
 *
 * Return:    Read data length or -1 when failed.
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
int spi_read(unsigned char *rbuf, int rbuf_len)
{
  volatile unsigned int data_in;
  int i, B_index_in_word = 1;
  int checkount = 0;
  int   shift;

  if (rbuf == NULL)
  {
    return -1;
  }

  if (inpdw(QUP_REGISTER_BASE + QUP_ERROR_FLAGS) 
       || inpdw(QUP_REGISTER_BASE + SPI_ERROR_FLAGS))
  {
    return -1;
  }

  while (!(inpdw(QUP_REGISTER_BASE + QUP_OPERATIONAL) &SPI_OP_INPUT_SERVICE_FLAG))
  {
    /* wait till we get input flag */
    spiWaitTicks();
    if (checkount++ >= SPI_MX_CHECK_VALID_COUNT)
    {
      /* Wait too long time, return -1 to caller */
      return -1;
    }
  }

  outpdw(QUP_REGISTER_BASE + QUP_OPERATIONAL, SPI_OP_INPUT_SERVICE_FLAG);
  
  i = 0;
  while ((inpdw(QUP_REGISTER_BASE + QUP_OPERATIONAL) & SPI_OP_IP_FIFO_NOT_EMPTY))
  {
    data_in = inpdw(QUP_REGISTER_BASE + QUP_INPUT_FIFO);
    /* The data format depends on bytes_per_word:
        4 bytes: 0x12345678
        3 bytes: 0x00123456
        2 bytes: 0x00001234
        1 byte : 0x00000012
        */
    for (B_index_in_word = 1; (B_index_in_word <= SPI_BYTES_PER_WORD) && (i < rbuf_len); B_index_in_word++)
    {
      shift = SPI_BITS_PER_BYTE * (SPI_BYTES_PER_WORD - B_index_in_word);
      rbuf[i++] = (data_in & (0xFF << shift)) >> shift;
    }

    if (i >= rbuf_len)
    {
      break;
    }
  }

  return i;
}

/************
 *
 * Name:      spi_read_write
 *
 * Purpose:   This function is for throughput test with SPI emulator
 *
 * Params:  wbuf - point data buf to be written
 *                wbuf_len - length of data buf  
 *                rbuf - point buf to receive data from SPI FIFO
 *                rbuf_len - length of buf
 *
 * Return:    TRUE when success, FALSE when fail
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
boolean spi_read_write(unsigned char *wbuf, int *wbuf_len, unsigned char *rbuf, int *rbuf_len)
{
  int rec_len = 0, rec_ttl = 0;
  int checkount = 0;

  if ((wbuf == NULL) || (wbuf_len == NULL) || (rbuf == NULL) || (rbuf_len == NULL))
  {
    return FALSE;
  }
  
  /* MDM9x40 is the master device, so we send data first */
  *wbuf_len = spi_write(wbuf, *wbuf_len);
  if (*wbuf_len <= 0)
  {
    return FALSE;
  }
  
  /* Based on SPI theory, when master send N bytes out, it should get N bytes back */
  if (*rbuf_len > *wbuf_len)
  {
    *rbuf_len = *wbuf_len;
  }
  
  do
  {
    rec_len = spi_read(&rbuf[rec_ttl], (*rbuf_len) - rec_ttl);
    if ((rec_len < 0) || (checkount++ >= SPI_MX_CHECK_VALID_COUNT))
    {
      return FALSE;
    }
    rec_ttl += rec_len;
  } while (rec_ttl < *wbuf_len);

  *rbuf_len = rec_ttl;
  return TRUE;
}


