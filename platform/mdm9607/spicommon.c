/************
 *
 * $Id$
 *
 * Filename:  spicommon.c
 *
 * Purpose:   Common files for spi driver package
 *
 *
 * Copyright (C) 2009 Sierra Wireless, Inc.
 *
 ************/

/* Include files */
#include <platform/spiudefs.h>
#include <reg.h>
#include "qtimer.h"
#include "gpio.h"
#include <platform/clock.h>
#include <string.h>

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

#define SPI_NO_CHAR (-1)

/* SPI driver globe configuration begin:
  * Developer should modify these item to adapt SPI register and clock of MDM9x28 */

#if 0
#define SPI_USE_BLSP_QUP2
#endif

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
/* We use QUP5 config, real index is 6 in QC's HW document */

/* Range of BLSP_QUP_QUP_CONFIG: 
  * BLSP_QUP0_QUP_CONFIG,
  * BLSP_QUP1_QUP_CONFIG,
  * BLSP_QUP2_QUP_CONFIG,
  * BLSP_QUP3_QUP_CONFIG */
unsigned int qup_register = 0x78BA000;  /* Now we use BLSP_QUP5_QUP_CONFIG: 0x78BA000, real index 6 */

/* GPIOs configuration for SPI */
/* Real index for BLSP_QUP5_QUP_CONFIG is index 6 */
#define GPIO_BLSP_QUP_GPIO_CNF_ID GPIO_BLSP_QUP5_GPIO_CNF_ID

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

/* SPI FIFO length by word */
#define SPI_FIFO_LEN_BY_WORD        16

/* SPI FIFO length by bytes */
#define SPI_FIFO_LEN_BY_BYTE        (SPI_FIFO_LEN_BY_WORD * SPI_BYTES_PER_WORD)

/* Refer to Kernel, set SPI_DEASSERT_WAIT to 42 ticks */
#define SPI_DEASSERT_WAIT_TICKS     0x14

#define SPI_MX_CHECK_VALID_COUNT    100

#define SPI_COMMON_TIME_INTERVAL    1   /*ns*/

#define SPI_DUMMY_BYTES_FOR_READING 0xFF

#define SPI_READ_WRITE_BUF_MAX_LEN  SPI_FIFO_LEN_BY_BYTE

unsigned char spi_dummy_buf[SPI_READ_WRITE_BUF_MAX_LEN] = {0}; /* Dummy buf for reading and writing */

unsigned char spi_read_buf[SPI_READ_WRITE_BUF_MAX_LEN] = {0};  /* To receive read data */
int spi_read_buf_len = 0;                                      /* Vaild length of read_buf */
int spi_read_index = 0;                                        /* Index to be read of read_buf */


unsigned char spi_write_buf[SPI_READ_WRITE_BUF_MAX_LEN] = {0}; /* To receive write data */
int spi_write_buf_len = 0;                                     /* Vaild length of write_buf */
int spi_write_index = 0;                                       /* Index to be written of write_buf */


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

  /*IO mode config*/
  outpdw(QUP_REGISTER_BASE + QUP_IO_MODES, 0x000100A5);

  /* SPI_CFG_INPUT_FIRST */
  /* Customer request CHPA = 1, so we remove it */
  /* outpdw(QUP_REGISTER_BASE + SPI_CONFIG, SPI_CFG_INPUT_FIRST); */
  
  /* SPI core, xBytes_Bits transfer */
  outpdw(QUP_REGISTER_BASE + QUP_CONFIG, SPI_MINI_CORE | (SPI_BYTES_PER_WORD * SPI_BITS_PER_BYTE - 1));

  /* FORCE_CS, MX_CS_MODE, NO_TRI_STATE */
  /* Customer reqeust not to force CS low, so we remove SPI_IO_C_FORCE_CS | SPI_IO_C_MX_CS_MODE | */
  outpdw(QUP_REGISTER_BASE + SPI_IO_CONTROL, SPI_IO_C_NO_TRI_STATE);

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
 * Name:     spi_init_ex
 *
 * Purpose:  SPI init
 *
 * Parms:    use_pid - not used
 *
 * Return:   none
 *
 * Abort:    none
 *
 * Notes:    none
 *
 ************/
void spi_init_ex(boolean use_pid)
{
  memset(spi_read_buf, 0, SPI_READ_WRITE_BUF_MAX_LEN);
  spi_read_buf_len = 0;
  spi_read_index = 0;

  memset(spi_write_buf, 0, SPI_READ_WRITE_BUF_MAX_LEN);
  spi_write_index = 0;
  
  spi_init();
  return;
}


/************
 *
 * Name:      spi_shutdown
 *
 * Purpose:   This function close SPI
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
void spi_shutdown(void)
{
  /* In LK, we won't have a special API to close clock for special device
   * So leave it stub here. */
  return;
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
  int i, B_index_in_word = 0;
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
  int i, B_index_in_word = 0;
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
        4 bytes: 0x78563412
        3 bytes: 0x00563412
        2 bytes: 0x00003412
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
 * Name:      spi_drain
 *
 * Purpose:  This function waits for the last character in the SPI's transmit
 *                FIFO to be transmitted.  This allows the caller to be sure that all
 *                characters are transmitted.
 *
 * Params:    
 *
 * Return:    Read data length or -1 when failed.
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
void spi_drain(void)
{
  while ((inpdw(QUP_REGISTER_BASE + QUP_OPERATIONAL) & SPI_OP_OP_FIFO_NOT_EMPTY))
  {
    spiWaitTicks();
  }
  
  /* When OP FIFO empty, it will return */
  return;
}

/************
 *
 * Name:      spi_drain_timeout
 *
 * Purpose:  This function waits for the last character in the SPI's transmit
 *                FIFO to be transmitted.  This allows the caller to be sure that all
 *                characters are transmitted.
 *
 * Params:    timeout - not used.
 *
 * Return:    Read data length or -1 when failed.
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
void spi_drain_timeout(uint32 timeout)
{
  spi_drain();
  return;
}

/************
 *
 * Name:      spi_receive_byte
 *
 * Purpose:  This function receives an incoming data from the respective USB out fifos and
 *                returns one character at a time to the calling function. Though it receives
 *                a bigger packet at once, it always retuns one character to the calling function.
 *                This approach is choosen to have a consitancy between the UART and USB modules.
 *
 * Params:    
 *
 * Return:  character from the receive buffer.
 *              If there is nothing in the receive buffer then it return SPI_NO_CHAR (-1).
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
int spi_receive_byte(void)
{
  int ret = -1;
  int write_ret = 0, read_ret = 0, checkcount= 0;
  
  if (spi_read_buf_len <= spi_read_index)
  {
    /* Clear read buf */
    memset(spi_read_buf, 0, SPI_READ_WRITE_BUF_MAX_LEN);
    spi_read_buf_len = 0;
    spi_read_index = 0;
    
    /* 1, we send out any data in write_buf, and align it with dummy bytes */
    memset(spi_dummy_buf, SPI_DUMMY_BYTES_FOR_READING, SPI_READ_WRITE_BUF_MAX_LEN);
    write_ret = spi_write(spi_dummy_buf, SPI_BYTES_PER_WORD);
    if (write_ret <= 0)
    {
      return SPI_NO_CHAR;
    }
    else
    {
      /* 2, we will get back length of data as the lengh we already send out  */
      read_ret = 0;
      checkcount = 0;

      do
      {
        read_ret = spi_read(&spi_read_buf[spi_read_buf_len], SPI_READ_WRITE_BUF_MAX_LEN - spi_read_buf_len);
        if ((read_ret < 0) || (checkcount++ >= SPI_MX_CHECK_VALID_COUNT))
        {
          return SPI_NO_CHAR;
        }
        else
        {
          spi_read_buf_len += read_ret;
        }
      } while(spi_read_buf_len < write_ret);
      
    }
  }

  ret = (int)spi_read_buf[spi_read_index++];
  
  return ret;
}

/************
 *
 * Name:      spi_transmit_byte
 *
 * Purpose:  Transmit a byte to the host.
 *
 * Params:    data - byte to transmit
 *
 * Return:    None
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
void spi_transmit_byte(unsigned char data)
{
  /* It will be very complex to impletement send data byte by byte on SPI, 
     * because we have to deal with case 1,2,3,4 bytes per word when do this. 
     * For case 2,3,4 bytes per word, we have to deal it with  Length  threshold and time threshold  
     * For a FW of simple task, it is hard to implement time threshold  */
     
  /* However it is good luck that SSDP doens't request to send data byte by byte,
     * So we just keep it as stub function now. 
     * When it is necessarry in future, we will implement it with APP's logic */
  return;
}

/************
 *
 * Name:      spi_receive_pkt
 *
 * Purpose:  This function receive a buffer from host.
 *
 * Params:    buf - point to final receive buffer 
 *
 * Return:    Length data received from host 
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
uint32 spi_receive_pkt(unsigned char **buf)
{
  uint32  ulLen = 0;
  int write_ret = 0, read_ret = 0, checkcount= 0;

  if (buf == NULL)
  {
    return 0;
  }

  if (spi_read_buf_len <= spi_read_index)
  {
    /* Clear read buf */
    memset(spi_read_buf, 0, SPI_READ_WRITE_BUF_MAX_LEN);
    spi_read_buf_len = 0;
    spi_read_index = 0;

    /* 1, we send out dummy bytes */
    memset(spi_dummy_buf, SPI_DUMMY_BYTES_FOR_READING, SPI_READ_WRITE_BUF_MAX_LEN);
    write_ret = spi_write(spi_dummy_buf, SPI_READ_WRITE_BUF_MAX_LEN);
    if (write_ret <= 0)
    {
      ulLen = 0;
      *buf = NULL;
    }
    else
    {
      /* 2, we will get back length of data as the lengh we already send out */
      read_ret = 0;
      checkcount = 0;
      *buf = spi_read_buf;
      
      do
      {
        read_ret = spi_read(&spi_read_buf[spi_read_buf_len], SPI_READ_WRITE_BUF_MAX_LEN - spi_read_buf_len);
        if ((read_ret < 0) || (checkcount++ >= SPI_MX_CHECK_VALID_COUNT))
        {
          ulLen = 0;
          *buf = NULL;
          break;
        }
        else
        {
          spi_read_buf_len += read_ret;
          ulLen = spi_read_buf_len;
        }
      } while(spi_read_buf_len < write_ret);
    }  
  }
  else
  {
    /* There are still some data when we "spi_receive_byte()", return all of them to APP first,
         * then we can receive pkt high speed next time */
    *buf = &spi_read_buf[spi_read_index];
    ulLen = spi_read_buf_len - spi_read_index;
  }

  spi_read_buf_len = 0;
  spi_read_index = 0;
  return ulLen;
}

/************
 *
 * Name:      spi_transmit_pkt
 *
 * Purpose:  This function transmit a buffer to the host.
 *
 * Params:    pkt - pointer to pkt to be transmitted
 *                 len - number of bytes to tx
 *
 * Return:    None
 *
 * Note:      None
 *
 * Abort:     None
 *
 ************/
void spi_transmit_pkt (unsigned char *pkt, uint32 len)
{
  uint32 ttl_send = 0, len_to_send = 0;
  int write_ret = 0, read_ret = 0, read_ttl = 0, checkcount= 0;
    
  if (pkt == NULL)
  {
    return;
  }

  ttl_send = 0;
  do
  {
    len_to_send = (len - ttl_send > SPI_READ_WRITE_BUF_MAX_LEN) ? SPI_READ_WRITE_BUF_MAX_LEN:len - ttl_send;

    /* 1, we send out bytes */
    write_ret = spi_write(&pkt[ttl_send], len_to_send);
    if (write_ret <= 0)
    {
      return;
    }
    else
    {
      /* 2, we will get back length of dummy data as the lengh we already send out, and discard all of those dummy data */
      read_ret = 0;
      read_ttl = 0;
      checkcount = 0;
      
      do
      {
        read_ret = spi_read(&spi_dummy_buf[read_ttl], SPI_READ_WRITE_BUF_MAX_LEN - read_ttl);
        if ((read_ret < 0) || (checkcount++ >= SPI_MX_CHECK_VALID_COUNT))
        {
          return;
        }
        else
        {
          read_ttl += read_ret;
        }
      } while(read_ttl < write_ret);
    }

    ttl_send += write_ret;
  } while (len > ttl_send);

  return;
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


