/*
 * Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Linux Foundation nor
 *     the names of its contributors may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <reg.h>
#include <debug.h>
#include <platform/iomap.h>
#include <platform/gpio.h>

typedef struct {
	uint32_t  gpio;
	uint8_t   func;
} uart_gpio_conf_t;

typedef struct {
	uart_gpio_conf_t tx;
	uart_gpio_conf_t rx;
} uart_gpio_pair_t;

static const uart_gpio_pair_t uart_pair[] = {
	{{20, 3}, {21, 3}}, /* UART1 */
	{{4, 2}, {5, 2}},   /* UART2 */
	{{8, 3}, {9, 3}}    /* UART3 */
};

/* SWISTART */
#ifdef SIERRA
typedef uart_gpio_conf_t spi_gpio_conf_t;

typedef struct {
	spi_gpio_conf_t mosi;
	spi_gpio_conf_t miso;
	spi_gpio_conf_t cs;
	spi_gpio_conf_t clk;
} spi_gpio_pair_t;

static const spi_gpio_pair_t spi_pair[] = {
	{{0x00, 0x00}, {0x00, 0x00}, {0x00, 0x00}, {0x00, 0x00}}, /* For BLSP_QUP1_SPI, not supported yet */
	{{0x08, 0x02}, {0x09, 0x02}, {0x0A, 0x02}, {0x0B, 0x02}}, /* For BLSP_QUP2_SPI */ 
	{{0x10, 0x02}, {0x11, 0x02}, {0x12, 0x02}, {0x13, 0x02}}, /* For BLSP_QUP3_SPI */ 
};
#endif
/* SWISTOP */

void gpio_tlmm_config(uint32_t gpio,
					  uint8_t  func,
					  uint8_t  dir,
					  uint8_t  pull,
					  uint8_t  drvstr,
					  uint32_t enable)
{
	uint32_t val = 0;

	val |= pull;
	val |= func << 2;
	val |= drvstr << 6;
	val |= enable << 9;

	writel(val, GPIO_CONFIG_ADDR(gpio));

	return;
}

void gpio_set(uint32_t gpio, uint32_t dir)
{
	writel(dir, GPIO_IN_OUT_ADDR(gpio));

	return;
}

uint32_t gpio_get_state(uint32_t gpio)
{
	return readl(GPIO_IN_OUT_ADDR(gpio));
}

void gpio_config_uart_dm(uint8_t id)
{
	const uart_gpio_pair_t *p;

	/* check for array out of bound */
	if (id < 1 || id > ARRAY_SIZE(uart_pair)) {
		dprintf(CRITICAL, "GPIOs for UART%d not supported.\n", id);
		ASSERT(0);
		/* should never be here, but anyway... */
		return;
	}

	/* extract GPIO configuration for UART */
	p = &(uart_pair[id - 1]);

	/* configure rx gpio. */
	gpio_tlmm_config(p->rx.gpio, p->rx.func, GPIO_INPUT, GPIO_NO_PULL, GPIO_6MA, GPIO_DISABLE);
	/* configure tx gpio. */
	gpio_tlmm_config(p->tx.gpio, p->tx.func, GPIO_OUTPUT, GPIO_NO_PULL, GPIO_6MA, GPIO_DISABLE);
	return;
}

/* SWISTART */
#ifdef SIERRA
void gpio_config_spi(uint8_t id)
{
	const spi_gpio_pair_t *p;

	/* check for array out of bound */
	if ((GPIO_BLSP_QUP2_GPIO_CNF_ID > id) || (id > GPIO_BLSP_QUP3_GPIO_CNF_ID)) {
		dprintf(CRITICAL, "GPIOs for SPI%d not supported.\n", id);
		ASSERT(0);
		/* should never be here, but anyway... */
		return;
	}

	/* extract GPIO configuration for UART */
	p = &(spi_pair[id]);

	/* configure mosi gpio. */
	gpio_tlmm_config(p->mosi.gpio, p->mosi.func, GPIO_OUTPUT, GPIO_NO_PULL, GPIO_6MA, GPIO_DISABLE);
	/* configure miso gpio. */
	gpio_tlmm_config(p->miso.gpio, p->miso.func, GPIO_INPUT, GPIO_NO_PULL, GPIO_6MA, GPIO_DISABLE);
	/* configure cs gpio. */
	gpio_tlmm_config(p->cs.gpio, p->cs.func, GPIO_OUTPUT, GPIO_NO_PULL, GPIO_6MA, GPIO_DISABLE);
	/* configure clk gpio. */
	gpio_tlmm_config(p->clk.gpio, p->clk.func, GPIO_OUTPUT, GPIO_NO_PULL, GPIO_6MA, GPIO_DISABLE);
	return;
}
#endif
/* SWISTOP */
