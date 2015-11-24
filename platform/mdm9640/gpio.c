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
