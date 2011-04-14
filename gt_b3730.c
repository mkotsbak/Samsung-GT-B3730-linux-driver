/*
 * USB network interface driver for Samsung GT-B3730 LTE USB modem
 *
 * Copyright (C) 2011 Marius Bjoernstad Kotsbak
 *
 * Based on the cdc_eem module
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ctype.h>
#include <linux/ethtool.h>
#include <linux/workqueue.h>
#include <linux/mii.h>
#include <linux/usb.h>
#include <linux/crc32.h>
#include <linux/usb/cdc.h>
#include <linux/usb/usbnet.h>
#include <linux/gfp.h>


/*
 */

//#define      DEBUG                   // error path messages, extra info
//#define      VERBOSE

#define HEADER_LENGTH 6
#define ALIGN_SIZE 4
#define USB_TIMEOUT 10000

/*-------------------------------------------------------------------------*/

/*
static void eem_linkcmd_complete(struct urb *urb)
{
	dev_kfree_skb(urb->context);
	usb_free_urb(urb);
}

static void eem_linkcmd(struct usbnet *dev, struct sk_buff *skb)
{
	struct urb		*urb;
	int			status;

	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb)
		goto fail;

	usb_fill_bulk_urb(urb, dev->udev, dev->out,
			skb->data, skb->len, eem_linkcmd_complete, skb);

	status = usb_submit_urb(urb, GFP_ATOMIC);
	if (status) {
		usb_free_urb(urb);
fail:
		dev_kfree_skb(skb);
		netdev_warn(dev->net, "link cmd failure\n");
		return;
	}
}
*/


static int init_and_get_ethernet_addr(const struct usbnet *dev, u8 *ethernet_addr)
{
  int act_len;
  int status;
  char init_msg_1[] = {0x57,0x50,0x04,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00};
  char init_msg_2[] = {0x57,0x50,0x04,0x00,0x00,0x00,0x00,0x02,0x00,0xf4,0x00,0x00};
  char receive_buf[512];

  printk(KERN_INFO"Trying to send init package");

  status = usb_bulk_msg(dev->udev, usb_sndbulkpipe(dev->udev, 0x02), init_msg_1, sizeof(init_msg_1), &act_len, USB_TIMEOUT);

  if (status != 0) {
    printk(KERN_ERR"Error sending init package. Status %i, length %i\n", status, act_len);
    return status;
  }
  else {
    printk(KERN_INFO"Sent package length: %i\n", act_len);
  }

  status = usb_bulk_msg(dev->udev, usb_rcvbulkpipe(dev->udev, 0x81), receive_buf, sizeof(receive_buf), &act_len, USB_TIMEOUT);

  if (status != 0) {
    printk(KERN_ERR"Error receiving init result. Status %i, length %i\n", status, act_len);
    return status;
  }
  else {
    printk(KERN_INFO"Received init result: %i\n", act_len);
  }

  printk(KERN_INFO"Trying to send init package 2");

  status = usb_bulk_msg(dev->udev, usb_sndbulkpipe(dev->udev, 0x02), init_msg_2, sizeof(init_msg_2), &act_len, USB_TIMEOUT);

  if (status != 0) {
    printk(KERN_ERR"Error sending init package. Status %i, length %i\n", status, act_len);
    return status;
  }
  else {
    printk(KERN_INFO"Sent package length: %i\n", act_len);
  }

  status = usb_bulk_msg(dev->udev, usb_rcvbulkpipe(dev->udev, 0x81), receive_buf, sizeof(receive_buf), &act_len, USB_TIMEOUT);

  if (status != 0) {
    printk(KERN_ERR"Error receiving init result. Status %i, length %i\n", status, act_len);
    return status;
  }
  else {
    printk(KERN_INFO"Received init result: %i\n", act_len);
    memcpy(ethernet_addr, receive_buf + 10, ETH_ALEN);
  }

  return status;
}

static int gt_b3730_bind(struct usbnet *dev, struct usb_interface *intf)
{
  u8 status;
  u8 ethernet_addr[ETH_ALEN];

	dev->in = usb_rcvbulkpipe (dev->udev, 0x81 & USB_ENDPOINT_NUMBER_MASK);
	dev->out = usb_sndbulkpipe (dev->udev, 0x02 & USB_ENDPOINT_NUMBER_MASK);
	dev->status = NULL;

	dev->net->hard_header_len += HEADER_LENGTH;
	dev->hard_mtu = 1400;
	dev->rx_urb_size = dev->hard_mtu * 20;

	status = init_and_get_ethernet_addr(dev, ethernet_addr);

	if (status < 0) {
		usb_set_intfdata(intf, NULL);
		usb_driver_release_interface(driver_of(intf), intf);
		return status;
	}

        memcpy(dev->net->dev_addr, ethernet_addr, ETH_ALEN);
        memcpy(dev->net->perm_addr, ethernet_addr, ETH_ALEN);

	return status;
}

/*
 */
static struct sk_buff *gt_b3730_tx_fixup(struct usbnet *dev, struct sk_buff *skb,
				       gfp_t flags)
{
	struct sk_buff	*skb2 = NULL;
	u16		content_len;
	//	u32		crc = 0;
	unsigned char *header_start;
	unsigned char ether_type_1, ether_type_2;
	u8 reminder, padlen;

	if (!skb_cloned(skb)) {
		int	headroom = skb_headroom(skb);
		int	tailroom = skb_tailroom(skb);

		if ((tailroom >= ALIGN_SIZE) &&
		    (headroom >= HEADER_LENGTH))
			goto done;

		if ((headroom + tailroom)
				> (HEADER_LENGTH + ALIGN_SIZE)) {
			skb->data = memmove(skb->head +
					HEADER_LENGTH,
					skb->data,
					skb->len);
			skb_set_tail_pointer(skb, skb->len);
			goto done;
		}
	}

	skb2 = skb_copy_expand(skb, HEADER_LENGTH, ALIGN_SIZE, flags);
	if (!skb2)
		return NULL;

	dev_kfree_skb_any(skb);
	skb = skb2;

done:
	//	crc = crc32_le(~0, skb->data, skb->len);
	//	crc = ~crc;

	//	put_unaligned_le32(crc, skb_put(skb, ETH_FCS_LEN));

	// len = skb->len;

	header_start = skb_push(skb, HEADER_LENGTH);
	ether_type_1 = header_start[HEADER_LENGTH + 12];
	ether_type_2 = header_start[HEADER_LENGTH + 13];

#ifdef DEBUG
	printk(KERN_INFO"Sending etherType: %02x%02x", ether_type_1, ether_type_2);
#endif

	// According to empiric data for data packages
	header_start[0] = 0x57;
	header_start[1] = 0x44;
	content_len = skb->len - HEADER_LENGTH;
	header_start[2] = (content_len & 0xff); // low byte
	header_start[3] = (content_len >> 8);   // high byte

	header_start[4] = ether_type_1;
	header_start[5] = ether_type_2;

	// Align to 4 bytes by padding with zeros
	reminder = skb->len % ALIGN_SIZE;
	if (reminder > 0) {
	  padlen = ALIGN_SIZE - reminder;
	  memset(skb_put(skb, padlen), 0, padlen);
	}

#ifdef DEBUG
	printk(KERN_INFO"Sending package with length %i and padding %i. Header: %02x:%02x:%02x:%02x:%02x:%02x.", content_len,
	       padlen, header_start[0], header_start[1], header_start[2], header_start[3], header_start[4], header_start[5]);
#endif

	return skb;
}

static int gt_b3730_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	/*
	 * Our task here is to strip off framing, leaving skb with one
	 * data frame for the usbnet framework code to process.
	 */
		const u8 HEADER_END_OF_USB_PACKET[] = {0x57,0x5a,0x00,0x00,0x08,0x00};
		u8 i = 0;

		/* incomplete header? */
		if (skb->len < HEADER_LENGTH)
			return 0;

		/* TODO: check first 2 header bytes for 0x57:0x44 */

		do {
		    struct sk_buff *skb2 = NULL;
		    u8 *header_start;
		    u16 usb_packet_length, ether_packet_lenght;
		    int	is_last;

		    header_start = skb->data;

		    if (unlikely(header_start[0] != 0x57 || header_start[1] != 0x44)) {
		      printk(KERN_INFO"Received unknown frame header: %02x:%02x:%02x:%02x:%02x:%02x. Package length: %i\n",
			     header_start[0], header_start[1], header_start[2], header_start[3], header_start[4], header_start[5], skb->len - HEADER_LENGTH);
		      return 0;
		    }
#ifdef DEBUG
		    printk(KERN_INFO"Received header: %02x:%02x:%02x:%02x:%02x:%02x. Package length: %i\n",
			   header_start[0], header_start[1], header_start[2], header_start[3], header_start[4], header_start[5], skb->len - HEADER_LENGTH);
#endif

		    usb_packet_length = skb->len - (2 * HEADER_LENGTH); // subtract start header and end header
		    ether_packet_lenght = header_start[2] + (header_start[3] << 8);
		    skb_pull(skb, HEADER_LENGTH);

		    if (unlikely(usb_packet_length < ether_packet_lenght)) {
		        printk(KERN_ERR"Invalid package length %i, expected %i!", usb_packet_length, ether_packet_lenght);
			ether_packet_lenght = usb_packet_length + HEADER_LENGTH;
			is_last = true;
		    }
		    else {
#ifdef DEBUG
		        printk(KERN_INFO"Correct package lenght #%i", i+1);
#endif

			is_last = (memcmp(skb->data + ether_packet_lenght, HEADER_END_OF_USB_PACKET, sizeof(HEADER_END_OF_USB_PACKET)) == 0);
			if (!is_last) {
			  header_start = skb->data + ether_packet_lenght;
#ifdef DEBUG
			  printk(KERN_INFO"End header: %02x:%02x:%02x:%02x:%02x:%02x. Package length: %i\n",
			   header_start[0], header_start[1], header_start[2], header_start[3], header_start[4], header_start[5], skb->len - HEADER_LENGTH);
#endif

			}
		    }

		    if (is_last) skb2 = skb;
		    else {
		        skb2 = skb_clone(skb, GFP_ATOMIC);
			if (unlikely(!skb2))
  			    return 0;
		    }

		    skb_trim(skb2, ether_packet_lenght);

		    if (is_last) return 1;
		    else {
			usbnet_skb_return(dev, skb2);
			skb_pull(skb, ether_packet_lenght);
		    }

		i++;
		} while (skb->len);

	return 1;
}

static const struct driver_info gt_b3730_info = {
	.description =	"Samsung GT-B3730 LTE USB dongle",
	.flags =	FLAG_WWAN,
	.bind =		gt_b3730_bind,
	.rx_fixup =	gt_b3730_rx_fixup,
	.tx_fixup =	gt_b3730_tx_fixup,
};

/*-------------------------------------------------------------------------*/

static const struct usb_device_id products[] = {
{
	/* Samsung LTE modem */
	.match_flags    =   USB_DEVICE_ID_MATCH_INT_INFO
		 | USB_DEVICE_ID_MATCH_DEVICE,
	.idVendor               = 0x04e8,
	.idProduct              = 0x6889,	/* Samsung LTE */
	USB_INTERFACE_INFO(USB_CLASS_VENDOR_SPEC, 0, 0),
	.driver_info = (unsigned long) &gt_b3730_info,
},
{
	/* EMPTY == end of list */
},
};
MODULE_DEVICE_TABLE(usb, products);

static struct usb_driver gt_b3730_driver = {
	.name =		"gt_b3730",
	.id_table =	products,
	.probe =	usbnet_probe,
	.disconnect =	usbnet_disconnect,
	.suspend =	usbnet_suspend,
	.resume =	usbnet_resume,
};


static int __init gt_b3730_init(void)
{
	return usb_register(&gt_b3730_driver);
}
module_init(gt_b3730_init);

static void __exit gt_b3730_exit(void)
{
	usb_deregister(&gt_b3730_driver);
}
module_exit(gt_b3730_exit);

MODULE_AUTHOR("Marius Bjoernstad Kotsbak <marius@kotsbak.com>");
MODULE_DESCRIPTION("Samsung GT-B3730");
MODULE_LICENSE("GPL");
