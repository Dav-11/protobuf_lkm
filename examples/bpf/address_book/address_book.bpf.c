#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "address_book_gen.h"

#define MY_PORT 60001
#define BUFFER_SIZE 1024

unsigned int process_message(char *buffer, int size) {
  uint8_t workspace[BUFFER_SIZE];

  struct address_book_address_book_t *address_book_p;

  /*
   * Decode the message.
   */
  address_book_p =
      address_book_address_book_new(&workspace[0], sizeof(workspace));

  address_book_address_book_decode(address_book_p, buffer, size);

  return SK_PASS;
}

/**
 * This function reads the first 4 bytes of the payload extracting the size of
 * the message, if the size is bigger than the buffer size, returns -1
 */
static int extract_message_size(char *buffer) {
  // extract first 4 bytes (int) as protobuf size
  int size = (uint32_t)ntohl(*((uint32_t *)buffer));

  if (size < BUFFER_SIZE) {

    bpf_printk("Found size: %u\n", size);
    return size;
  } else {

    bpf_printk(
        "Payload is too big for the specified buffer: [wanted: %u, got: %d]\n",
        size, BUFFER_SIZE);
    return -1;
  }
}

SEC("sk_skb/prog_parser")
int address_book_skb(struct __sk_buff *skb) {

  struct iphdr *ip;
  struct tcphdr *tcp;
  __u32 payload_len;
  unsigned char *buffer;

  if (skb->protocol != IPPROTO_TCP) {
    return SK_PASS;
  }

  if (skb->remote_ip != htonl(INADDR_LOOPBACK)) {
    return SK_PASS;
  }

  if (skb->remote_port != htons(MY_PORT)) {
    return SK_PASS;
  }

  if (skb->data_end - skb->data < sizeof(struct iphdr)) {
    return SK_PASS;
  }

  ip = (struct iphdr *)skb->data;

  if (skb->data_end - (skb->data + sizeof(struct iphdr)) <
      sizeof(struct tcphdr)) {
    return SK_PASS;
  }

  tcp = (struct tcphdr *)(skb->data + sizeof(struct iphdr));

  if (!tcp->psh) {
    return SK_PASS;
  }

  // linearize skb
  if (skb_is_nonlinear(skb)) {
    if (skb_linearize(skb) != 0) {
      return SK_PASS;
    }
  }

  payload_len = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);

  bpf_printk("Payload length: %d\n", payload_len);

  if (payload_len > 0) {

    buffer = (unsigned char *)(tcp) + (tcp->doff * 4);

    // extract size of protobuf from buffer
    int size = extract_message_size(buffer);

    if (size > 0) {

      // Process received data as needed
      return process_message(buffer + 4, size);
    }
  }

  return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
