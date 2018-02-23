#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>

#include <seclib.h>
#include "project.h"

static UCHAR broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


// Recv Thread
void EmRecvThread(THREAD *thread, void *param)
{
	EM *m;
	ETH *eth = NULL;
	CANCEL *cancel = NULL;
	UINT num_open_fail = 0;
	char if_name[MAX_SIZE];
	QUEUE *q;
	if (thread == NULL || param == NULL)
	{
		return;
	}
	m = (EM *)param;

	StrCpy(if_name, sizeof(if_name), m->Config->InputIf);

	while (m->Halt == false)
	{
		if (eth == NULL)
		{
			eth = OpenEth(if_name, false, false, NULL);
			if (eth == NULL)
			{
				// open failed
				if (num_open_fail == 0)
				{
					EmLog(m, "EMLOG_ETH_OPEN_ERROR", if_name);
				}
				num_open_fail++;
				SleepThread(200);
			}
			else
			{
				// open ok
				cancel = EthGetCancel(eth);
			}
		}

		if (eth != NULL)
		{
			// Get next packet
			q = NULL;
			while (true)
			{
				UCHAR *data;
				UINT size = EthGetPacket(eth, &data);
				if (size == INFINITE)
				{
					// Interface error
					EmLog(m, "EMLOG_ETH_GET_ERROR", if_name);

					CloseEth(eth);
					eth = NULL;
					num_open_fail = 0;

					ReleaseCancel(cancel);
					cancel = NULL;

					break;
				}
				else if (size == 0)
				{
					// Wait for next packet
					Select(NULL, 10, cancel, NULL);
					break;
				}
				else
				{
					if (size >= 14 && Cmp(data + 6, m->Config->OutputMac, 6) != 0)
					{
						// Packet received. Check it.
						PKT *pkt = EmParsePacket(m, data, size);

						if (pkt != NULL)
						{
							// Insert to the queue.
							if (q == NULL)
							{
								q = NewQueueFast();
							}

							//						Debug("%u\n", size);
							if (q->num_item < EM_MAX_QUEUE_SIZE)
							{
								InsertQueue(q, pkt);
							}
							else
							{
								FreePacketWithData(pkt);
							}
						}
					}
					else
					{
						//Debug("Self: %u\n", size);
						Free(data);
					}
				}
			}

			if (q != NULL)
			{
				UINT num_inserted_packets = 0;

				LockQueue(m->SendQueue);
				{
					PKT *pkt;

					while (pkt = GetNext(q))
					{
						if (m->SendQueue->num_item < EM_MAX_QUEUE_SIZE)
						{
							InsertQueue(m->SendQueue, pkt);

							num_inserted_packets++;
						}
						else
						{
							FreePacketWithData(pkt);
						}
					}
				}
				UnlockQueue(m->SendQueue);

				ReleaseQueue(q);

				if (num_inserted_packets != 0)
				{
					CANCEL *cancel = NULL;

					Lock(m->Lock);
					{
						cancel = m->SendCancel;

						if (cancel != NULL)
						{
							AddRef(cancel->ref);
						}
					}
					Unlock(m->Lock);

					if (cancel != NULL)
					{
						Cancel(cancel);

						ReleaseCancel(cancel);
					}
				}
			}
		}
	}

	CloseEth(eth);
	ReleaseCancel(cancel);
}

// check the received packet
PKT *EmParsePacket(EM *m, UCHAR *data, UINT size)
{
	PKT *p = NULL;
	if (m == NULL || data == NULL || size == 0)
	{
		return false;
	}

	p = ParsePacket(data, size);

	// Check the source MAC address
	if (Cmp(p->MacAddressSrc, m->Config->OutputMac, 6) == 0)
	{
		goto LABEL_ERROR;
	}
	
	if (p->TypeL3 != L3_IPV4)
	{
		goto LABEL_ERROR;
	}

	return p;

LABEL_ERROR:
	FreePacketWithData(p);
	return NULL;
}

// Send Thread
void EmSendThread(THREAD *thread, void *param)
{
	EM *m;
	ETH *eth = NULL;
	UINT num_open_fail = 0;
	char if_name[MAX_SIZE];
	if (thread == NULL || param == NULL)
	{
		return;
	}
	m = (EM *)param;

	StrCpy(if_name, sizeof(if_name), m->Config->OutputIf);

	while (m->Halt == false)
	{
		UINT64 now = Tick64();

		if (eth == NULL)
		{
			eth = OpenEth(if_name, false, false, NULL);
			if (eth == NULL)
			{
				// open failed
				if (num_open_fail == 0)
				{
					EmLog(m, "EMLOG_ETH_OPEN_ERROR", if_name);
				}
				num_open_fail++;
				SleepThread(200);
			}
			else
			{
				// open ok
				Lock(m->Lock);
				{
					m->SendCancel = EthGetCancel(eth);
				}
				Unlock(m->Lock);
			}
		}

		if (eth != NULL)
		{
			QUEUE *q = NewQueueFast();

			// Packet sender (from the mirror queue)
			LockQueue(m->SendQueue);
			{
				PKT *pkt;
				while (pkt = GetNext(m->SendQueue))
				{
					InsertQueue(q, pkt);
				}
			}
			UnlockQueue(m->SendQueue);

			// ARP request sender
			if (now >= m->next_arp_send_tick || m->next_arp_send_tick == 0)
			{
				ARPV4_HEADER arp;
				UINT i;

				for (i = 0;i < m->Config->NumTargetIp;i++)
				{
					UCHAR *buf;
					MAC_HEADER *mac_header;
					IP target_ip;

					Zero(&arp, sizeof(arp));
					
					CopyIP(&target_ip, &m->Config->TargetIpList[i]);

					// Build an ARP header
					arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
					arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
					arp.HardwareSize = 6;
					arp.ProtocolSize = 4;
					arp.Operation = Endian16(ARP_OPERATION_REQUEST);
					Copy(arp.SrcAddress, m->Config->OutputMac, 6);
					arp.SrcIP = IPToUINT(&m->Config->OutputArpSrc);
					Zero(&arp.TargetAddress, 6);
					arp.TargetIP = IPToUINT(&target_ip);

					// Buffer creation
					buf = Malloc(MAC_HEADER_SIZE + sizeof(arp));

					// MAC header
					mac_header = (MAC_HEADER *)&buf[0];
					Copy(mac_header->DestAddress, broadcast, 6);
					Copy(mac_header->SrcAddress, m->Config->OutputMac, 6);
					mac_header->Protocol = Endian16(MAC_PROTO_ARPV4);

					// Copy data
					Copy(&buf[sizeof(MAC_HEADER)], &arp, sizeof(arp));

					EthPutPacket(eth, Clone(buf, MAC_HEADER_SIZE + sizeof(arp)), MAC_HEADER_SIZE + sizeof(arp));

					Free(buf);
				}

				m->next_arp_send_tick = now + (UINT64)m->Config->ArpInterval;
			}

			if (q != NULL)
			{
				PKT *pkt;
				UINT num = q->num_item;
				UCHAR **packet_array = ZeroMalloc(sizeof(void *) * num);
				UINT *packet_sizes = ZeroMalloc(sizeof(UINT) * num);
				UINT i = 0;

				while (pkt = GetNext(q))
				{
					UINT j;

					for (j = 0;j < m->Config->NumTargetIp;j++)
					{
						if (IsZero(m->Config->TargetMacList[j], 6) == false &&
							now <= (m->Config->TargetMacLastSeen[j] + (UINT64)m->Config->ArpTimeout))
						{
							UCHAR *data = Clone(pkt->PacketData, MAX(pkt->PacketSize, 14));
							UINT size = pkt->PacketSize;

							Copy(data, m->Config->TargetMacList[j], 6);
							Copy(data + 6, m->Config->OutputMac, 6);

							packet_array[i] = data;
							packet_sizes[i] = size;
							i++;
						}
					}

					FreePacketWithData(pkt);
				}

				EthPutPackets(eth, num, packet_array, packet_sizes);

				Free(packet_array);
				Free(packet_sizes);

				ReleaseQueue(q);
			}

			// Packet Receiver (for ARP response)
			while (true)
			{
				UCHAR *data;
				UINT size = EthGetPacket(eth, &data);
				if (size == INFINITE)
				{
					// Interface error
					EmLog(m, "EMLOG_ETH_GET_ERROR", if_name);

					CloseEth(eth);
					eth = NULL;
					num_open_fail = 0;

					Lock(m->Lock);
					{
						ReleaseCancel(m->SendCancel);
						m->SendCancel = NULL;
					}
					Unlock(m->Lock);

					break;
				}
				else if (size == 0)
				{
					// Wait for next packet
					Select(NULL, 10, m->SendCancel, NULL);
					break;
				}
				else
				{
					if (size >= 15)
					{
						if (Cmp(data, m->Config->OutputMac, 6) == 0)
						{
							PKT *rp = ParsePacket(data, size);

							if (rp != NULL)
							{
								if (rp->TypeL3 == L3_ARPV4 &&
									Endian16(rp->L3.ARPv4Header->Operation) == ARP_OPERATION_RESPONSE &&
									Endian16(rp->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
									Endian16(rp->L3.ARPv4Header->ProtocolType) == MAC_PROTO_IPV4 &&
									rp->L3.ARPv4Header->HardwareSize == 6 &&
									rp->L3.ARPv4Header->ProtocolSize == 4 &&
									IsZero(&rp->L3.ARPv4Header->SrcAddress, 6) == false &&
									IsMacBroadcast(rp->L3.ARPv4Header->SrcAddress) == false)
								{
									UINT i;

									for (i = 0;i < m->Config->NumTargetIp;i++)
									{
										if (IPToUINT(&m->Config->TargetIpList[i]) == rp->L3.ARPv4Header->SrcIP)
										{
											Copy(m->Config->TargetMacList[i], rp->L3.ARPv4Header->SrcAddress, 6);
											m->Config->TargetMacLastSeen[i] = now;
										}
									}
								}

								FreePacket(rp);
							}
						}
					}
					Free(data);
				}
			}
		}
	}

	Lock(m->Lock);
	{
		ReleaseCancel(m->SendCancel);
		m->SendCancel = NULL;
	}
	Unlock(m->Lock);

	CloseEth(eth);
	ReleaseCancel(m->SendCancel);
}

// Free the config
void EmFreeConfig(EM_CONFIG *c)
{
	if (c == NULL)
	{
		return;
	}

	Free(c);
}

// Load the config
EM_CONFIG *EmLoadConfig(char *fn)
{
	EM_CONFIG *c;
	LIST *o;
	char output_mac_str[64];
	char output_arp_src_ip_str[64];
	char output_target_ip_list_str[MAX_SIZE];
	bool ok = false;
	if (fn == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(EM_CONFIG));

	o = ReadIniFile(EM_CONFIG_FN);

	if (IniGetStr(o, "InputIf", c->InputIf, sizeof(c->InputIf)) == false ||
		IniGetStr(o, "OutputIf", c->OutputIf, sizeof(c->OutputIf)) == false ||
		IniGetStr(o, "OutputMac", output_mac_str, sizeof(output_mac_str)) == false ||
		IniGetStr(o, "OutputArpSrcIp", output_arp_src_ip_str, sizeof(output_arp_src_ip_str)) == false ||
		IniGetStr(o, "TargetIpList", output_target_ip_list_str, sizeof(output_target_ip_list_str)) == false)
	{}
	else
	{
		TOKEN_LIST *t;
		UINT i;

		c->ArpInterval = IniIntValue(o, "ArpInterval");
		c->ArpTimeout = IniIntValue(o, "ArpTimeout");

		c->ArpInterval = MAKESURE(c->ArpInterval, 1000, 3600 * 24 * 1000);
		c->ArpTimeout = MAKESURE(c->ArpTimeout, 1000, 3600 * 24 * 1000);

		t = ParseTokenWithoutNullStr(output_target_ip_list_str, ",; ");
		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				IP ip;

				if (StrToIP(&ip, t->Token[i]))
				{
					if (c->NumTargetIp < EM_MAX_TARGET_IP)
					{
						CopyIP(&c->TargetIpList[c->NumTargetIp], &ip);
						c->NumTargetIp++;
					}
				}
			}

			FreeToken(t);
		}

		if (StrToIP(&c->OutputArpSrc, output_arp_src_ip_str) &&
			StrToMac(c->OutputMac, output_mac_str))
		{
			ok = true;
		}
	}

	FreeIni(o);

	if (ok == false)
	{
		goto LABEL_ERROR;
	}

	return c;

LABEL_ERROR:

	EmFreeConfig(c);

	return NULL;
}

// Stop and free the EM instance
void FreeEm(EM *m)
{
	PKT *pkt;
	if (m == NULL)
	{
		return;
	}

	m->Halt = true;

	WaitThread(m->RecvThread, INFINITE);
	WaitThread(m->SendThread, INFINITE);

	ReleaseThread(m->RecvThread);
	ReleaseThread(m->SendThread);

	EmFreeConfig(m->Config);

	EmLog(m, "EMLOG_STOP");
	FreeLog(m->Log);

	while (pkt = GetNext(m->SendQueue))
	{
		FreePacketWithData(pkt);
	}

	ReleaseQueue(m->SendQueue);

	DeleteLock(m->Lock);

	Free(m);
}

// Start the EM instance
EM *NewEm()
{
	EM *m = ZeroMalloc(sizeof(EM));

	m->SendQueue = NewQueue();

	m->Lock = NewLock();

	// Logger
	m->Log = NewLog(EM_LOGDIR, EM_LOGPREFIX, LOG_SWITCH_DAY);

	EmLog(m, "EMLOG_START");

	// Load the log file
	EmLog(m, "EMLOG_CONFIG_LOADING");
	m->Config = EmLoadConfig(EM_CONFIG_FN);
	if (m->Config == NULL)
	{
		EmLog(m, "EMLOG_CONFIG_LOAD_ERROR");
	}
	else
	{
		EmLog(m, "EMLOG_CONFIG_LOAD_OK");

		// Start threads
		m->RecvThread = NewThread(EmRecvThread, m);
		m->SendThread = NewThread(EmSendThread, m);
	}

	return m;
}

void EmLog(EM *m, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (name == NULL || m == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", buf);
	}

	InsertUnicodeRecord(m->Log, buf);

	va_end(args);
}
