/*
Copyright (c) 2013-2019, 2021 The Linux Foundation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
		* Redistributions of source code must retain the above copyright
			notice, this list of conditions and the following disclaimer.
		* Redistributions in binary form must reproduce the above
			copyright notice, this list of conditions and the following
			disclaimer in the documentation and/or other materials provided
			with the distribution.
		* Neither the name of The Linux Foundation nor the names of its
			contributors may be used to endorse or promote products derived
			from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*!
	@file
	IPACM_Neighbor.cpp

	@brief
	This file implements the functionality of handling IPACM Neighbor events.

	@Author
	Skylar Chang

*/

#include <sys/ioctl.h>
#include <linux/if.h>
#include <IPACM_Neighbor.h>
#include <IPACM_EvtDispatcher.h>
#include "IPACM_Defs.h"
#include "IPACM_Log.h"

#define MAX_FDB_ROW_LEN 200
#define MAX_FDB_PARAM_CNT 5
#define MAX_FDB_PARAM_LEN 50
#define IPA_SYS_CMD_LEN 200
#define ETH_INTF "eth0"
#define RNDIS_INTF "rndis0"
#define ECM_INTF "ecm0"

#define IPA_TMP_DIR "/tmp/data"
#define IPA_FDB_TABLE IPA_TMP_DIR"/ipa_fdb_table.txt"
#define IPA_NO_IFACE_NAME "IFACE_NONE"

IPACM_Neighbor::IPACM_Neighbor()
{
	num_neighbor_client = 0;
	circular_index = 0;
	memset(neighbor_client, 0, IPA_MAX_NUM_NEIGHBOR_CLIENTS * sizeof(ipa_neighbor_client));
	IPACM_EvtDispatcher::registr(IPA_WLAN_CLIENT_ADD_EVENT_EX, this);
	IPACM_EvtDispatcher::registr(IPA_NEW_NEIGH_EVENT, this);
	IPACM_EvtDispatcher::registr(IPA_DEL_NEIGH_EVENT, this);

	return;
}

void IPACM_Neighbor::event_callback(ipa_cm_event_id event, void *param)
{
	ipacm_event_data_all *data_all = NULL;
#ifdef FEATURE_VLAN_MPDN
	ipacm_event_new_neigh_vlan *data_vlan = NULL;
#endif
	int i, ipa_interface_index;
	ipacm_cmd_q_data evt_data;
	int num_neighbor_client_temp = num_neighbor_client;

	IPACMDBG("Recieved event %d\n", event);

	switch (event)
	{
		case IPA_WLAN_CLIENT_ADD_EVENT_EX:
		{
			ipacm_event_data_wlan_ex *data = (ipacm_event_data_wlan_ex *)param;
			ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data->if_index);
			/* check for failure return */
			if (IPACM_FAILURE == ipa_interface_index) {
				IPACMERR("IPA_WLAN_CLIENT_ADD_EVENT_EX: not supported iface id: %d\n", data->if_index);
				break;
			}
			uint8_t client_mac_addr[6];
			memset(client_mac_addr,0,sizeof(client_mac_addr));

			IPACMDBG_H("Received IPA_WLAN_CLIENT_ADD_EVENT\n");
			for(i = 0; i < data->num_of_attribs; i++)
			{
				if(data->attribs[i].attrib_type == WLAN_HDR_ATTRIB_MAC_ADDR)
				{
					memcpy(client_mac_addr,
							data->attribs[i].u.mac_addr,
							sizeof(client_mac_addr));
					IPACMDBG_H("AP Mac Address %02x:%02x:%02x:%02x:%02x:%02x\n",
							 client_mac_addr[0], client_mac_addr[1], client_mac_addr[2],
							 client_mac_addr[3], client_mac_addr[4], client_mac_addr[5]);
				}
				else
				{
					IPACMDBG_H("The attribute type is not expected!\n");
				}
			}

			for (i = 0; i < num_neighbor_client_temp; i++)
			{
				/* find the client */
				if (memcmp(neighbor_client[i].mac_addr, client_mac_addr, sizeof(neighbor_client[i].mac_addr)) == 0)
				{
					/* check if iface is not bridge interface*/
					if (strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name) != 0)
					{
						/* use previous ipv4 first */
						if(data->if_index != neighbor_client[i].iface_index)
						{
							IPACMERR("update new kernel iface index \n");
							neighbor_client[i].iface_index = data->if_index;
						}

						/* check if client associated with previous network interface */
						if(ipa_interface_index != neighbor_client[i].ipa_if_num)
						{
							/* replacing the updated iface */
							IPACMERR("client associate to different AP, update to %s \n", IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name);
							neighbor_client[i].ipa_if_num = ipa_interface_index;
							strlcpy(neighbor_client[i].iface_name, IPACM_Iface::ipacmcfg->iface_table[ipa_interface_index].iface_name, sizeof(neighbor_client[i].iface_name));
						}

						if (neighbor_client[i].v4_addr != 0) /* not 0.0.0.0 */
						{
							/* check if getting real netdev name yet */
							if(strcmp(neighbor_client[i].iface_name, IPA_NO_IFACE_NAME) == 0)
							{
								IPACMERR("client %d name %s not real\n", i, neighbor_client[i].iface_name);
								return;
							}

							evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
							data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
							if (data_all == NULL)
							{
								IPACMERR("Unable to allocate memory\n");
								return;
							}
							memset(data_all,0,sizeof(ipacm_event_data_all));
							data_all->iptype = IPA_IP_v4;
							data_all->if_index = neighbor_client[i].iface_index;
							data_all->ipv4_addr = neighbor_client[i].v4_addr; //use previous ipv4 address
							memcpy(data_all->mac_addr,
									neighbor_client[i].mac_addr,
												sizeof(data_all->mac_addr));
							memcpy(data_all->iface_name, neighbor_client[i].iface_name,
								sizeof(data_all->iface_name));
							evt_data.evt_data = (void *)data_all;
							IPACM_EvtDispatcher::PostEvt(&evt_data);
							/* ask for replaced iface name*/
							ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data_all->if_index);
							/* check for failure return */
							if (IPACM_FAILURE == ipa_interface_index) {
								IPACMERR("not supported iface id: %d\n", data_all->if_index);
							} else {
								IPACMDBG_H("Posted event %d, with %s for ipv4 client re-connect\n",
									evt_data.event,
									data_all->iface_name);
							}
						}
					}
					break;
				}
			}
		}
		break;

		default:
		{
			if (event == IPA_NEW_NEIGH_EVENT)
			{
				IPACMDBG_H("Received IPA_NEW_NEIGH_EVENT\n");
			}
			else
			{
				IPACMDBG_H("Received IPA_DEL_NEIGH_EVENT\n");
			}

			ipacm_event_data_all *data = (ipacm_event_data_all *)param;
			ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data->if_index);
#if !defined(FEATURE_L2TP) && !defined(FEATURE_VLAN_MPDN)
			/* check for failure return */
			if (IPACM_FAILURE == ipa_interface_index) {
				IPACMERR("not supported iface id: %d\n", data->if_index);
				break;
			}
#endif
#ifdef FEATURE_VLAN_MPDN
			if(IPACM_FAILURE != ipa_interface_index && (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE))
			{
				if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(data->iface_name))
				{
					IPACMDBG_H("ignoring physical IFACE neighbor event in VLAN mode\n");
					break;
				}
			}
#endif
			if (data->iptype == IPA_IP_v4)
			{
				if (data->ipv4_addr != 0) /* not 0.0.0.0 */
				{
					IPACMDBG("Got Neighbor event with ipv4 address: 0x%x \n", data->ipv4_addr);
					/* check if ipv4 address is link local(169.254.xxx.xxx) */
					if ((data->ipv4_addr & IPV4_ADDR_LINKLOCAL_MASK) == IPV4_ADDR_LINKLOCAL)
					{
						IPACMDBG_H("This is link local ipv4 address: 0x%x : ignore this NEIGH_EVENT\n", data->ipv4_addr);
						return;
					}
					/* check if iface is bridge interface*/
#ifdef FEATURE_VLAN_MPDN
					/* VLAN clients don't have to be on bridge0 */
					if (((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) && strstr(data->iface_name, "bridge")) ||
						(((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
						(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
						(strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, data->iface_name) == 0)))
#else
					if (strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, data->iface_name) == 0)
#endif
					{
#ifdef FEATURE_VLAN_MPDN
						ipacm_bridge *bridge;
						if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
						{
							bridge = IPACM_Iface::ipacmcfg->get_vlan_bridge(data->iface_name);
							if(!bridge)
							{
								IPACMDBG("couldn't find the bridge %s, trying to add\n", data->iface_name);
								/* since we know that this is a bridge, let's try to add */
								IPACM_Iface::ipacmcfg->add_vlan_bridge(data);
								bridge = IPACM_Iface::ipacmcfg->get_vlan_bridge(data->iface_name);
								if(!bridge)
								{
									IPACMERR("couldn't find or add bridge %s, not sending internal event\n", data->iface_name);
									return;
								}
							}
						}
#endif
						/* search if seen this client or not*/
						for (i = 0; i < num_neighbor_client_temp; i++)
						{
							if (memcmp(neighbor_client[i].mac_addr, data->mac_addr, sizeof(neighbor_client[i].mac_addr)) == 0)
							{
#ifdef FEATURE_VLAN_MPDN
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
								{
									if(neighbor_client[i].bridge)
									{
										if(neighbor_client[i].bridge != bridge)
										{
											IPACMERR("client (dev %s) already associated with a different bridge %s->%s, keep looking for same MAC\n",
												neighbor_client[i].iface_name,
												neighbor_client[i].bridge->bridge_name,
												bridge->bridge_name);
											continue;
										}
									}
									else
									{
										/* for VLAN interfaces make sure bridge is with correct VID */
										if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(neighbor_client[i].iface_name))
										{
											uint16_t vlan_id;
											if(IPACM_Iface::ipacmcfg->get_vlan_id(neighbor_client[i].iface_name, &vlan_id))
											{
												IPACMERR("failed to get iface vlan ID, skipping\n");
												continue;
											}
											if(bridge->associate_VID != vlan_id)
											{
												IPACMDBG("client bridge vid mismatch (%d)(%d), skip\n",
													vlan_id, bridge->associate_VID);
												continue;
											}
											IPACMDBG_H("client - bridge vid match (%d)\n", vlan_id);
										}
									}
								}
#endif
								IPACMDBG_H("Iface name:%s\n", data->iface_name);
								IPACMDBG_H("found client %d, MAC %02x:%02x:%02x:%02x:%02x:%02x, total client: %d\n",
												i,
												neighbor_client[i].mac_addr[0],
												neighbor_client[i].mac_addr[1],
												neighbor_client[i].mac_addr[2],
												neighbor_client[i].mac_addr[3],
												neighbor_client[i].mac_addr[4],
												neighbor_client[i].mac_addr[5],
												num_neighbor_client);

								data->if_index = neighbor_client[i].iface_index;
								strlcpy(data->iface_name, neighbor_client[i].iface_name, sizeof(data->iface_name));
								neighbor_client[i].v4_addr = data->ipv4_addr; // cache client's previous ipv4 address
								/* check if getting real netdev name yet */
								if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
								{
									IPACMERR("client %d name %s not real\n", i, data->iface_name);
									return;
								}
								/* construct IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT command and insert to command-queue */
								if (event == IPA_NEW_NEIGH_EVENT)
									evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
								else
									/* not to clean-up the client mac cache on bridge0 delneigh */
									evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT;
#ifdef FEATURE_VLAN_MPDN
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
								{
									data_vlan = (ipacm_event_new_neigh_vlan *)malloc(sizeof(ipacm_event_new_neigh_vlan));
									if(data_vlan == NULL)
									{
										IPACMERR("Unable to allocate memory\n");
										return;
									}
									memcpy(&data_vlan->data_all, data, sizeof(ipacm_event_data_all));
									data_vlan->bridge = bridge;
									neighbor_client[i].bridge = bridge;
									evt_data.evt_data = (void *)data_vlan;
									data_all = (ipacm_event_data_all *)data_vlan;
								}
								else
								{
									if (IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP ||
										IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)
									{
										data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
										if (data_all == NULL)
										{
											IPACMERR("Unable to allocate memory\n");
											return;
										}
										memcpy(data_all, data, sizeof(ipacm_event_data_all));
										evt_data.evt_data = (void *)data_all;
									}
								}
#else
								data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
								if (data_all == NULL)
								{
									IPACMERR("Unable to allocate memory\n");
									return;
								}
								memcpy(data_all, data, sizeof(ipacm_event_data_all));
								evt_data.evt_data = (void *)data_all;
#endif
								IPACM_EvtDispatcher::PostEvt(&evt_data);

								/* ask for replaced iface name*/
								ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data_all->if_index);
								/* check for failure return */
								if (IPACM_FAILURE == ipa_interface_index) {
#ifndef FEATURE_VLAN_MPDN
									IPACMERR("not supported iface id: %d\n", data_all->if_index);
#else
									IPACMDBG_H("Posted event %d with %s for ipv4\n",
										evt_data.event, data->iface_name);
#endif
								} else {
									IPACMDBG_H("Posted event %d with %s for ipv4\n",
										evt_data.event, data->iface_name);
								}
								break;
							}
						}
						/* Cache the neighbor event from bridgeX as well if physical netdev can't find */
						if (i == num_neighbor_client_temp)
						{
							IPACMDBG_H("Cant find ipv4 neighbor client with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
								data->mac_addr[0], data->mac_addr[1], data->mac_addr[2],
								data->mac_addr[3], data->mac_addr[4], data->mac_addr[5]);

							if (num_neighbor_client_temp < IPA_MAX_NUM_NEIGHBOR_CLIENTS)
							{
								memcpy(neighbor_client[num_neighbor_client_temp].mac_addr,
											data->mac_addr,
											sizeof(data->mac_addr));
								neighbor_client[num_neighbor_client_temp].iface_index = data->if_index;
								/* cache the network interface client associated */
								neighbor_client[num_neighbor_client_temp].ipa_if_num = ipa_interface_index;
								neighbor_client[num_neighbor_client_temp].v4_addr = data->ipv4_addr;
#ifdef FEATURE_VLAN_MPDN
								if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
									neighbor_client[num_neighbor_client_temp].bridge = bridge;
#endif

								IPACMDBG_H("Iface name:%s\n", data->iface_name);
								/* use IPA_NO_IFACE_NAME for handling out-of-order sequence issue */
								strlcpy(neighbor_client[num_neighbor_client_temp].iface_name, IPA_NO_IFACE_NAME,
									sizeof(neighbor_client[num_neighbor_client_temp].iface_name));

								num_neighbor_client++;
								IPACMDBG_H("Copy client MAC %02x:%02x:%02x:%02x:%02x:%02x, total client: %d\n",
												neighbor_client[num_neighbor_client_temp].mac_addr[0],
												neighbor_client[num_neighbor_client_temp].mac_addr[1],
												neighbor_client[num_neighbor_client_temp].mac_addr[2],
												neighbor_client[num_neighbor_client_temp].mac_addr[3],
												neighbor_client[num_neighbor_client_temp].mac_addr[4],
												neighbor_client[num_neighbor_client_temp].mac_addr[5],
												num_neighbor_client);
								return;
							}
							else
							{
								IPACMERR("error:  neighbor client oversize! recycle %d-st entry ! \n", circular_index);
								memcpy(neighbor_client[circular_index].mac_addr,
											data->mac_addr,
											sizeof(data->mac_addr));
								neighbor_client[circular_index].iface_index = data->if_index;
								/* cache the network interface client associated */
								neighbor_client[circular_index].ipa_if_num = ipa_interface_index;
								neighbor_client[circular_index].v4_addr = data->ipv4_addr;
#ifdef FEATURE_VLAN_MPDN
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
									neighbor_client[circular_index].bridge = bridge;
#endif
								/* use IPA_NO_IFACE_NAME for handling out-of-order sequence issue */
								strlcpy(neighbor_client[circular_index].iface_name, IPA_NO_IFACE_NAME,
									sizeof(neighbor_client[circular_index].iface_name));

								IPACMDBG_H("Copy wlan-iface client MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %d, circular %d\n",
												neighbor_client[circular_index].mac_addr[0],
												neighbor_client[circular_index].mac_addr[1],
												neighbor_client[circular_index].mac_addr[2],
												neighbor_client[circular_index].mac_addr[3],
												neighbor_client[circular_index].mac_addr[4],
												neighbor_client[circular_index].mac_addr[5],
												num_neighbor_client,
												circular_index);
								circular_index = (circular_index + 1) % IPA_MAX_NUM_NEIGHBOR_CLIENTS;
								return;
							}
						}
					}
					else
					{
						/* construct IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT command and insert to command-queue */
						if(event == IPA_NEW_NEIGH_EVENT)
						{
#if defined(FEATURE_VLAN_MPDN) || defined(FEATURE_L2TP)
							if(IPACM_FAILURE == ipa_interface_index)
							{
								IPACMDBG_H("non bridged VLAN interface %s, ignoring\n", data->iface_name);
								return;
							}
#endif
							evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
							/* Also save to cache for ipv4 */
							/*search if seen this client or not*/
							for (i = 0; i < num_neighbor_client_temp; i++)
							{
								/* find the client */
								if (memcmp(neighbor_client[i].mac_addr, data->mac_addr, sizeof(neighbor_client[i].mac_addr)) == 0)
								{
									/* update the network interface client associated */
									neighbor_client[i].iface_index = data->if_index;
									neighbor_client[i].ipa_if_num = ipa_interface_index;
									neighbor_client[i].v4_addr = data->ipv4_addr; // cache client's previous ipv4 address
									strlcpy(neighbor_client[i].iface_name, data->iface_name, sizeof(neighbor_client[i].iface_name));
									IPACMDBG_H("update cache %d-entry, with %s iface, ipv4 address: 0x%x\n",
										i, data->iface_name, data->ipv4_addr);
									break;
								}
							}
							/* not find client */
							if (i == num_neighbor_client_temp)
							{
								if (num_neighbor_client_temp < IPA_MAX_NUM_NEIGHBOR_CLIENTS)
								{
									memcpy(neighbor_client[num_neighbor_client_temp].mac_addr,
												data->mac_addr,
												sizeof(data->mac_addr));
									neighbor_client[num_neighbor_client_temp].iface_index = data->if_index;
									/* cache the network interface client associated */
									neighbor_client[num_neighbor_client_temp].ipa_if_num = ipa_interface_index;
									neighbor_client[num_neighbor_client_temp].v4_addr = data->ipv4_addr;
#ifdef FEATURE_VLAN_MPDN
									if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
										neighbor_client[num_neighbor_client_temp].bridge = NULL;
#endif
									strlcpy(neighbor_client[num_neighbor_client_temp].iface_name,
										data->iface_name, sizeof(neighbor_client[num_neighbor_client_temp].iface_name));
									num_neighbor_client++;
									IPACMDBG_H("Cache client MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %d\n",
												neighbor_client[num_neighbor_client_temp].mac_addr[0],
												neighbor_client[num_neighbor_client_temp].mac_addr[1],
												neighbor_client[num_neighbor_client_temp].mac_addr[2],
												neighbor_client[num_neighbor_client_temp].mac_addr[3],
												neighbor_client[num_neighbor_client_temp].mac_addr[4],
												neighbor_client[num_neighbor_client_temp].mac_addr[5],
												num_neighbor_client);
								}
								else
								{

									IPACMERR("error:  neighbor client oversize! recycle %d-st entry ! \n", circular_index);
									memcpy(neighbor_client[circular_index].mac_addr,
												data->mac_addr,
												sizeof(data->mac_addr));
									neighbor_client[circular_index].iface_index = data->if_index;
									/* cache the network interface client associated */
									neighbor_client[circular_index].ipa_if_num = ipa_interface_index;
									neighbor_client[circular_index].v4_addr = 0;
#ifdef FEATURE_VLAN_MPDN
									if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
										neighbor_client[circular_index].bridge = NULL;
#endif
									strlcpy(neighbor_client[circular_index].iface_name,
										data->iface_name, sizeof(neighbor_client[circular_index].iface_name));
									IPACMDBG_H("Copy wlan-iface client MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %d, circular %d\n",
													neighbor_client[circular_index].mac_addr[0],
													neighbor_client[circular_index].mac_addr[1],
													neighbor_client[circular_index].mac_addr[2],
													neighbor_client[circular_index].mac_addr[3],
													neighbor_client[circular_index].mac_addr[4],
													neighbor_client[circular_index].mac_addr[5],
													num_neighbor_client,
													circular_index);
									circular_index = (circular_index + 1) % IPA_MAX_NUM_NEIGHBOR_CLIENTS;
								}
							}
						}
						else
						{
							evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT;
							/*searh if seen this client or not*/
							for (i = 0; i < num_neighbor_client_temp; i++)
							{
								/* find the client */
								if (memcmp(neighbor_client[i].mac_addr, data->mac_addr, sizeof(neighbor_client[i].mac_addr)) == 0)
								{
#ifdef FEATURE_VLAN_MPDN
									if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
									{
										/* for VLAN interfaces make sure this is the correct interface */
										if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(neighbor_client[i].iface_name))
										{
											if(strcmp(neighbor_client[i].iface_name, data->iface_name) != 0)
											{
												IPACMDBG_H("IP_ADDR_DEL_EVENT: MAC match but iface name is different %s <-> %s, skip\n",
													data->iface_name, neighbor_client[i].iface_name);
												continue;
											}
										}
									}
#endif
									IPACMDBG_H("Clean %d-st Cached client-MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %d\n",
												i,
												neighbor_client[i].mac_addr[0],
												neighbor_client[i].mac_addr[1],
												neighbor_client[i].mac_addr[2],
												neighbor_client[i].mac_addr[3],
												neighbor_client[i].mac_addr[4],
												neighbor_client[i].mac_addr[5],
												num_neighbor_client);

									for (; i < num_neighbor_client_temp - 1; i++)
									{
										memcpy(neighbor_client[i].mac_addr,
													neighbor_client[i+1].mac_addr,
													sizeof(neighbor_client[i].mac_addr));
#ifdef FEATURE_VLAN_MPDN
										if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
											neighbor_client[i].bridge = neighbor_client[i + 1].bridge;
#endif
										neighbor_client[i].iface_index = neighbor_client[i+1].iface_index;
										neighbor_client[i].v4_addr = neighbor_client[i+1].v4_addr;
										neighbor_client[i].ipa_if_num = neighbor_client[i+1].ipa_if_num;
										strlcpy(neighbor_client[i].iface_name, neighbor_client[i+1].iface_name,
											sizeof(neighbor_client[i].iface_name));
									}
									memset(neighbor_client[i].mac_addr, 0, sizeof(neighbor_client[i].mac_addr));
									neighbor_client[i].iface_index = 0;
									neighbor_client[i].v4_addr = 0;
									neighbor_client[i].ipa_if_num = 0;
									memset(neighbor_client[i].iface_name, 0, sizeof(neighbor_client[i].iface_name));
#ifdef FEATURE_VLAN_MPDN
									if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
										neighbor_client[i].bridge = NULL;
#endif

									num_neighbor_client--;
									IPACMDBG_H(" total number of left cased clients: %d\n", num_neighbor_client);
									break;
								}
							}
							/* not find client, no need clean-up */
						}
						/* check if getting real netdev name yet */
						if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
						{
							IPACMERR("client %d name %s not real\n", i, data->iface_name);
							return;
						}

						data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
						if (data_all == NULL)
						{
							IPACMERR("Unable to allocate memory\n");
							return;
						}
						memcpy(data_all, data, sizeof(ipacm_event_data_all));
						evt_data.evt_data = (void *)data_all;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						IPACMDBG_H("Posted event %d with %s for ipv4\n",
							evt_data.event, data->iface_name);
					}
				}
			}
			else
			{   //ipv6 starts

				if ((data->ipv6_addr[0]) || (data->ipv6_addr[1]) || (data->ipv6_addr[2]) || (data->ipv6_addr[3]))
				{
					IPACMDBG("Got New_Neighbor event with ipv6 address \n");
					/* check if iface is bridge interface*/
#ifdef FEATURE_VLAN_MPDN
					/* VLAN clients don't have to be on bridge0 */
					if (strstr(data->iface_name, "bridge"))
#else
					if (strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, data->iface_name) == 0)
#endif
					{
#ifdef FEATURE_VLAN_MPDN
						ipacm_bridge *bridge;
						if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
						{
							bridge = IPACM_Iface::ipacmcfg->get_vlan_bridge(data->iface_name);
							if(!bridge)
							{
								IPACMDBG("couldn't find the bridge %s, trying to add\n", data->iface_name);
								/* since we know that this is a bridge, let's try to add */
								IPACM_Iface::ipacmcfg->add_vlan_bridge(data);
								bridge = IPACM_Iface::ipacmcfg->get_vlan_bridge(data->iface_name);
								if(!bridge)
								{
									IPACMERR("couldn't find or add bridge %s, not sending internal event\n", data->iface_name);
									return;
								}
							}
						}
#endif
						/* search if seen this client or not*/
						for (i = 0; i < num_neighbor_client_temp; i++)
						{
							if (memcmp(neighbor_client[i].mac_addr, data->mac_addr, sizeof(neighbor_client[i].mac_addr)) == 0)
							{
#ifdef FEATURE_VLAN_MPDN
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
								{
									if(neighbor_client[i].bridge)
									{
										if(neighbor_client[i].bridge != bridge)
										{
											IPACMERR("client (dev %s) already associated with a different bridge %s->%s, keep looking for same MAC\n",
												neighbor_client[i].iface_name,
												neighbor_client[i].bridge->bridge_name,
												bridge->bridge_name);
											continue;
										}
									}
									else
									{
										/* for VLAN interfaces make sure bridge is with correct VID */
										if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(neighbor_client[i].iface_name))
										{
											uint16_t vlan_id;
											if(IPACM_Iface::ipacmcfg->get_vlan_id(neighbor_client[i].iface_name, &vlan_id))
											{
												IPACMERR("failed to get iface vlan ID, skipping\n");
												continue;
											}
											if(bridge->associate_VID != vlan_id)
											{
												IPACMDBG("client bridge vid mismatch (%d)(%d), skip\n",
													vlan_id, bridge->associate_VID);
												continue;
											}
											IPACMDBG_H("client - bridge vid match (%d)\n", vlan_id);
										}
									}
								}
#endif
								data->if_index = neighbor_client[i].iface_index;
								strlcpy(data->iface_name, neighbor_client[i].iface_name, sizeof(data->iface_name));
								/* check if getting real netdev name yet */
								if(strcmp(data->iface_name, IPA_NO_IFACE_NAME) == 0)
								{
									IPACMERR("client %d name %s not real\n", i, data->iface_name);
									return;
								}
								/* construct IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT command and insert to command-queue */
								if(event == IPA_NEW_NEIGH_EVENT)
									evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
								else
									evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT;
#ifdef FEATURE_VLAN_MPDN
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
								{
									data_vlan = (ipacm_event_new_neigh_vlan *)malloc(sizeof(ipacm_event_new_neigh_vlan));
									if(data_vlan == NULL)
									{
										IPACMERR("Unable to allocate memory\n");
										return;
									}
									memcpy(&data_vlan->data_all, data, sizeof(ipacm_event_data_all));
									data_vlan->bridge = bridge;
									neighbor_client[i].bridge = bridge;
									evt_data.evt_data = (void *)data_vlan;
									data_all = (ipacm_event_data_all *)data_vlan;
								}
								else
								{
									data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
									if (data_all == NULL)
									{
										IPACMERR("Unable to allocate memory\n");
										return;
									}
									memcpy(data_all, data, sizeof(ipacm_event_data_all));
									evt_data.evt_data = (void *)data_all;
								}
#else
								data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
								if (data_all == NULL)
								{
									IPACMERR("Unable to allocate memory\n");
									return;
								}
								memcpy(data_all, data, sizeof(ipacm_event_data_all));
								evt_data.evt_data = (void *)data_all;
#endif
								IPACM_EvtDispatcher::PostEvt(&evt_data);
								/* ask for replaced iface name*/
								ipa_interface_index = IPACM_Iface::iface_ipa_index_query(data_all->if_index);
								/* check for failure return */
								if (IPACM_FAILURE == ipa_interface_index) {
#if !defined(FEATURE_VLAN_MPDN) && !defined(FEATURE_L2TP)
									IPACMERR("not supported iface id: %d\n", data_all->if_index);
#else
									IPACMDBG_H("Posted event %d, with %s for ipv6\n",
										evt_data.event, data->iface_name);
#endif
								} else {
									IPACMDBG_H("Posted event %d with %s for ipv6\n",
										evt_data.event, data->iface_name);
								}
								break;
							}
						}
					}
					else
					{
						/* construct IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT command and insert to command-queue */
						if (event == IPA_NEW_NEIGH_EVENT)
							evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
						else
							evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT;
						data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
						if (data_all == NULL)
						{
							IPACMERR("Unable to allocate memory\n");
							return;
						}
						memcpy(data_all, data, sizeof(ipacm_event_data_all));
						evt_data.evt_data = (void *)data_all;
						IPACM_EvtDispatcher::PostEvt(&evt_data);
						IPACMDBG_H("Posted event %d with %s for ipv6 (%d)\n",
							evt_data.event, data_all->iface_name, data_all->iptype);
					}
				}
				else
				{
					IPACMDBG(" Got Neighbor event with no ipv6/ipv4 address \n");
					/*no ipv6 in data search if seen this client or not*/
					for (i = 0; i < num_neighbor_client_temp; i++)
					{
						/* find the client */
						if (memcmp(neighbor_client[i].mac_addr, data->mac_addr, sizeof(neighbor_client[i].mac_addr)) == 0)
						{
							IPACMDBG_H("Iface name:%s\n", data->iface_name);
							IPACMDBG_H("found client %d, MAC %02x:%02x:%02x:%02x:%02x:%02x, total client: %d\n",
												i,
												neighbor_client[i].mac_addr[0],
												neighbor_client[i].mac_addr[1],
												neighbor_client[i].mac_addr[2],
												neighbor_client[i].mac_addr[3],
												neighbor_client[i].mac_addr[4],
												neighbor_client[i].mac_addr[5],
												num_neighbor_client);
							/* check if iface is not bridge interface*/
#ifdef FEATURE_VLAN_MPDN
							/* VLAN clients don't have to be on bridge0 */
							if (((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) && !strstr(data->iface_name, "bridge")) ||
								(((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
								(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
								(strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, data->iface_name) != 0)))
#else
							if (strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, data->iface_name) != 0)
#endif
							{
#ifdef FEATURE_VLAN_MPDN
								/* VLAN interface && not the same iface name */
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE && IPACM_FAILURE == ipa_interface_index)
								{
									/* for this case we cached the neigh event from bridgeX where it won't have iface_name */
									if(strcmp(neighbor_client[i].iface_name, IPA_NO_IFACE_NAME) == 0)
									{
										/* for VLAN interfaces make sure bridge is with correct VID */
										if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(data->iface_name))
										{
											uint16_t vlan_id;
											if(IPACM_Iface::ipacmcfg->get_vlan_id(data->iface_name, &vlan_id))
											{
												IPACMERR("failed to get iface vlan ID, skipping\n");
												continue;
											}
											if(neighbor_client[i].bridge->associate_VID != vlan_id)
											{
												IPACMDBG("client bridge vid mismatch (%d)(%d), skip\n",
													vlan_id, neighbor_client[i].bridge->associate_VID);
												continue;
											}
											IPACMDBG_H("client - bridge vid match (%d)\n", vlan_id);
										}
									}
									else if (strcmp(neighbor_client[i].iface_name, data->iface_name) != 0)
									{
										IPACMDBG_H("VLAN interface name (%s) is different (%s): keep looking\n",
											neighbor_client[i].iface_name, data->iface_name);
										continue;
									}
								}
#endif
								/* use previous ipv4 first */
								if(data->if_index != neighbor_client[i].iface_index)
								{
									IPACMDBG_H("update new kernel iface index \n");
									neighbor_client[i].iface_index = data->if_index;
									strlcpy(neighbor_client[i].iface_name, data->iface_name, sizeof(neighbor_client[i].iface_name));
								}

								/* check if client associated with previous network interface */
								if(ipa_interface_index != neighbor_client[i].ipa_if_num)
								{
									/* replacing the updated iface */
									IPACMDBG_H("client associate to different AP %s\n", data->iface_name);
									neighbor_client[i].ipa_if_num = ipa_interface_index;
									strlcpy(neighbor_client[i].iface_name, data->iface_name, sizeof(neighbor_client[i].iface_name));
								}

								if (neighbor_client[i].v4_addr != 0) /* not 0.0.0.0 */
								{
									/* check if getting real netdev name yet */
									if(strcmp(neighbor_client[i].iface_name, IPA_NO_IFACE_NAME) == 0)
									{
										IPACMERR("client %d name %s not real\n", i, neighbor_client[i].iface_name);
										return;
									}
									/* construct IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT command and insert to command-queue */
									if (event == IPA_NEW_NEIGH_EVENT)
										evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_ADD_EVENT;
									else
										evt_data.event = IPA_NEIGH_CLIENT_IP_ADDR_DEL_EVENT;
#ifdef FEATURE_VLAN_MPDN
									if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
									{
										data_vlan = (ipacm_event_new_neigh_vlan *)malloc(sizeof(ipacm_event_new_neigh_vlan));
										if(data_vlan == NULL)
										{
											IPACMERR("Unable to allocate memory\n");
											return;
										}
										data_vlan->data_all.iptype = IPA_IP_v4;
										data_vlan->data_all.if_index = neighbor_client[i].iface_index;
										data_vlan->data_all.ipv4_addr = neighbor_client[i].v4_addr; //use previous ipv4 address
										memcpy(data_vlan->data_all.mac_addr, neighbor_client[i].mac_addr,
											sizeof(data_vlan->data_all.mac_addr));
										strlcpy(data_vlan->data_all.iface_name, neighbor_client[i].iface_name,
											sizeof(data_vlan->data_all.iface_name));
										data_vlan->bridge = neighbor_client[i].bridge;
										evt_data.evt_data = (void *)data_vlan;
										data_all = (ipacm_event_data_all *)data_vlan;
									}
									else
									{
										data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
										if (data_all == NULL)
										{
											IPACMERR("Unable to allocate memory\n");
											return;
										}
										data_all->iptype = IPA_IP_v4;
										data_all->if_index = neighbor_client[i].iface_index;
										data_all->ipv4_addr = neighbor_client[i].v4_addr; //use previous ipv4 address
										memcpy(data_all->mac_addr, neighbor_client[i].mac_addr,
											sizeof(data_all->mac_addr));
										strlcpy(data_all->iface_name, neighbor_client[i].iface_name, sizeof(data_all->iface_name));
										evt_data.evt_data = (void *)data_all;
									}
#else
									data_all = (ipacm_event_data_all *)malloc(sizeof(ipacm_event_data_all));
									if (data_all == NULL)
									{
										IPACMERR("Unable to allocate memory\n");
										return;
									}
									data_all->iptype = IPA_IP_v4;
									data_all->if_index = neighbor_client[i].iface_index;
									data_all->ipv4_addr = neighbor_client[i].v4_addr; //use previous ipv4 address
									memcpy(data_all->mac_addr, neighbor_client[i].mac_addr,
										sizeof(data_all->mac_addr));
									strlcpy(data_all->iface_name, neighbor_client[i].iface_name, sizeof(data_all->iface_name));
									evt_data.evt_data = (void *)data_all;
#endif
									IPACM_EvtDispatcher::PostEvt(&evt_data);
									IPACMDBG_H("Posted event %d with %s for ipv4\n",
										evt_data.event, data_all->iface_name);
								}
							}
							/* delete cache neighbor entry */
							if (event == IPA_DEL_NEIGH_EVENT)
							{
								IPACMDBG_H("Clean %d-st Cached client-MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %d\n",
										i,
										neighbor_client[i].mac_addr[0],
										neighbor_client[i].mac_addr[1],
										neighbor_client[i].mac_addr[2],
										neighbor_client[i].mac_addr[3],
										neighbor_client[i].mac_addr[4],
										neighbor_client[i].mac_addr[5],
										num_neighbor_client);

								for (; i < num_neighbor_client_temp - 1; i++)
								{
									memcpy(neighbor_client[i].mac_addr,
												neighbor_client[i+1].mac_addr,
												sizeof(neighbor_client[i].mac_addr));
#ifdef FEATURE_VLAN_MPDN
									neighbor_client[i].bridge = neighbor_client[i + 1].bridge;
#endif
									neighbor_client[i].iface_index = neighbor_client[i+1].iface_index;
									neighbor_client[i].v4_addr = neighbor_client[i+1].v4_addr;
									neighbor_client[i].ipa_if_num = neighbor_client[i+1].ipa_if_num;
									strlcpy(neighbor_client[i].iface_name, neighbor_client[i+1].iface_name,
										sizeof(neighbor_client[i].iface_name));
								}
								memset(neighbor_client[i].mac_addr, 0, sizeof(neighbor_client[i].mac_addr));
								neighbor_client[i].iface_index = 0;
								neighbor_client[i].v4_addr = 0;
								neighbor_client[i].ipa_if_num = 0;
								memset(neighbor_client[i].iface_name, 0, sizeof(neighbor_client[i].iface_name));
#ifdef FEATURE_VLAN_MPDN
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
									neighbor_client[i].bridge = NULL;
#endif
								num_neighbor_client--;
								IPACMDBG_H(" total number of left cased clients: %d\n", num_neighbor_client);
							}
							break;
						}
					}
					/* not find client */
					if ((i == num_neighbor_client_temp) && (event == IPA_NEW_NEIGH_EVENT))
					{
						/* check if iface is not bridge interface*/
#ifdef FEATURE_VLAN_MPDN
						/* VLAN clients don't have to be on bridge0 */
						if (((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) && !strstr(data->iface_name, "bridge")) ||
							(((IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP) ||
							(IPACM_Iface::ipacmcfg->ipacm_l2tp_enable == IPACM_L2TP_E2E)) &&
							(strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, data->iface_name) != 0)))
#else
						if (strcmp(IPACM_Iface::ipacmcfg->ipa_virtual_iface_name, data->iface_name) != 0)
#endif
						{
#ifdef FEATURE_VLAN_MPDN
							/* if this is a vlan interface that was not added we ignore*/
							if((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) &&
								(IPACM_FAILURE == ipa_interface_index) &&
								(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(data->iface_name)) &&
								!(IPACM_Iface::ipacmcfg->is_added_vlan_iface(data->iface_name)))
							{
								IPACMDBG_H("not added VLAN interface %s, ignoring\n", data->iface_name);
								return;
							}
#endif
							if (num_neighbor_client_temp < IPA_MAX_NUM_NEIGHBOR_CLIENTS)
							{
								memcpy(neighbor_client[num_neighbor_client_temp].mac_addr,
											data->mac_addr,
											sizeof(data->mac_addr));
								neighbor_client[num_neighbor_client_temp].iface_index = data->if_index;
								/* cache the network interface client associated */
								neighbor_client[num_neighbor_client_temp].ipa_if_num = ipa_interface_index;
								neighbor_client[num_neighbor_client_temp].v4_addr = 0;
#ifdef FEATURE_VLAN_MPDN
								if (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
									neighbor_client[num_neighbor_client_temp].bridge = NULL;
#endif
								strlcpy(neighbor_client[num_neighbor_client_temp].iface_name, data->iface_name,
									sizeof(neighbor_client[num_neighbor_client_temp].iface_name));
								IPACMDBG_H("Iface name:%s\n", data->iface_name);
								num_neighbor_client++;
								IPACMDBG_H("Copy client MAC %02x:%02x:%02x:%02x:%02x:%02x, total client: %d\n",
												neighbor_client[num_neighbor_client_temp].mac_addr[0],
												neighbor_client[num_neighbor_client_temp].mac_addr[1],
												neighbor_client[num_neighbor_client_temp].mac_addr[2],
												neighbor_client[num_neighbor_client_temp].mac_addr[3],
												neighbor_client[num_neighbor_client_temp].mac_addr[4],
												neighbor_client[num_neighbor_client_temp].mac_addr[5],
												num_neighbor_client);
								return;
							}
							else
							{
								IPACMERR("error:  neighbor client oversize! recycle %d-st entry ! \n", circular_index);
								memcpy(neighbor_client[circular_index].mac_addr,
											data->mac_addr,
											sizeof(data->mac_addr));
								neighbor_client[circular_index].iface_index = data->if_index;
								/* cache the network interface client associated */
								neighbor_client[circular_index].ipa_if_num = ipa_interface_index;
								neighbor_client[circular_index].v4_addr = 0;
#ifdef FEATURE_VLAN_MPDN
								if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
									neighbor_client[circular_index].bridge = NULL;
#endif
								strlcpy(neighbor_client[circular_index].iface_name, data->iface_name,
									sizeof(neighbor_client[circular_index].iface_name));
								IPACMDBG_H("Copy wlan-iface client MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %d, circular %d\n",
												neighbor_client[circular_index].mac_addr[0],
												neighbor_client[circular_index].mac_addr[1],
												neighbor_client[circular_index].mac_addr[2],
												neighbor_client[circular_index].mac_addr[3],
												neighbor_client[circular_index].mac_addr[4],
												neighbor_client[circular_index].mac_addr[5],
												num_neighbor_client,
												circular_index);
								circular_index = (circular_index + 1) % IPA_MAX_NUM_NEIGHBOR_CLIENTS;
								return;
							}
						}
					}
				}
			} //ipv6 ends
		}
		break;
	}
	return;
}

void IPACM_Neighbor::update_neigh_cache()
{
	FILE *fp = NULL;
	char *tok = NULL, *ptr = NULL;
	char *params[MAX_FDB_PARAM_CNT] = { NULL };
	char rdev_name[IPA_IFACE_NAME_LEN] = {0}, mac[MAX_FDB_PARAM_LEN] = {0};
	char fdb_row[MAX_FDB_ROW_LEN] = {0}, cmd[IPA_SYS_CMD_LEN] = {0};
	uint8_t mac_addr_fdb[IPA_MAC_ADDR_SIZE] = {0};
	int tmp_var[IPA_MAC_ADDR_SIZE];
	int query_ifindex, query_ipa_if_num, j, i;
	bool is_phy_iface = false, is_client_cached = false, parse_error = false;;

	snprintf(cmd, IPA_SYS_CMD_LEN, "bridge fdb show | grep \"master bridge\" > %s",IPA_FDB_TABLE);
	system(cmd);

	fp = fopen(IPA_FDB_TABLE, "r");
	if (fp == NULL)
	{
		IPACMERR("can't open fdb file\n");
		return;
	}

	while (fgets(fdb_row, MAX_FDB_ROW_LEN, fp) != NULL)
	{
		if (strstr(fdb_row,"dev bridge")) {
			continue;
		}
		else if (strstr(fdb_row,"permanent")) {
			is_phy_iface = true;
		}

		/*parse the fdb entry*/
		tok = strtok_r(fdb_row, " ", &ptr);
		for (i = 0; (tok != NULL) && i < MAX_FDB_PARAM_CNT; ++i )
		{
			params[i] = tok;
			tok = strtok_r(NULL, " ", &ptr);
		}

		for(i = 0; i < MAX_FDB_PARAM_CNT; ++i)
		{
			if ((strncmp("dev",params[i], IPA_IFACE_NAME_LEN)==0) && (i < MAX_FDB_PARAM_CNT -1))
			{
				strlcpy(rdev_name, params[i+1], IPA_IFACE_NAME_LEN);
			}
			else if (strstr(params[i],":"))
			{
				strlcpy(mac, params[i], MAX_FDB_PARAM_LEN);
				if( IPA_MAC_ADDR_SIZE != sscanf( mac, "%x:%x:%x:%x:%x:%x%*c",
					&tmp_var[0], &tmp_var[1], &tmp_var[2],
					&tmp_var[3], &tmp_var[4], &tmp_var[5] ) )
				{
					IPACMERR("couldnt parse the mac address\n");
					parse_error = true;
					break;
				}
				else
				{
					for (j = 0 ; j < IPA_MAC_ADDR_SIZE; j++)
					{
						mac_addr_fdb[j] = (uint8_t)tmp_var[j];
					}
				}
			}
		}

		if (parse_error) {
			parse_error = false;
			continue;
		}

		/* Check if already cached*/
		for (i = 0; i < num_neighbor_client; ++i)
		{
			if (memcmp(mac_addr_fdb, neighbor_client[i].mac_addr, sizeof(neighbor_client[i].mac_addr)) == 0) {
				is_client_cached = true;
				break;
			}
		}

		if(is_client_cached) {
			is_client_cached = false;
			continue;
		}

		if(IPACM_Iface::ipa_get_if_index(rdev_name, &query_ifindex))
		{
			IPACMERR("Error while getting interface index for %s device\n", rdev_name);
			continue;
		}
		query_ipa_if_num = IPACM_Iface::iface_ipa_index_query(query_ifindex);

#if !defined(FEATURE_L2TP) && !defined(FEATURE_VLAN_MPDN)
		if (IPACM_FAILURE == query_ipa_if_num) {
			IPACMERR("not supported iface id: %d\n", query_ifindex);
			continue;
		}
#endif

		/* Post USB_LINK_UP event for parent phy netdev intf */
		post_phys_iface_event( rdev_name, query_ipa_if_num, query_ifindex);

		if (is_phy_iface) {
			is_phy_iface =false;
			continue;
		}

		/* In case of vlan ignore the fdb entry for phy netdev  */
#ifdef FEATURE_VLAN_MPDN
		if(IPACM_FAILURE != query_ipa_if_num && (IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE))
		{
			if(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(rdev_name))
			{
				IPACMDBG_H("ignoring physical IFACE neighbor event in VLAN mode\n");
				continue;
			}
		}

		/* if this is a vlan interface that was not added we ignore*/
		if((IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE) &&
			(IPACM_FAILURE == query_ipa_if_num) &&
			(IPACM_Iface::ipacmcfg->iface_in_vlan_mode(rdev_name)) &&
			!(IPACM_Iface::ipacmcfg->is_added_vlan_iface(rdev_name)))
		{
			IPACMDBG_H("not added VLAN interface %s, ignoring\n", rdev_name);
			continue;
		}
#endif

		/*Insert in client list */
		if (num_neighbor_client < IPA_MAX_NUM_NEIGHBOR_CLIENTS)
		{
			memcpy(neighbor_client[num_neighbor_client].mac_addr,
						mac_addr_fdb,
						sizeof(mac_addr_fdb));
#ifdef FEATURE_VLAN_MPDN
			if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
				neighbor_client[circular_index].bridge = NULL;
#endif
			neighbor_client[num_neighbor_client].iface_index = query_ifindex;
			/* cache the network interface client associated */
			neighbor_client[num_neighbor_client].ipa_if_num = query_ipa_if_num;
			neighbor_client[num_neighbor_client].v4_addr = 0;
			strlcpy(neighbor_client[num_neighbor_client].iface_name,
				rdev_name, sizeof(neighbor_client[num_neighbor_client].iface_name));
			IPACMDBG_H("Cache client MAC %02x:%02x:%02x:%02x:%02x:%02x\n, total client: %d\n",
						neighbor_client[num_neighbor_client].mac_addr[0],
						neighbor_client[num_neighbor_client].mac_addr[1],
						neighbor_client[num_neighbor_client].mac_addr[2],
						neighbor_client[num_neighbor_client].mac_addr[3],
						neighbor_client[num_neighbor_client].mac_addr[4],
						neighbor_client[num_neighbor_client].mac_addr[5],
						num_neighbor_client);
			num_neighbor_client++;
		}
		else
		{
			IPACMERR("error:  neighbor client oversize! recycle %d-st entry ! \n", circular_index);
			memcpy(neighbor_client[circular_index].mac_addr,
						mac_addr_fdb,
						sizeof(mac_addr_fdb));
			neighbor_client[circular_index].iface_index = query_ifindex;
			neighbor_client[circular_index].ipa_if_num = query_ipa_if_num;
			neighbor_client[circular_index].v4_addr = 0;
#ifdef FEATURE_VLAN_MPDN
			if(IPACM_Iface::ipacmcfg->ipacm_mpdn_enable == TRUE)
				neighbor_client[circular_index].bridge = NULL;
#endif
			strlcpy(neighbor_client[circular_index].iface_name,
				rdev_name, sizeof(neighbor_client[circular_index].iface_name));\
			IPACMDBG_H("Copy client MAC %02x:%02x:%02x:%02x:%02x:%02x, total client: %d, circular %d\n",
							neighbor_client[circular_index].mac_addr[0],
							neighbor_client[circular_index].mac_addr[1],
							neighbor_client[circular_index].mac_addr[2],
							neighbor_client[circular_index].mac_addr[3],
							neighbor_client[circular_index].mac_addr[4],
							neighbor_client[circular_index].mac_addr[5],
							num_neighbor_client,
							circular_index);
			circular_index = (circular_index + 1) % IPA_MAX_NUM_NEIGHBOR_CLIENTS;
		}
	}
	fclose(fp);
}

void IPACM_Neighbor::post_phys_iface_event(const char *iface_name, int ipa_if_num, int if_idx)
{
	char phys_iface_name[IPA_IFACE_NAME_LEN] = {0};
	int phys_if_idx;
	ipacm_event_data_fid *data_fid = NULL;
	ipacm_cmd_q_data evt_data;

	/* Vlan client */
	if (IPACM_FAILURE == ipa_if_num) {
		if (strstr(iface_name,ETH_INTF)) {
			strlcpy(phys_iface_name, ETH_INTF, IPA_IFACE_NAME_LEN);
		}
		else if (strstr(iface_name,RNDIS_INTF)) {
			strlcpy(phys_iface_name, RNDIS_INTF, IPA_IFACE_NAME_LEN);
		}
		else if (strstr(iface_name,ECM_INTF)) {
			strlcpy(phys_iface_name, ECM_INTF, IPA_IFACE_NAME_LEN);
		}
		else
			return;
		if(IPACM_Iface::ipa_get_if_index(phys_iface_name, &phys_if_idx))
		{
			IPACMERR("Error while getting interface index for %s device", phys_iface_name);
			return;
		}
	}
	else
		phys_if_idx = if_idx;

	data_fid = (ipacm_event_data_fid *)malloc(sizeof(ipacm_event_data_fid));
	if (data_fid == NULL) {
		IPACMERR("unable to allocate memory for event data_fid\n");
		return;
	}

	data_fid->if_index = phys_if_idx;
	evt_data.event = IPA_USB_LINK_UP_EVENT;
	evt_data.evt_data = data_fid;
	IPACMDBG_H("Posting usb IPA_LINK_UP_EVENT with if index: %d iface_name : %s\n",
						 data_fid->if_index, iface_name);
	IPACM_EvtDispatcher::PostEvt(&evt_data);
}
