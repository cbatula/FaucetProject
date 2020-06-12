"""Prometheus for Gauge."""

# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import pandas as pd
import numpy as np
import time

from sklearn.ensemble import RandomForestRegressor
from prometheus_client import Gauge

from faucet.faucet_pipeline import _fib_table
from faucet.faucet_pipeline import ValveTableConfig
from ryu.ofproto import ofproto_v1_3_parser as parser
from faucet.valve import valve_factory,SUPPORTED_HARDWARE
from faucet.gauge_pollers import GaugePortStatsPoller, GaugePortStatePoller, GaugeFlowTablePoller
from faucet.prom_client import PromClient
from ryu.lib.packet import packet
from ryu.lib.packet import packet_base
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import arp,icmp,icmpv6,ipv4,ipv6
from faucet import valve_of
from faucet.valve_switch_stack import ValveSwitchStackManagerBase
from faucet.valve_manager_base import ValveManagerBase
from faucet import valve_packet 
from faucet import faucet_metrics 
from faucet.valve import Valve
from faucet import valve_pipeline 

PROM_PREFIX_DELIM = '_'
PROM_PORT_PREFIX = 'of_port'
PROM_PORT_STATE_VARS = (
    'reason',
    'state',
    'curr_speed',
    'max_speed',
)
PROM_PORT_VARS = (
    'tx_packets',
    'rx_packets',
    'tx_bytes',
    'rx_bytes',
    'tx_dropped',
    'rx_dropped',
    'tx_errors',
    'rx_errors')
PROM_FLOW_VARS = (
    'flow_byte_count',
    'flow_packet_count'
)
PROM_METER_PREFIX = 'of_meter'
PROM_METER_VARS = (
    'flow_count',
    'byte_in_count',
    'packet_in_count',
    'byte_band_count',
    'packet_band_count'
)

class GaugePrometheusClient(PromClient):
    """Wrapper for Prometheus client that is shared between all pollers."""

    def __init__(self, reg=None):
        super(GaugePrometheusClient, self).__init__(reg=reg)
        self.table_tags = collections.defaultdict(set)
        self.metrics = {}
        self.dp_status = Gauge( # pylint: disable=unexpected-keyword-arg
            'dp_status',
            'status of datapaths',
            self.REQUIRED_LABELS,
            registry=self._reg)
        for prom_var in PROM_PORT_VARS + PROM_PORT_STATE_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join(
                (PROM_PORT_PREFIX, prom_var))
            self.metrics[exported_prom_var] = Gauge(  # pylint: disable=unexpected-keyword-arg
                exported_prom_var, '',
                self.REQUIRED_LABELS + ['port', 'port_description'],
                registry=self._reg)
        for prom_var in PROM_METER_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join(
                (PROM_METER_PREFIX, prom_var))
            self.metrics[exported_prom_var] = Gauge(  # pylint: disable=unexpected-keyword-arg
                exported_prom_var, '',
                self.REQUIRED_LABELS + ['meter_id'],
                registry=self._reg)

    def reregister_flow_vars(self, table_name, table_tags):
        """Register the flow variables needed for this client"""
        for prom_var in PROM_FLOW_VARS:
            table_prom_var = PROM_PREFIX_DELIM.join((prom_var, table_name))
            try:
                self._reg.unregister(self.metrics[table_prom_var])
            except KeyError:
                pass
            self.metrics[table_prom_var] = Gauge( # pylint: disable=unexpected-keyword-arg
                table_prom_var, '', list(table_tags), registry=self._reg)


class GaugePortStatsPrometheusPoller(GaugePortStatsPoller):
    """Exports port stats to Prometheus."""

    def __init__(self, conf, logger, prom_client):
        super(GaugePortStatsPrometheusPoller, self).__init__(
            conf, logger, prom_client)
        self.prom_client.start(
            self.conf.prometheus_port, self.conf.prometheus_addr, self.conf.prometheus_test_thread)

    def _format_stat_pairs(self, delim, stat):
        stat_pairs = (
            ((delim.join((PROM_PORT_PREFIX, prom_var)),), getattr(stat, prom_var))
            for prom_var in PROM_PORT_VARS)
        return self._format_stats(delim, stat_pairs)

    def _update(self, rcv_time, msg):
        for stat in msg.body:
            port_labels = self.dp.port_labels(stat.port_no)
            for stat_name, stat_val in self._format_stat_pairs(
                    PROM_PREFIX_DELIM, stat):
                self.prom_client.metrics[stat_name].labels(**port_labels).set(stat_val)


class GaugeMeterStatsPrometheusPoller(GaugePortStatsPoller):
    """Exports meter stats to Prometheus."""

    def __init__(self, conf, logger, prom_client):
        super(GaugeMeterStatsPrometheusPoller, self).__init__(
            conf, logger, prom_client)
        self.prom_client.start(
            self.conf.prometheus_port, self.conf.prometheus_addr, self.conf.prometheus_test_thread)

    def _format_stat_pairs(self, delim, stat):
        band_stats = stat.band_stats[0]
        stat_pairs = (
            (('flow', 'count'), stat.flow_count),
            (('byte', 'in', 'count'), stat.byte_in_count),
            (('packet', 'in', 'count'), stat.packet_in_count),
            (('byte', 'band', 'count'), band_stats.byte_band_count),
            (('packet', 'band', 'count'), band_stats.packet_band_count),
        )
        return self._format_stats(delim, stat_pairs)

    def _update(self, rcv_time, msg):
        for stat in msg.body:
            meter_labels = self.dp.base_prom_labels()
            meter_labels.update({'meter_id': stat.meter_id})
            for stat_name, stat_val in self._format_stat_pairs(
                    PROM_PREFIX_DELIM, stat):
                stat_name = PROM_PREFIX_DELIM.join((PROM_METER_PREFIX, stat_name))
                self.prom_client.metrics[stat_name].labels(**meter_labels).set(stat_val)


class GaugePortStatePrometheusPoller(GaugePortStatePoller):
    """Export port state changes to Prometheus."""

    def _update(self, rcv_time, msg):
        port_no = msg.desc.port_no
        port = self.dp.ports.get(port_no, None)
        if port is None:
            return
        port_labels = self.dp.port_labels(port_no)
        for prom_var in PROM_PORT_STATE_VARS:
            exported_prom_var = PROM_PREFIX_DELIM.join((PROM_PORT_PREFIX, prom_var))
            msg_value = msg.reason if prom_var == 'reason' else getattr(msg.desc, prom_var)
            self.prom_client.metrics[exported_prom_var].labels(**port_labels).set(msg_value)

class parse_flow_stateless:

    currentStats={}
    dstStats={}
    total_pkts = 0

    def __init__(self):
        currentStats = {None:{}}                     
        dstStats={None:{}}
        self.rf = RandomForestRegressor(n_estimators = 1000, random_state = 42)
        self.trainData(self.rf)

    def trainData(self,rf):
        data = pd.read_csv("TRAINDATA.csv")
        x_train = data[['pkt_count','pkt_length','tcp_perc','udp_perc','icmp_perc','ratio_comm']]
        y_train = data['type']
        rf.fit(x_train,y_train)
   
    def inference(self, tester):
        predictions = self.rf.predict(tester)
        return predictions

    def parseSend(self,eth_src,pkt_cnt,byte_cnt,ip_proto,eth_dst):
   
        new_data = {'eth_src': str(eth_src),
                    'pkt_cnt': pkt_cnt,
                    'byte_cnt': byte_cnt,
                    'ip_proto': ip_proto,
                    'num_proto': 1,
                    'tcp_cnt': int(ip_proto == 6),
                    'icmp_cnt': int(ip_proto == 1),
                    'udp_cnt': int(ip_proto == 17),
                    'eth_dst': []
        }
    
        if str(eth_src) not in self.currentStats:
            self.currentStats[str(eth_src)] = new_data
            self.currentStats[str(eth_src)]['eth_dst'].append(str(eth_dst))
        else:
            self.currentStats[str(eth_src)]['pkt_cnt']+=pkt_cnt
            self.currentStats[str(eth_src)]['byte_cnt']+=byte_cnt
            self.currentStats[str(eth_src)]['num_proto']+=1
            self.currentStats[str(eth_src)]['tcp_cnt']+=int(ip_proto==6)
            self.currentStats[str(eth_src)]['icmp_cnt']+=int(ip_proto==1)
            self.currentStats[str(eth_src)]['udp_cnt']+=int(ip_proto==17)
            if str(eth_dst) not in self.currentStats[str(eth_src)]['eth_dst']:
                self.currentStats[str(eth_src)]['eth_dst'].append(str(eth_dst))
            self.total_pkts+=pkt_cnt

        return self.currentStats[str(eth_src)]



clock = -1
deviceTypes = {}
x_flow = parse_flow_stateless()
dstFlag=0
srcFlag=0
eth_dst=None
eth_src=None
pkt_cnt=None
of_proto=None

class GaugeFlowTablePrometheusPoller(GaugeFlowTablePoller):
    """Export flow table entries to Prometheus."""

    def _update(self, rcv_time, msg):
        global clock
        global x_flow
        global deviceTypes
        global dstFlag
        global srcFlag
        global eth_dst
        global eth_src
        global pkt_cnt
        global of_proto
        jsondict = msg.to_jsondict()
        flag = 0
        timer = 0
        if clock == -1:
            clock = time.time()
        print = self.logger.info
        for stats_reply in jsondict['OFPFlowStatsReply']['body']:
            stats = stats_reply['OFPFlowStats']
            d=self._parse_flow_stats(stats) 
            #print(time.time() - clock)
            #print(d[1]['eth_dst'])
            if 'eth_dst' in d[1][1] and not dstFlag:
                eth_dst=d[1][1]['eth_dst']
                print('eth_dst: ', eth_dst)
                if eth_dst not in x_flow.dstStats:
                    x_flow.dstStats[eth_dst]=0
                dstFlag=1
            if 'eth_src' in d[1][1] and 'in_port' in d[0][1] and not srcFlag:
                eth_src=d[1][1]['eth_src']
                pkt_cnt=d[0][2]
                byte_cnt=d[1][2]
                of_proto=jsondict['OFPFlowStatsReply']['body'][0]['OFPFlowStats']['instructions'][0]['OFPInstructionActions']['actions'][0]['OFPActionPushVlan']['type']
                print('eth_src: ',eth_src)
                print('pkt_cnt: ',pkt_cnt)
                print('byte_cnt: ', byte_cnt)
                print('of_proto: ', of_proto)
                srcFlag=1
            if dstFlag and srcFlag:
                print('dstFlag and srcFlag are set')
                x_flow.parseSend(eth_src,pkt_cnt,byte_cnt,of_proto,eth_dst)
                srcFlag=0
                dstFlag=0

            if time.time() - clock >= 120:
                timer = 1
            for var, tags, count in self._parse_flow_stats(stats):
                table_id = int(tags['table_id'])
                #print(self.dp.table_by_id(table_id).match())
                table_name = self.dp.table_by_id(table_id).name
                table_tags = self.prom_client.table_tags[table_name]
                tags_keys = set(tags.keys())
                if tags_keys != table_tags:
                    unreg_tags = tags_keys - table_tags
                    if unreg_tags:
                        table_tags.update(unreg_tags)
                        self.prom_client.reregister_flow_vars(
                            table_name, table_tags)
                        #self.logger.info( # pylint: disable=logging-not-lazy
                         #   'Adding tags %s to %s for table %s' % (
                         #       unreg_tags, table_tags, table_name))
                    # Add blank tags for any tags not present.
                    missing_tags = table_tags - tags_keys
                    for tag in missing_tags:
                        tags[tag] = ''
                table_prom_var = PROM_PREFIX_DELIM.join((var, table_name))
                try:
                    self.prom_client.metrics[table_prom_var].labels(**tags).set(count)
                except ValueError:
                    self.logger.error( # pylint: disable=logging-not-lazy
                        'labels %s versus %s incorrect on %s' % (
                            tags, table_tags, table_prom_var))

        if timer: 
            totalpkts=x_flow.total_pkts
            ratio_comm = len(x_flow.dstStats)
            for dic, ip in x_flow.currentStats.items():
                tcp_perc = ip['tcp_cnt']/ip['num_proto']
                udp_perc = ip['udp_cnt']/ip['num_proto']
                icmp_perc = ip['icmp_cnt']/ip['num_proto']
                byte_cnt = ip['byte_cnt']/ip['num_proto']
                ratio_comm = len(ip['eth_dst'])
                if ip['pkt_cnt'] != 0:
                    ratio_comm = ratio_comm / ip['pkt_cnt']
                else:
                    ratio_comm = 0
                arr = [ip['pkt_cnt'],byte_cnt,tcp_perc,udp_perc,icmp_perc,ratio_comm]
                arr = np.array(arr)
                arr = arr.reshape(1,-1)
                dtype = (x_flow.inference(arr)).astype(int)
                dtype = np.array(dtype).tolist()[0]
                if dic not in deviceTypes:
                    deviceTypes[dic]=dtype
            timer=0
            print(deviceTypes)
            flag = 1
            newObj = parse_flow_stateless()
            x_flow = newObj
            clock = time.time()
