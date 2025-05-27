#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish-oss

import os
import re
import sys
import zipfile
import datetime
import hashlib
import random
from ipwhois.net import Net
from ipwhois.asn import IPASN
import json


class TimestampNow:
    '''Generate Timestamp'''
    def Timestamp(self):
        now = datetime.datetime.now().strftime("%c")
        return now


class VerifyPath:
    '''Verify or create path if not exist'''
    def VerifyOrCreate(self, path):
        try:
            os.makedirs(path, mode=0o777, exist_ok=True)
        except FileExistsError:
            pass
        except:
            err = sys.exc_info()
            print("[!!!] VerifyPath class Error: " + str(err))


class SHA256:
    '''Generate sha256 hash of a file'''
    def hashFile(self, filename, block_size=65536):
        h = hashlib.sha256()
        try:
            with open(filename, 'rb') as f:
                buf = f.read(block_size)
                while len(buf) > 0:
                    h.update(buf)
                    buf = f.read(block_size)
                    filehash = h.hexdigest()
            return filehash
        except:
            err = sys.exc_info()
            print("[!!!] Error in hashFile Class: " + str(err))


class UAgent:
    '''Choose a random user-agent from a file'''
    def ChooseUA(self, UAfile):
        try:
            with open(UAfile, 'rb') as f:
                UA = random.choice(list(f)).strip().decode("utf-8")
                return UA
        except:
            err = sys.exc_info()
            print("[!!!] Problem with UserAgent Class: " + str(err))


class NetInfo:
    '''Retrieve network informations'''
    def GetASN(self, IPaddress):
        '''Retrieve AS Number of an IP address'''
        try:
            if IPaddress:
                net = Net(IPaddress)
                obj = IPASN(net)
                res = obj.lookup()
                IPasn = json.dumps(res["asn"])
            else:
                IPasn = None
            return IPasn
        except:
            err = sys.exc_info()
            print("[!!!] Problem with NetInfo Class: " + str(err))


class ZipSearch:
    '''Search for e-mail addresses into Zip file'''
    def PKzipSearch(self, InvTABLEname, SQL, LOG, DLDir, savefile):
        try:
            # print(zipfile.getinfo(savefile))
            if zipfile.is_zipfile(savefile):
                file = zipfile.ZipFile(savefile, "r")
                extracted_emails = []
                for name in file.namelist():
                    if re.findall("php|ini$", name):
                        scam_email2 = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', str(file.read(name)))
                        for mailadd in scam_email2:
                            if mailadd not in extracted_emails:
                                extracted_emails.append(mailadd)
                # Extracted scammers email
                if any(map(len, extracted_emails)):
                    return [extracted_emails]
                else:
                    LOG.info("No emails in this kit")
                    pass
            else:
                LOG.info("{} is not a zip file...".format(savefile))
        except Exception as e:
            print("[!!!] Problem with PKzipSearch Class: " + str(e))


class TelegramSearch:
    '''Search for Telegram into Zip file'''
    def PKzipSearch(self, InvTABLEname, SQL, LOG, DLDir, savefile):
        try:
            if zipfile.is_zipfile(savefile):
                file = zipfile.ZipFile(savefile, "r")

                extracted_TG = []
                bots = set()
                dict_TG = {}
                for name in file.namelist():
                    if re.findall("php|ini|js|html|htm$", name):

                        # Search for TG addresses
                        re_tgbot = re.compile(r'(?:bot)?\d{10}:[0-9A-Za-z_-]{35}')

                        text = str(file.read(name))
                        TG_bot = re.search(re_tgbot, text)

                        if TG_bot:
                            matched_string = TG_bot.group()
                            TG_botid = TG_bot.group(0)
                            if TG_botid.startswith("bot"):
                                TG_botid = TG_botid[3:]

                            # start of first regex
                            tg_bot_start = TG_bot.start()
                            tg_bot_end = TG_bot.end()

                            # Calculate the new start position, 100 lines before
                            chars_before = 100
                            start_pos_before = max(0, tg_bot_start - chars_before)

                            # Calculate the limit for 600 characters after TG_bot
                            limit_after = tg_bot_end + 600

                            # Extract text 100 lines before and 600 characters after TG_bot
                            limited_text_before = text[start_pos_before:tg_bot_start]
                            limited_text_after = text[tg_bot_end:limit_after]

                            # Combine both parts
                            limited_text = limited_text_before + limited_text_after

                            # Telegram channel ID
                            re_tgchan = re.compile(r'-?\d{9}|\d{10}|\d{14}')
                            TG_chanid = re.search(re_tgchan, limited_text)
                            if TG_chanid:
                                TG_chan = TG_chanid.group(0)

                            else:
                                print("No Telegram channel found.")
                                print(limited_text)
                                pass

                            if (TG_botid, TG_chan) not in bots:
                                try:
                                    dict_TG = {
                                        'botID': TG_botid,
                                        'channelID': TG_chan
                                    }
                                    extracted_TG.append(dict_TG)
                                    bots.add((TG_botid, TG_chan))
                                except Exception as e:
                                    print(f"[!!!] Problem retrieving TG info: {e}")

                            # Enrich TG data
                            def get_bot_info(bot_token, proxy=None):
                                url = f"https://api.telegram.org/bot{bot_token}/getMe"
                                
                                try:
                                    try:
                                        response = requests.get(url, proxies=proxies)
                                    except Exception as e:
                                        print(f"[bot_info] Error: {e}")
                                        sys.exit(1)

                                    response.raise_for_status()
                                    data = response.json()
                                    if data.get("ok"):
                                        result = data.get("result")
                                        bot_info = {
                                            "first_name": result.get("first_name"),
                                            "username": result.get("username"),
                                            "id": result.get("id")
                                        }
                                        return bot_info
                                    else:
                                        return {"error": "Failed to retrieve bot information."}
                                except requests.exceptions.RequestException as e:
                                    return {"error": f"An error occurred: {e}"}

                            def get_chat_info(bot_token, chat_id, proxy=None):
                                url = f"https://api.telegram.org/bot{bot_token}/getChat?chat_id={chat_id}"
                                
                                try:
                                    try:
                                        response = requests.get(url, proxies=proxies)
                                    except Exception as e:
                                        print(f"[chat_info] Error: {e}")
                                        sys.exit(1)
                                    response.raise_for_status()
                                    data = response.json()
                                    if data.get("ok"):
                                        result = data.get("result")
                                        chat_info = {
                                            "title": result.get("title"),
                                            "type": result.get("type"),
                                            "invite_link": result.get("invite_link")
                                        }
                                        return chat_info
                                    else:
                                        return {"error": "Failed to retrieve chat information."}
                                except requests.exceptions.RequestException as e:
                                    return {"error": f"An error occurred: {e}"}

                            def get_chat_administrators(bot_token, chat_id, proxies):
                                url = f"https://api.telegram.org/bot{bot_token}/getChatAdministrators?chat_id={chat_id}"
                                
                                try:
                                    try:
                                        response = requests.get(url, proxies=proxies)
                                    except Exception as e:
                                        print(f"[admin_info] Error: {e}")
                                        sys.exit(1)
                                    response.raise_for_status()
                                    data = response.json()
                                    if data.get("ok"):
                                        administrators = data.get("result")
                                        admins_info = []
                                        for admin in administrators:
                                            user = admin.get("user")
                                            user_info = {
                                                "id": user.get("id"),
                                                "is_bot": user.get("is_bot"),
                                                "first_name": user.get("first_name"),
                                                "last_name": user.get("last_name"),
                                                "language_code": user.get("language_code"),
                                                "username": user.get("username")
                                            }
                                            admins_info.append(user_info)
                                        return admins_info
                                    else:
                                        return {"error": "Failed to retrieve chat administrators information."}
                                except requests.exceptions.RequestException as e:
                                    return {"error": f"An error occurred: {e}"}

                            for entry in extracted_TG:
                                botID = entry["botID"]
                                channelID = entry["channelID"]
                                proxies = {}

                                if PROXY:
                                    if PROXY.startswith('socks5://'):
                                        proxies['http'] = PROXY
                                        proxies['https'] = PROXY
                                    else:
                                        proxies['http'] = PROXY
                                        proxies['https'] = PROXY

                                bot_info = get_bot_info(botID, proxies)
                                chat_info = get_chat_info(botID, channelID, proxies)
                                admins_info = get_chat_administrators(botID, channelID, proxies)

                                if "error" not in bot_info:
                                    entry["bot_info"] = bot_info
                                else:
                                    entry["bot_info"] = []

                                if "error" not in chat_info:
                                    entry["chat_info"] = chat_info
                                else:
                                    entry["chat_info"] = []

                                if "error" not in admins_info:
                                    entry["admins_info"] = admins_info
                                else:
                                    entry["admins_info"] = []

                # After the loop, convert extracted_TG to JSON and return it
                if extracted_TG:
                    extracted_TG_json = json.dumps(extracted_TG)
                    return [extracted_TG_json]
                else:
                    extracted_TG_json = "{}"
                    return [extracted_TG_json]

                LOG.info(f"Telegram info: {extracted_TG_json}")
            else:
                LOG.info("{} is not a zip file...".format(savefile))
        except Exception as e:
            print("[!!!] Problem with PKzipSearchTelegram Class: " + str(e))

