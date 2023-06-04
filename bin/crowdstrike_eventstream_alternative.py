import os
import signal
import sys
import json
import asyncio
import ssl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *
import aiohttp

class Input(Script):
    MASK = "<encrypted>"
    APP = __file__.split(os.sep)[-3]
    USER_AGENT = "Splunk TA_crowdstrike_eventstream_alternative"
    REFRESH_INTERVAL = 1740

    def get_scheme(self):

        scheme = Scheme("CrowdStrike Event Stream (unoffical)")
        scheme.description = ("A single threaded asynchronous implementation of the CrowdStrike Falcon Event Stream")
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(Argument(
            name="client_id",
            title="Client ID",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="client_secret",
            title="Client Secret",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=False
        ))
        scheme.add_argument(Argument(
            name="domain",
            title="Domain",
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=False
        ))
        return scheme

    def stream_events(self, inputs, ew):
        self.service.namespace['app'] = self.APP
        # Get Variables
        input_name, input_items = inputs.inputs.popitem()
        kind, name = input_name.split("://")
        auth_url = f"https://{input_items['domain']}/oauth2/token"
        discover_url = f"https://{input_items['domain']}/sensors/entities/datafeed/v2"
        app_id = ("".join([c for c in name if c.isalpha() or c.isdigit()]).rstrip())[:15]
        checkpoint_folder = self._input_definition.metadata["checkpoint_dir"]

        auth = {"access_token":None,"client_id":None,"client_secret":None}
        timeout = aiohttp.ClientTimeout(connect=10,sock_read=11,total=0) #Keep alives are sent every 5 seconds
        sslcontext = ssl.create_default_context(cafile=os.path.join(os.path.dirname(__file__),'cacert.pem')) #Crowdstrike Cert fails in default certifi

        # Password Encryption / Decryption
        updates = {}
        for item in ["client_id","client_secret"]:
            stored_password = [x for x in self.service.storage_passwords if x.username == item and x.realm == name]
            if input_items[item] == self.MASK:
                if len(stored_password) != 1:
                    ew.log(EventWriter.ERROR,f"Encrypted {item} was not found for {input_name}, reconfigure its value.")
                    return
                auth[item] = stored_password[0].content.clear_password
            else:
                if(stored_password):
                    ew.log(EventWriter.DEBUG,"Removing Current password")
                    self.service.storage_passwords.delete(username=item,realm=name)
                ew.log(EventWriter.DEBUG,"Storing password and updating Input")
                self.service.storage_passwords.create(input_items[item],item,name)
                updates[item] = self.MASK
                auth[item] = input_items[item]
        if(updates):
            self.service.inputs.__getitem__((name,kind)).update(**updates)
        
        
        # Setup Async
        loop = asyncio.get_event_loop()

        async def main():
            ew.log(EventWriter.INFO,f"{name} - Starting Event Stream '{app_id}'")
            session = aiohttp.ClientSession()

            # Handle Signals/Errors gracefully
            async def exit(reason, level=EventWriter.INFO):
                ew.log(level,f"{name} - {reason}")
                await session.close()
                ew.log(EventWriter.INFO,f"{name} - aiohttp session closed")
                loop.stop()

            # Listen for signals
            for signame in ('SIGINT', 'SIGTERM'):
                loop.add_signal_handler(getattr(signal, signame),lambda: loop.create_task(exit(signame)))

            # Login
            async def login(wait=0):
                await asyncio.sleep(wait)
                async with session.post(auth_url, data=auth,headers={'content-type': 'application/x-www-form-urlencoded', 'User-Agent': self.USER_AGENT}, ssl=sslcontext) as r:
                    login_data = await r.json()
                    r.raise_for_status()
                    auth['access_token'] = login_data.get('access_token')
                ew.log(EventWriter.INFO,f"{name} - Access Token refreshed")
                loop.create_task(login(self.REFRESH_INTERVAL)) #login_data['expires_in']-60

            await login()

            if auth['access_token'] == None:
                return await exit("No Access token, cannot proceed",EventWriter.ERROR)

            if not discover_url.startswith('https'):
                return await exit(f"Insecure discover URL: {discover_url}",EventWriter.ERROR)

            # Discover
            ew.log(EventWriter.INFO,f"{name} - Starting discover")
            async with session.get(discover_url, params={'appId':app_id}, headers={"Authorization": f"Bearer {auth['access_token']}", "Accept": "application/json", 'User-Agent': self.USER_AGENT}, ssl=sslcontext) as r:
                r.raise_for_status()
                discovery_data = await r.json()
                if discovery_data['resources'] == None:
                    return await exit("No Event Stream feeds discovered, cannot proceed",EventWriter.ERROR)
                count = len(discovery_data['resources'])
                ew.log(EventWriter.INFO,f"{name} - Discovered {count} Event Stream feed(s)")

            # Listen
            async def listen(number,feed):
                # Schedule Feed Refresh
                refresh_url = feed['refreshActiveSessionURL']

                if not refresh_url.startswith('https'):
                    return await exit(f"Insecure refresh URL: {refresh_url}",EventWriter.ERROR)

                async def refresh():
                    while True:
                        await asyncio.sleep(self.REFRESH_INTERVAL)
                        async with session.post(refresh_url,headers={'Authorization': f"Bearer {auth['access_token']}", 'Accept': 'application/json', 'Content-Type': 'application/json', 'User-Agent': self.USER_AGENT}, ssl=sslcontext) as r:
                            r.raise_for_status()
                            await r.json()
                            ew.log(EventWriter.INFO,f"{name} - Refreshed feed {number}")
                
                loop.create_task(refresh())

                # Listen for data
                token = feed['sessionToken']['token']
                data_url = feed['dataFeedURL']
                checkpoint_file = os.path.join(
                    checkpoint_folder,
                    "".join([c for c in data_url if c.isalpha() or c.isdigit() or c==' ']).rstrip()
                )
                try:
                    offset = int(open(checkpoint_file, "r").read())
                except:
                    offset = 0
                
                ew.log(EventWriter.INFO,f"{name} - Connecting to feed {number}")
                async with session.get(f"{data_url}&offset={offset}",headers={'Authorization': f"Token {token}", 'Accept': 'application/json', 'Connection': 'Keep-Alive', 'X-INTEGRATION': app_id, 'User-Agent': self.USER_AGENT}, ssl=sslcontext, timeout=timeout) as r:
                    r.raise_for_status()
                    while True:
                        try:
                            line = (await r.content.readline()).decode('utf-8')
                        #except aiohttp.ClientError as e:
                        #    await session.close()
                        #    raise Exception(e)
                        except Exception as e:
                            return await exit(e,EventWriter.ERROR)
                        if line == '':
                            return await exit("Connection Closed (EOF)",EventWriter.WARN)
                        if line == '\r\n':
                            continue #Just a keep alive
                        try:
                            data = json.loads(line)
                        except:
                            ew.log(EventWriter.WARN,f"{name} - Failed to parse event: {line}")
                            continue

                        # Save checkpoint (this isnt ideal for performance, but safe)
                        offset = data['metadata']['offset']
                        open(checkpoint_file, "w").write(str(offset))

                        # Optional fix for the AuditKeyValues array
                        try:
                            if "AuditKeyValues" in data["event"]:
                                data["event"]["Audit"] = {}
                                for x in data["event"]["AuditKeyValues"]:
                                    if "Key" in x:
                                        data["event"]["Audit"][x['Key']] = x.get('ValueString')
                        except AttributeError:
                            pass

                        # Write the event
                        ew.write_event(Event(
                            time=data['metadata']['eventCreationTime']/1000,
                            data=json.dumps(data, separators=(',', ':')),
                            source=data_url,
                            host=input_items['domain']
                        ))

            for number, feed in enumerate(discovery_data['resources']):
                if not feed['dataFeedURL'].startswith('https'):
                    return await exit(f"Insecure feed URL: {feed['dataFeedURL']}",EventWriter.ERROR)
                await asyncio.sleep(5)
                try:
                    loop.create_task(listen(number, feed))
                except Exception as e:
                    return await exit(e,EventWriter.ERROR)
                
        try:
            loop.create_task(main())
            loop.run_forever()
        except Exception as e:
            ew.log(EventWriter.ERROR,e)
            loop.stop()
        finally:
            loop.close()

        ew.close()
        ew.log(EventWriter.INFO,"Clean Exit")
        return

if __name__ == '__main__':
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)