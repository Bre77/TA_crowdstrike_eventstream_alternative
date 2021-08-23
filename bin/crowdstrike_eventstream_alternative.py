import os
import sys
import json
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.modularinput import *
import aiohttp

class Input(Script):
    MASK = "<encrypted>"
    APP = __file__.split(os.sep)[-3]
    USER_AGENT = "Splunk TA_crowdstrike_eventstream_alternative"

    def get_scheme(self):

        scheme = Scheme("CrowdStrike Event Stream (alternative)")
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
        app_id = f"Splunk {input_name}"
        checkpoint_folder = self._input_definition.metadata["checkpoint_dir"]
        access_token = None

        # Password Encryption / Decryption
        updates = {}
        for item in ["client_id","client_secret"]:
            stored_password = [x for x in self.service.storage_passwords if x.username == item and x.realm == name]
            if input_items[item] == self.MASK:
                if len(stored_password) != 1:
                    ew.log(EventWriter.ERROR,f"Encrypted {item} was not found for {input_name}, reconfigure its value.")
                    return
                input_items[item] = stored_password[0].content.clear_password
            else:
                if(stored_password):
                    ew.log(EventWriter.DEBUG,"Removing Current password")
                    self.service.storage_passwords.delete(username=item,realm=name)
                ew.log(EventWriter.DEBUG,"Storing password and updating Input")
                self.service.storage_passwords.create(input_items[item],item,name)
                updates[item] = self.MASK
        if(updates):
            self.service.inputs.__getitem__((name,kind)).update(**updates)
        
        
        # Setup Async
        async def main():
            session = aiohttp.ClientSession()
            # Login
            async def login(wait=0):
                await asyncio.sleep(wait)
                async with session.post(auth_url, data={'client_id':input_items['client_id'],'client_secret':input_items['client_secret']},headers={'content-type': 'application/x-www-form-urlencoded', 'User-Agent': self.USER_AGENT}) as r:
                    r.raise_for_status()
                    login_data = await r.json()
                    access_token = login_data['access_token']
                    ew.log(EventWriter.INFO,"Access token refreshed")
                    loop.create_task(login(login_data['expires_in']-10))
            
            await login()
            if not access_token:
                ew.log(EventWriter.ERROR,"No Access token, cannot proceed")
                await session.close()
                loop.stop()
                return

            if not discover_url.startswith('https'):
                ew.log(EventWriter.ERROR,"Insecure discover URL: {discover_url}")
                await session.close()
                loop.stop()
                return

            # Discover
            async with session.get(discover_url, params={'appId':app_id,'format':'json'},headers={'Authorization': f"Bearer {self['access_token']}", 'User-Agent': self.USER_AGENT}) as r:
                r.raise_for_status()
                discovery_data = await r.json()
                count = len(discovery_data['resources'])
                ew.log(EventWriter.INFO,f"Discovered {count} feeds")

            async def listen(number,feed):
                # Schedule Feed Refresh
                refresh_url = feed['refreshActiveSessionURL']
                refresh_time = feed['refreshActiveSessionInterval']
                async def refresh():
                    while True:
                        await asyncio.sleep(refresh_time)
                        async with session.post(refresh_url,headers={'Authorization': f"Bearer {self['access_token']}", 'Content-Type': 'application/json', 'User-Agent': self.USER_AGENT}) as refresh:
                            r.raise_for_status()
                            ew.log(EventWriter.INFO,"Refreshed feed {number}")

                if not refresh_url.startswith('https'):
                    ew.log(EventWriter.ERROR,"Insecure refresh URL: {refresh_url}")
                    await session.close()
                    loop.stop()
                    return
                
                loop.create_task(refresh())

                # Listen for data
                token = feed['sessionToken']['token']
                data_url = feed['dataFeedURL']
                source = f"Crowdstrike Eventstream {input_name} {number}"
                checkpoint_file = os.path.join(
                    checkpoint_folder,
                    "".join([c for c in data_url if c.isalpha() or c.isdigit() or c==' ']).rstrip()
                )
                try:
                    offset = int(open(checkpoint_file, "r").read())
                except:
                    offset = 0
                
                while True:
                    async with session.get(f"{data_url}&offset={offset}",headers={'Authorization': f"Token {token}", 'Connection': 'Keep-Alive', 'X-INTEGRATION': app_id, 'User-Agent': self.USER_AGENT}) as r:
                        r.raise_for_status()
                        while True:
                            raw = await r.content.readline()
                            if raw == b'\r\n':
                                continue #Just a keep alive
                            try:
                                data = json.loads(raw.decode('utf-8'))
                            except:
                                ew.log(EventWriter.ERROR,"Failed to parse event: {raw}")
                                continue

                            offset = data['metadata']['offset']
                            open(checkpoint_file, "w").write(str(offset))

                            ew.write_event(Event(
                                time=data['metadata']['eventCreationTime']/1000,
                                data=json.dumps(data, separators=(',', ':')),
                                source=source,
                                host=input_items['domain']
                            ))

            for number, feed in enumerate(discovery_data['resources']):
                if not feed['dataFeedURL'].startswith('https'):
                    ew.log(EventWriter.ERROR,"Insecure feed URL: {feed['dataFeedURL']}")
                    await session.close()
                    loop.stop()
                asyncio.create_task(listen(number, feed))

        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())
        loop.run_forever()
        ew.close()

if __name__ == '__main__':
    exitcode = Input().run(sys.argv)
    sys.exit(exitcode)