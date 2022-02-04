__author__ = "ivo hrbacek"
__credits__ = ["ivosh", "laura"]
__version__ = "1.0"
__maintainer__ = "ivo hrbacek"
__email__ = "ihr@actinet.cz"
__status__ = "production"
__dev_version__ = "v3"
__spec__= "Check Point password change via mgmt API"


import requests
import urllib3
import json
import sys
import time
import getpass
import logging
import os
import base64


######## Class############
class Connector():
    
    """
    
    Connector class is main class handling connectivity to CP API
    Login is done in constructor once instance of Connector is created
    methods:
            task_method() - help method for publish status check
            publish() - method for changes publishing
            send_cmd() - makes API call based on functionality (viz. API reference)
            logout() - logout form API
            discard() - discard changes
            get_last_status_code() - returns last status code
            run_script - run OS command via mgmt API
    """

    # do not care about ssl cert validation for now   
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    @classmethod
    def task_method(cls, sid:str, url:str, task:str) -> dict:

        """
        this is help method which is checking task status when publish is needed
        """

        payload_list={}
        payload_list['task-id']=task
        headers = {
            'content-type': "application/json",
            'Accept': "*/*",
            'x-chkp-sid': sid,
        }
        response = requests.post(url+"show-task", json=payload_list, headers=headers, verify=False)
        return response



    def __init__(self, url:str, payload:dict):

        """
        This is constructor for class, login to API server is handled here - handling also conectivity problems to API
        """

        
        self.sid=""
        # default header without SID
        self.headers_default = {
             'content-type': "application/json",
              'Accept': "*/*",
             }
        # headers for usage in instance methods - with self.SID - will be filled up in constructor
        self.headers = {}
        self.url=url
        self.payload_list = payload # default only username and passowrd
        done=False
        counter=0
        
        # loop to handle connection interuption
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging ('Connector() - init() - connection to mgmt can not be established even in loop, check your credentials or IP connectivity')
                sys.exit(1)
            try:
                self.response = requests.post(self.url+"login", json=self.payload_list, headers=self.headers_default, verify=False) 
                #print(json.loads(self.response.text))
                if self.response.status_code == 200:
                    #print(json.loads(self.response.text))
                    try:
                        sid_out=json.loads(self.response.text)
                        self.sid = sid_out['sid']
                        self.headers = {
                                'content-type': "application/json",
                                'Accept': "*/*",
                                'x-chkp-sid': self.sid,
                        }
                        DoLogging().do_logging('Connector() - init() - Connection to API is okay')
                        
                    except Exception as e:
                        DoLogging().do_logging(' Connector() - init() - API is not running probably: {}..'.format(e))
                else:
                    try:
                        
                        a = json.loads(self.response.text)
                        DoLogging().do_logging("Connector() - init() - Exception occured: {}".format(a))
                        
                        
                        if a['message']=='Authentication to server failed.':
                            
                            DoLogging().do_logging ("Connector() - init() - You entered wrong password probably..try it again from the beggining..\n")
                            sys.exit(1)

                        if a['message']=='Administrator is locked.':
                        
                            DoLogging().do_logging ("Connector() - init() - Use this command to unlock admin:\n")
                            DoLogging().do_logging ("Connector() - init() - mgmt_cli -r true unlock-administrator name 'admin' --format json -d 'System Data'")
                            sys.exit(1)

                        DoLogging().do_logging('Connector() - init() - There is no SID, connection problem to API gateway, trying again..')
                        time.sleep (5)
                        continue
                    except Exception as e:
                        DoLogging().do_logging ("Connector() - init() - can not parse data from mgmt API, is API running?:\n")
                        
            except requests.exceptions.RequestException as e:   
                DoLogging().do_logging(' Connector() - init() - exception occured..can not connect to mgmt server, check IP connectivity or ssl certificates!!!')     
            else:
                done=True
                
  



    def publish(self):

        """
        Publish method is responsible for publishing changes to mgmt server, its here for future usage, its not used now by rulerevision
        """

        payload_list={}
        headers = {
            'content-type': "application/json",
            'Accept': "*/*",
            'x-chkp-sid': self.sid,
        }

        done=False
        counter=0
        
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging ('Connector() - publish() - connection to mgmt for publish does not work even in loop.. exit')
                sys.exit(1)
            try:
                self.response = requests.post(self.url+"publish", json=payload_list, headers=headers, verify=False)
                publish_text=json.loads(self.response.text)
                #print (publish_text)
                show_task=Connector.task_method(self.sid,self.url,publish_text['task-id'])
                show_task_text = json.loads(show_task.text)
                
                while show_task_text['tasks'][0]['status'] == "in progress":
                    DoLogging().do_logging ("Connector() - publish() - publish status = ", show_task_text['tasks'][0]['progress-percentage'])
                    time.sleep(10)
                    show_task=Connector.task_method(self.sid,self.url,publish_text['task-id'])
                    show_task_text=json.loads(show_task.text)
                    DoLogging().do_logging (" Connector() - publish() - publish status = ", show_task_text['tasks'][0]['progress-percentage'] , show_task_text['tasks'][0]['status'])
                    

                DoLogging().do_logging ('Connector() - publish() - publish is done')
                return self.response
            except:   
                DoLogging().do_logging(' Connector() - publish() - exception occured..can not connect to mgmt server when publishing, check IP connectivity!!!')     
            else:
                done=True



    def logout(self):

        """
        Logout method for correct disconenction from API

        """

        done=False
        counter=0
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging('Connector() - logout() - logout can not be done because connection to mgmt is lost and reconnect does not work...')
                sys.exit(1)
                
            else:
                try:
                    payload_list={}
                    self.response = requests.post(self.url+"logout", json=payload_list, headers=self.headers, verify=False)
                    if self.response.status_code == 200:
                        DoLogging().do_logging ('Connector() - logout() - logout from API is okay')
                        return self.response.json()
                    else:
                        out = json.loads(self.response.text)
                        DoLogging().do_logging (" ")
                        DoLogging().do_logging(out)
                        DoLogging().do_logging (" ")
                        return self.response.json()
                    
                except:
                   DoLogging().do_logging ('Connector() - logout() - connection to gateway is broken, trying again')
                else:
                    done=True
           
                     

    def send_cmd(self, cmd, payload):

        """
        Core method, all data are exchanged via this method via cmd variable, you can show, add data etc.
        """

        done=False
        counter=0
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging ("Connector() - send_cmd() - Can not send API cmd in loop, there are some problems, changes are unpublished, check it manually..")
                self.discard()
                self.logout()
                sys.exit(1)
            else:
                 try:
                     payload_list=payload
                     self.response = requests.post(self.url + cmd, json=payload_list, headers=self.headers, verify=False)
                     if self.response.status_code == 200:
                         #uncomment for TSHOOT purposes
                         #DoLogging().do_logging ('Connector() - send_cmd() - send cmd is okay')
                         #out = json.loads(self.response.text)
                         #DoLogging().do_logging ('Connector() - send_cmd() - send cmd response is 200 :{}'.format(out))
                         return self.response.json()
                     else:
                         out = json.loads(self.response.text)
                         DoLogging().do_logging(" Connector() - send_cmd() - response code is not 200 :{}".format(out))
                         return self.response.json()
                     
                     
                 except:
                    DoLogging().do_logging ("Connector() - send_cmd() - POST operation to API is broken due connectivity flap or issue.. trying again..")
                    
                 else:
                    done=True


    def discard(self):

        """
        discard method for correct discard of all data modified via API

        """

        done=False
        counter=0
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging('Connector() - discard() - discard can not be done because connection to mgmt is lost and reconnect does not work...')
                sys.exit(1)
                
            else:
                try:
                    payload_list={}
                    self.response = requests.post(self.url+"discard", json=payload_list, headers=self.headers, verify=False)
                    if self.response.status_code == 200:
                        DoLogging().do_logging ('Connector() - discard() - discard is okay')
                        out = json.loads(self.response.text)
                        DoLogging().do_logging("Connector() - discard() - response code 200: {}".format(out))
                        return self.response.json()

                    else:
                        out = json.loads(self.response.text)
                        DoLogging().do_logging("Connector() - discard() - response code is not 200: {}".format(out))
                        return self.response.json()
                except:
                   DoLogging().do_logging ('Connector() - discard() - discard - connection to gateway is broken, trying again')
                else:
                    done=True
                    
    @staticmethod
    def base64_ascii(base64resp):
        """Converts base64 to ascii for run command/showtask."""
        try:
            return base64.b64decode(base64resp).decode('utf-8')
        except Exception as e:
            DoLogging().do_logging("base64 error:{}".format(e))
    
                    
                    
    def run_script(self, payload):
        
        """
        run script method is responsible for running script on target (ls -la, df -lh etc. basic linux commands)
        """

        payload_list=payload
        headers = {
            'content-type': "application/json",
            'Accept': "*/*",
            'x-chkp-sid': self.sid,
        }

        
        return_string = ''
        
        done=False
        counter=0
        
        while not done:
            counter +=1
            if counter == 5:
                DoLogging().do_logging('Connector() - run_script() - discard can not be done because connection to mgmt is lost and reconnect does not work...')
                sys.exit(1)
                
            else:
                try:    
                      
                    self.response = requests.post(self.url+"run-script", json=payload_list, headers=headers, verify=False)
                    tasks=json.loads(self.response.text)
                    for item in tasks['tasks']:
                        while True:
                            show_task=Connector.task_method(self.sid,self.url,item['task-id'])
                            show_task_text=json.loads(show_task.text)
                            DoLogging().do_logging ("Connector() - run_script() - :{}".format(show_task_text))
                            time.sleep (10)
                            if show_task_text['tasks'][0]['progress-percentage'] == 100:
                                base64resp = (str(self.send_cmd('show-task', payload={"task-id":show_task_text['tasks'][0]['task-id'], "details-level":"full"})['tasks'][0]['task-details'][0]['responseMessage']))
                                asciiresp = self.base64_ascii(base64resp)
                                return_string=return_string+"\n\n"+"Data for target:"+item['target']+"\n"+asciiresp+"\n\n\n\n\n\n"
                                DoLogging().do_logging ("Connector() - run_script() - :{}".format(show_task_text))
                                break
                            else:
                                continue
                        
                        
                    return return_string
                        
                except Exception as e:
                    DoLogging().do_logging ("Connector() - run_script() - Exception in run_script method, some data not returned, continue: {} {}".format(e, tasks))
                else:
                    done=True
         
         
                    
            

######## Class############
class DoLogging():
    
    """
    Logging class, to have some possibility debug code in the future

    """

    def __init__(self):

        """
        Constructor does not do anything
        """
        pass
      

    def do_logging(self, msg:str):

        """
        Log appropriate message into log file
        """
        # if needed change to DEBUG for more data
        logging.basicConfig(filename="logcp.elg", level=logging.INFO)
        logging.info(msg)




 
#############################METHODS##################################

     
                    
def ask_for_question():
    
        """
        handle user input at the beginning

        """

        try:

            print("###############################",
                
                "CP password change.. changing password for user on all CP boxes managed by mgmt server through APi call",
                "To genarate hash for password run /sbin/grub-md5-crypt on any Gaia OS to get hash",
                "To define exceptions, check main() method and define them, otherwise it will run all all boxes connected to mgmt machine",
                 
                "###############################",
                sep="\n\n")

            
            user=input("Enter API/GUI user name with write permissions: ")
            password=getpass.getpass()
            server_ip=input("Enter server IP: ")
            
            user_account_for_change=input("Enter account you wanna change, leave blank if you wanna have default admin:")
            password_hash=input("Enter password hash (you can generate one on CP system running -> /sbin/grub-md5-crypt):")
            
            print ("")
            user_account=None
            user_account_default='admin'
           
            if not user_account_for_change:
                user_account=user_account_default
                
            if user_account_for_change:
                user_account=user_account_for_change
                
            
            
            if not user or not password or not server_ip:
                print ("Empty username or password or server IP, finish..")
                sys.exit(1)
            else:
                payload ={
                    "user":user,
                    "password":password
                }
                connector = Connector('https://{}/web_api/'.format(server_ip), payload)
                return {"connector":connector, "user":user_account, "password_hash":password_hash}


        except KeyboardInterrupt:
            print ("\n ctrl+c pressed, exit..")
            sys.exit(1) 



    

def get_targets_data(connector, mapping_list, exceptions):
    """
    get basic OS data from all targets connected to mgmt machine, but in this case just password
    """
    
    targets=connector.send_cmd('show-gateways-and-servers', payload={'limit':500})['objects']
    target_list = []
    

    for item in targets:
        is_there=False
        for item02 in exceptions:
            if item02 == item['name']:
                is_there=True
                break
        if is_there == False:
            target_list.append(item['name'])
            
    print ("targets:{}".format(target_list))
    print ("Waiting 15 secs, if you wanna modify target list by exceptions, hit ctrl+c and edit list in main () method")
    time.sleep(15)
    DoLogging().do_logging("targets:{}".format(target_list))           
    DoLogging().do_logging("\n get_targets_data() - staring..supported commands:\n{}".format(mapping_list))

    # go through list of dicts and map key and value to right possitions
    for box in target_list:
        for item in mapping_list:
            # map key and value - data filed in json and appropriate command for API
            for script_name, command in item.items() :
                # if JSON is empty with data - its emty list od dicts
                
                payload={
                "script-name": script_name,
                "script":command,
                "targets":box
                }
               
                
                print ("target: {}\n script_name:{}\n script:{}\n".format(box,payload['script-name'], payload['script']))
                output_api=connector.run_script(payload)
                DoLogging().do_logging('get_targets_data() - saving commands for script name:{}, output: {}'.format(script_name, output_api))
                       
                
                
def main():
    
    """
    main method where appropriate data methods are triggered
    """
    try:
        os.remove('logcp.elg')
    except:
        pass 
    
    DoLogging().do_logging("\n main() - main starting..")
    data=ask_for_question()
    connector = data['connector']
    password_hash=data['password_hash']
    user=data['user']

    print ("Changing user:{}".format(user),"Password hash is:{}".format(password_hash))
    
    """    
    CMD to boxes you can define new command just by new dict item in list in format:
    
    {name_of_command:command}
    
    """
    
    mapping_list = [
        {"lock database override for sure":"/bin/clish -s -c \'lock database override\'"},
        {"change-password-for-user: {}".format(user):"/bin/clish -s -c \'set user {} password-hash {}\' && /bin/echo $?".format(user,password_hash)},
        
    ]
    
    
    """
    if you want to exclude some targets, just add name here in exceptions
    """
    
    exceptions = ['abc', 'dce']
    
  
    
    try:    
        get_targets_data(connector,mapping_list, exceptions)                   
        connector.logout()
        DoLogging().do_logging("\n main() - main end..")
        print ("More data in logcp.elg, I am done here.")
        
    except KeyboardInterrupt:
        DoLogging().do_logging("\n main() - ctrl+c pressed, logout and exit..")
        connector.logout()
        sys.exit(1) 
    except Exception as e:
        DoLogging().do_logging("\n main() - some error occured, clean up: {}".format(e))
        connector.logout()
        sys.exit(1) 
        
    
    
    
    
    
if __name__ == "__main__":

    main()
