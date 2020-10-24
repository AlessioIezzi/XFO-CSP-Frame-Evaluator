from flask import Flask,render_template,request,redirect
import requests
from proxy import *
import sys 
import http.client
import json
import re

from io import BytesIO
import pycurl
import certifi 
import time



app=Flask(__name__)




@app.route('/')
def get_policy_no_method():
    return render_template('index.html',rawUrl='', raw='',error='')

@app.route('/', methods=['POST'])
def get_policy():
    response=FrameCheckResponse()
    
    input_url="" 
     
    if request.method == "POST":
        input_url = request.form.get("input_url")      
        if input_url.strip() != '': 
            try:                 
                response=get_frame_policy(input_url)
                new_head=" "                            
                ori_head=" "
                xfo=" "
                csp=" "
                if response != None:
                    for i in response.original_header:
                        ori_head=ori_head+i+" "                    
                    for i in response.new_xfo_policy:                            
                        xfo=xfo+i+" "
                        new_head=new_head+i+" "
                    for i in response.new_csp_policy:                            
                        csp=csp+i+" "
                        new_head=new_head+i+" "
                    if new_head.strip()=='':
                        new_head=''
                    if response.flag_code['no_policy']==1:
                        return render_template("index.html",rawUrl='', raw='',error='',alert=True)
                    else:
                        if response.flag_code['error_url']!="":
                            return render_template("index.html",rawUrl=ori_head, 
                                                                    raw=new_head,
                                                                    advices=response.errors,
                                                                    error='The server response contains an error: '+response.flag_code['error_url'],
                                                                    ok_policy=response.ok_policy,
                                                                    information=response.information,
                                                                    not_found=response.not_found,
                                                                    xfo=xfo,
                                                                    csp=csp)                         
                        else:
                            if response.flag_code['malformed_XFO']==1:
                                return render_template("index.html",rawUrl=ori_head, raw='',advices=response.errors,error='')
                            else:
                                return render_template("index.html", rawUrl=ori_head, 
                                                                    raw=new_head,
                                                                    advices=response.errors,
                                                                    error='',
                                                                    ok_policy=response.ok_policy,
                                                                    information=response.information,
                                                                    not_found=response.not_found,
                                                                    xfo=xfo,
                                                                    csp=csp) 
                else:
                    return render_template("index.html",rawUrl='', raw='',error='URL unreachable') 
            except Exception as e:
                print("exeption " ,e)             
            input_url=""
            return render_template("index.html",rawUrl='', raw='',error='URL unreachable')
        else:            
            return render_template("index.html",rawUrl='', raw='',error='')    
       
  
  

 


def get_frame_policy(input_url) -> FrameCheckResponse:
   
    response_object=FrameCheckResponse()
    input_url=input_url.strip()
    host=input_url

    if input_url.startswith('https://')==True or input_url.startswith('http://')==True:
        response_object.flag_code['error_url']="write only hostname"
        return response_object
    
    
    print(input_url)
    if input_url.endswith('/')==True :
        new_text = input_url.rstrip('/')
        input_url=new_text

    host= re.sub(r'/.*','',host)

    try:         
        input_url='http://'+input_url 
        response = requests.get(input_url,timeout=10)
        print(response.url) 
    except Exception as e: 
        try:           
            input_url='https://'+input_url
            response = requests.get(input_url,timeout=10)
            print(response.url)
        except Exception as e:
            print("exeption " ,e)
            response_object.flag_code['error_url']=e
            return response_object
    #creo byte response header dall'header che ricevo    
    if response.status_code == 200:
        byte_header:bytes=b"HTTP/1.1 200 OK\r\n"       
        for k, v in response.headers.items():
            byte_header=byte_header+bytes(k.lower() +' : '+v.lower() +'\r\n','utf-8')
        byte_header=byte_header+ b'host:'+ b'\''+bytes(host,'utf-8')+ b'\'\r\n'                 
               
        response_object=proxy(byte_header,input_url)  
        if response_object != None:  
            response_object.flag_code['response_code']=str(response.status_code)     
    else: 
        byte_header:bytes=b"HTTP/1.1 200 OK\r\n"       
        for k, v in response.headers.items():
            byte_header=byte_header+bytes(k.lower() +' : '+v.lower() +'\r\n','utf-8')
        byte_header=byte_header+ b'host:'+ b'\''+bytes(host,'utf-8')+ b'\'\r\n'                 
                   
        response_object=proxy(byte_header,input_url)     
        response_object.flag_code['error_url']=str(response.status_code)        
        response_object.error=True  

    return response_object 
    
  





@app.route('/test')
def test():
    try:        
        file=open('10k_tranco_url_13-09.txt','r')
        content = file.readlines()
        f2 = open("10k_tranco_url_13-09.csv", "w")
       
        count=1
        f2.write('url,status_code,policy_definition, inconsistency, which_policy,allow_from_inconsistency\n')
        for line in content:              
            response=get_frame_policy(line)                    
            print(str(count)+" : "+line)
            count=count+1
            if response != None:                
                f2.write(response.analysis.url)
                f2.write(',')  
                f2.write(response.flag_code['response_code'])
                f2.write(',')  
                f2.write(response.analysis.policy_definition)
                f2.write(',')
                f2.write(response.analysis.inconsistency)
                f2.write(',')
                f2.write(response.analysis.which_policy)
                f2.write(',')
                f2.write(response.analysis.allow_from_inconsistency)                
                f2.write('\n')  
        f2.close()          
        return 'OK'

    except Exception as e:
        print("exeption " ,e)   
        return 'ERROR' 
    
    

if __name__ == "__main__":
    app.run(debug=True)

