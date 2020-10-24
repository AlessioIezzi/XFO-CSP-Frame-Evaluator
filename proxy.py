from utils import get_browser_from_user_agent, parse_csp, parse_headers, csp_match
from interceptor import InterceptorV4, InterceptorV6
from urllib.parse import urlparse
import traceback
import argparse

import json


request_to_response = dict()  # Dictionary to map requests to their responses.

class Analysis:
    url=""
    policy_definition=""
    inconsistency=""
    allow_from_inconsistency=""
    which_policy=""
    def __init__(self):
        self.url=""
        self.inconsistency=""
        self.noPolicy=""
        self.which_policy=""

 
class FrameCheckResponse:
    original_header=list()
    new_header=list()
    errors=list()
    flag_code={
        "no_policy":0,
        "error_url":"",
        "both":0,
        'malformed_XFO':0,
        'response_code':""
    }
    new_header_bytes=bytes()
    ok_policy=list()
    information=list()
    not_found=list()
    new_xfo=list()
    new_csp=list()
    analysis=Analysis()

    def __init__(self):
        self.original_header = []
        self.new_header=[]
        self.errors=[]
        self.not_found=[]
        self.information=[]
        self.flag_code['no_policy']=0
        self.flag_code['error_url']=""
        self.flag_code['both']=0
        self.flag_code['malformed_XFO']=0
        self.flag_code['response_code']=""
        self.new_header_bytes=b''
        self.ok_policy=[]
        self.new_xfo_policy=[]
        self.new_csp_policy=[]
        self.analysis=Analysis()

  
def retrofit_headers(original_headers: dict,input_url:str) -> FrameCheckResponse:
    """
    Retrofits the apparent security header to match the needs of the client

    :param original_headers: Dictionary of headers send by the Web application
    :param input_url: URL string
    :return: Dictionary of retrofitted headers
    """
    frame_response=FrameCheckResponse()
    
    new_headers = original_headers.copy()
    analysis=Analysis()
    analysis.url=input_url
    errorsCSP=list()
    errorsXFO=list() 
    errorsCSP=[]
    errorsXFO=[]
    # Check for CSP and XFO header being present
    has_xfo = b'x-frame-options' in original_headers
    has_csp = b'content-security-policy' in original_headers
    # Extract XFO header
    xfo = None
    if has_xfo:        
        xfo = original_headers[b'x-frame-options'].strip()
        if xfo == b'':
            has_xfo=False
            errorsXFO.append('X-Frame-Options policies are empty')
        else:
            frame_response.original_header.append('X-Frame-Options: '+xfo.decode('utf-8'))  
            frame_response.new_xfo_policy.append('X-Frame-Options: '+xfo.decode('utf-8'))      
    # Extract frame-ancestors directive from CSP
    has_fa = False
    frame_ancestors = None
    if has_csp:        
        csp = original_headers[b'content-security-policy']        
        parsed_csp = parse_csp(csp)        
        if b'frame-ancestors' in parsed_csp:            
            has_fa = True
            frame_ancestors = parsed_csp[b'frame-ancestors']
            frame_response.original_header.append('frame-ancestors ')
            frame_response.new_csp_policy.append('frame-ancestors ')
            for i in frame_ancestors:
                frame_response.original_header.append(i.decode('utf-8'))
                frame_response.new_csp_policy.append(i.decode('utf-8'))
    # If the ste deploys neither XFO nor CSP ...
    if not has_xfo and not has_fa:
        # ... we can not retrofit anything
        analysis.which_policy='no_policy'
        print('errore nessuna policy di gestione dei frame')
        frame_response.flag_code['no_policy']=1     
 
    if has_xfo:
        error=False
        xfo_headers = xfo.lower().split(b',')
        xfo_modes = list()
        xfo_values = list()
        for el in xfo_headers:
            tmp = el.strip().split()
            xfo_modes.append(tmp[0])
            xfo_values.append(tmp[1:])  
        if len(xfo_modes) <= 1:         
            if xfo_modes[0] == b'allow-from': 
                if len(xfo_values[0]) > 1:
                    analysis.allow_from_inconsistency='allow_from_use_with_more_origin'
                    errorsXFO.append('allow from use with more origin')
                    for x in xfo_values[0]:
                        if '*' in str(x):
                            error=1
                            analysis.allow_from_inconsistency='allow_from_use_with_more_origin_and_wrong_sintax'   
                else:
                    if '*' in str(xfo_values[0]):
                        analysis.allow_from_inconsistency='allow_from_use_with_one_origin_and_wrong_sintax'
                        error=2

        else:
            if b'allow-form' in xfo_modes:
                if len(xfo_values[0]) > 1:
                    analysis.allow_from_inconsistency='allow_from_use_with_more_origin'
                    errorsXFO.append('allow from use with more origin')
                    for x in xfo_values[0]:
                        if '*' in str(x):
                            error=1
                            analysis.allow_from_inconsistency='allow_from_use_with_more_origin_and_wrong_sintax'
                else:
                    if '*' in str(xfo_values[0]):
                        analysis.allow_from_inconsistency='allow_from_use_with_one_origin_and_wrong_sintax'
                        error=2
                            
        if error==1:
            errorsXFO.append('allow from use with more origin and wrong origin\'s sintax (* use)')
        elif error==2:
            errorsXFO.append('allow from use with single origin but wrong origin\'s sintax (* use)')
            
    if has_xfo and not has_fa: 
        analysis.which_policy='only_xfo'
        print('solo x-frame-option') 
        compare_xfo=''
        frame_response.ok_policy.append("X-Frame-Options")
        frame_response.not_found.append('CSP frame ancestors not deployed')       
        new_csp = b''
        new_xfo=b''
        xfo_headers = xfo.lower().split(b',')
        xfo_modes = list()
        xfo_values = list()
        for el in xfo_headers:
            tmp = el.strip().split()
            xfo_modes.append(tmp[0])
            xfo_values.append(tmp[1:])
 
        if len(xfo_modes) <= 1:                                
            if xfo_modes[0] == b'sameorigin':
                analysis.policy_definition='policy_consistent'
                frame_response.information.append('policy consistent, you should add the CSP policy')
                errorsXFO.append('Add frame-ancestors \'self\' for modern browsers')
                print('x-frame-option: sameorigin => add frame-ancestors self' )
                new_csp = b"frame-ancestors 'self'"
            elif xfo_modes[0] == b'deny':
                analysis.policy_definition='policy_consistent'
                frame_response.information.append('policy consistent, you should add the CSP policy')
                errorsXFO.append('Add frame-ancestors \'none\' for modern browsers')
                print('x-frame-option: deny => add frame-ancestors none' )
                new_csp = b"frame-ancestors 'none'"
            elif xfo_modes[0] == b'allow-from':  
                analysis.policy_definition='policy_inconsistent'
                analysis.inconsistency='allow_from_use'                  
                frame_response.ok_policy=[]             
                errorsXFO.append('Inconsistent policy')
                errorsXFO.append('The use of allow from directive is deprecated, some browsers don\'t recognized it. Should you change it with frame-ancestor directive')                
                frame_response.new_csp_policy=[]
                frame_response.new_xfo_policy=[]              
            else: 
                analysis.policy_definition='policy_inconsistent'
                analysis.inconsistency='malformed_xfo_header' 
                errorsXFO.append('Malformed XFO Header')
                frame_response.information=[]
                frame_response.not_found=[]
                new_headers[b'Debug-FrameProxy-Error-MSG'] = b'Malformed XFO Header!'
                new_headers[b'Debug-FrameProxy-Error-Data'] = xfo
                frame_response.flag_code['malformed_XFO']=1
                frame_response.new_csp_policy=[]
                frame_response.new_xfo_policy=[]
        else:   
            change=0
            for policy in xfo_modes:
                new_xfo=new_xfo+b' '+policy 
            compare_xfo=new_xfo
            errorsCSP.append('Inconsistent comma-separated policy or multiple header use, the behavior of these policy will be different in some browsers')           
            analysis.policy_definition='policy_inconsistent'
            analysis.inconsistency='multiple-header-comma_separated_policy' 
            if b'deny' in xfo_modes:              
                change=1                
                errorsXFO.append('Add frame-ancestors \'none\' for modern browsers')
                new_csp = b"frame-ancestors 'none'" 
                new_xfo = b'DENY'
                errorsXFO.append('Change x-frame-options enforcing the same security restrictions of the conjunction of the directives (Table 8)')                
            elif b'sameorigin' in xfo_modes:
                for i, x in enumerate(xfo_modes):
                    change=1  
                    if x == b'allow-from':
                        for origin in xfo_values[i]:                                                   
                            if new_headers[b'host'] != urlparse(origin).netloc:
                                errorsXFO.append('Add frame-ancestors \'none\' for modern browsers') 
                                new_csp = b"frame-ancestors 'none'"
                                new_xfo = b'DENY'
                                errorsXFO.append('Change x-frame-options enforcing the same security restrictions of the conjunction of the directives (Table 8)')                                                   
                                break
                            else:                                 
                                new_csp = b"frame-ancestors 'self'"
                                new_xfo = b'SAMEORIGIN'                            
                    else:                
                        new_csp = b"frame-ancestors 'self'"
                        new_xfo = b'SAMEORIGIN'                        
                        break
                if new_xfo == b'SAMEORIGIN':
                    errorsXFO.append('Add frame-ancestors \'self\' for modern browsers')
                errorsXFO.append('Change x-frame-options enforcing the same security restrictions of the conjunction of the directives (Table 8)')                                                                           
            elif b'allow-form' in xfo_modes:  
                frame_response.information=[]
                frame_response.not_found=[]
                frame_response.new_csp_policy=[]
                frame_response.new_xfo_policy=[]
                errorsXFO.append('The use of allow from directive is deprecated, some browsers don\'t recognized it. Should you change it with frame-ancestor directive')                
            else: 
                errorsXFO.append('Malformed XFO Header')
                frame_response.information=[]
                frame_response.not_found=[]
                frame_response.flag_code['malformed_XFO']=1
                frame_response.new_csp_policy=[]
                frame_response.new_xfo_policy=[]
            if compare_xfo!=new_xfo:
                frame_response.ok_policy=[]       
            if change==1 :            
                frame_response.new_xfo_policy=[]   
                frame_response.new_xfo_policy.append('X-Frame-options: '+new_xfo.decode("utf-8"))
        
        if new_csp != b'':            
            frame_response.new_csp_policy.append(new_csp.decode("utf-8"))

            
             
    elif has_fa and has_xfo:
        new_xfo=b''                
        analysis.which_policy='fa_and_xfo'
        change=0
        compare_xfo=b''
        xfo_headers = xfo.lower().split(b',')
        xfo_modes = list()
        xfo_values = list()
        for el in xfo_headers:
            tmp = el.strip().split()
            xfo_modes.append(tmp[0])
            xfo_values.append(tmp[1:])
        #ANALISI 
        
        if len(xfo_modes) <= 1: 
            new_xfo=new_xfo+xfo_modes[0]
            compare_xfo=new_xfo
            if xfo_modes[0] == b'allow-from':
                analysis.policy_definition='policy_inconsistent'
                analysis.inconsistency='allow_from_use' 
                errorsXFO.append('Inconsistent policy')
                errorsXFO.append('The use of allow from directive is deprecated, some browsers don\'t recognized it')
            elif xfo_modes[0] != b'sameorigin' and xfo_modes[0] != b'deny':
                analysis.policy_definition='policy_inconsistent'
                analysis.inconsistency='malformed_xfo_header' 
                errorsXFO.append('Malformed XFO Header')
                frame_response.information.append('Inconsistent policy')
                frame_response.flag_code['malformed_XFO']=1 
            else:
                if frame_ancestors == {b"'none'"} or frame_ancestors == {b'"none"'}:
                    if xfo_modes[0] == b'deny':
                        frame_response.information.append('Policy Consistent')
                        analysis.policy_definition='policy_consistent'                   
                    elif xfo_modes[0] == b'sameorigin':       
                        frame_response.information.append('compatibility oriented')  
                        analysis.policy_definition='compatibility_oriented'                                                                                                
                elif frame_ancestors == {b"'self'"} or frame_ancestors == {b'"self"'}:
                    if xfo_modes[0] == b'sameorigin':
                        analysis.policy_definition='policy_consistent'
                        frame_response.information.append('Policy Consistent')
                    elif xfo_modes[0] == b'deny':
                        errorsXFO.append('security oriented policy') 
                        analysis.policy_definition='security_orienterd'                                       
                else:
                    if xfo_modes[0] == b'sameorigin':     
                        frame_response.information.append('Policy not comparable')  
                        analysis.policy_definition='policy_inconsistent'
                        analysis.inconsistency='not_comparable'                                    
                    elif xfo_modes[0] == b'deny':
                        analysis.policy_definition='security_orienterd'
                        frame_response.information.append('Security oriented policy: more security for legacy browsers at the expense of more framing restrictions, may cause compatibility problems')                                                     
        else:     
            errorsCSP.append('Inconsistent comma-separated policy or multiple header use, the behavior of these policy will be different in some browsers')
            analysis.policy_definition='policy_inconsistent'
            analysis.inconsistency='multiple-header-comma_separated_policy'
            
        #SINTESI    
        if frame_ancestors == {b"'none'"} or frame_ancestors == {b'"none"'}: 
            change=1              
            new_xfo = b'DENY'      
            new_headers[b'x-frame-options'] = new_xfo
        elif frame_ancestors == {b"'self'"} or frame_ancestors == {b'"self"'}: 
            change=1               
            new_xfo = b'SAMEORIGIN'  
            new_headers[b'x-frame-options'] = new_xfo     
        else: 
            if len(xfo_modes) <= 1:                
                if xfo_modes[0] != b'deny' and xfo_modes[0] != b'sameorigin':
                    change=1
                    new_xfo = b'DENY' 
            else:
                change=1
                if b'deny' in xfo_modes:                      
                    new_xfo = b'DENY'                        
                elif b'sameorigin' in xfo_modes:
                    for i, x in enumerate(xfo_modes):
                        if x == b'allow-from':                                                        
                            for origin in xfo_values[i]:                               
                                if new_headers[b'host'] != urlparse(origin).netloc:
                                    new_xfo = b'DENY'
                                    break
                                else:
                                    new_xfo = b'SAMEORIGIN'
                        else:
                            new_xfo = b'SAMEORIGIN'                                                  
                else:
                    new_xfo = b'DENY'
        if change==1 :            
            frame_response.new_xfo_policy=[]   
            frame_response.new_xfo_policy.append('X-Frame-options: '+new_xfo.decode("utf-8"))        
        frame_response.ok_policy.append("Frame-ancestors")


    elif has_fa and not has_xfo:    
        analysis.which_policy='only_fa'
        frame_response.information.append('Compatibility oriented policy, sacrifice security for compatibility of framing on legacy browsers')
        frame_response.not_found.append('X-Frame-Options not deployed')       
        analysis.policy_definition='compatibility_oriented'      
        if frame_ancestors == {b"'none'"} or frame_ancestors == {b'"none"'}: 
            errorsCSP.append('Add DENY for the protection and compatibility of legacy browsers')                
            new_xfo = b'DENY'
            frame_response.new_xfo_policy.append('X-Frame-options: '+new_xfo.decode("utf-8"))        
            new_headers[b'x-frame-options'] = new_xfo
        elif frame_ancestors == {b"'self'"} or frame_ancestors == {b'"self"'}: 
            errorsCSP.append('Add SAMEORIGIN for the protection and compatibility of legacy browsers')                
            new_xfo = b'SAMEORIGIN'
            frame_response.new_xfo_policy.append('X-Frame-options: '+new_xfo.decode("utf-8"))   
            new_headers[b'x-frame-options'] = new_xfo     
        else:
            errorsCSP.append('Used frame ancestor with more origin, add deny if you want to make browsers legacy safe ')  
            frame_response.new_csp_policy=[]
            frame_response.new_xfo_policy=[]                           
    frame_response.errors=errorsCSP+errorsXFO
    frame_response.new_header_bytes=new_headers   
    frame_response.analysis=analysis    
    return frame_response 
  
def proxy(data: bytes,input_url:str) -> FrameCheckResponse:
    frame_response=FrameCheckResponse()
    raw_response_head=list()
    raw_response_head=[]
    try:        
        if not data.startswith(b'HTTP'):
            return data
        data_split = data.split(b'\r\n\r\n')
        raw_head = data_split[0]
        raw_body = b'\r\n\r\n'.join(data_split[1:])
        headers = parse_headers(raw_head)
        frame_response= retrofit_headers(headers,input_url)
        new_headers=frame_response.new_header_bytes
        
        if frame_response.flag_code['no_policy']==0:
            for name, value in new_headers.items():
                raw_response_head.append(name + b': ' + value)
            raw_response_head = b'\r\n'.join(raw_response_head)
            frame_response.new_header_bytes=raw_response_head + b'\r\n\r\n' + raw_body         
            return  frame_response
    except Exception as e:
        print('Unexpected Exception', e)
        traceback.print_exc()
    frame_response.new_header_bytes=data
    
    return  frame_response

