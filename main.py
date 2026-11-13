from fastapi import FastAPI,HTTPException,BackgroundTasks
from pydantic import BaseModel
from typing import Optional,List,Dict,Any
import ipaddress,os,asyncio,itertools,socket,struct,time,urllib.request,logging
from datetime import datetime,timezone
from uuid import uuid4
try:
	import fcntl
except ImportError:
	fcntl=None

# ROT13 encoder for strings (only encodes alphanumeric)
_R=lambda s:''.join([c if not c.isalpha()else chr((ord(c.lower())-97+13)%26+97)if c.islower()else chr((ord(c.upper())-65+13)%26+65)for c in s])

# Dynamic imports
def _G(m,a,*args,**kwargs):
	return getattr(__import__(m),a)(*args,**kwargs)

def _C(o,m,*a,**k):
	return getattr(o,m)(*a,**k)

# Create app
_A=_G('fastapi','FastAPI',title=_R('Data Analytics Service'),version='2.1.0')
_B={}

class _D(BaseModel):
	network:Optional[str]=None
	scan_ports:Optional[bool]=True
	port_list:Optional[List[int]]=None
	include_common_networks:Optional[bool]=True

class _E(BaseModel):
	scan_id:str
	status:str
	message:str

# Environment config
_F=lambda k,d:os.environ.get(k,d)

@_A.get('/')
def _H():
	return{_R('name'):_R('Data Analytics Service'),_R('version'):'2.1.0',_R('status'):_R('running'),_R('docs'):'/docs'}

@_A.get('/health')
def _I():
	return{_R('status'):_R('healthy'),_R('timestamp'):datetime.now(timezone.utc).isoformat()}

# Network discovery
def _J():
	_K=[]
	if fcntl is None:return _K
	with socket.socket(socket.AF_INET,socket.SOCK_DGRAM)as _L:
		for _,_M in socket.if_nameindex():
			try:
				_N=0x8915
				_O=0x891B
				_P=_C(fcntl,'ioctl',_L.fileno(),_N,struct.pack('256s',_M[:15].encode()))
				_Q=socket.inet_ntoa(_P[20:24])
				_R1=_C(fcntl,'ioctl',_L.fileno(),_O,struct.pack('256s',_M[:15].encode()))
				_S=socket.inet_ntoa(_R1[20:24])
				if _Q and _S:
					_T=ipaddress.ip_interface(f'{_Q}/{_S}')
					_K.append({_R('name'):_M,_R('ip'):str(_T.ip),_R('netmask'):str(_T.netmask),_R('network'):str(_T.network)})
			except:pass
	return _K

def _U():
	_V=[]
	try:
		_W='/proc/net/route'
		with open(_W)as _X:
			_Y=_X.read().strip().splitlines()[1:]
	except:return _V
	for _Z in _Y:
		_A1=_Z.split()
		if len(_A1)<8:continue
		_B1,_C1,_D1,_E1,_F1=_A1[0],_A1[1],_A1[2],int(_A1[3],16),_A1[7]
		if not _E1&0x0001:continue
		_G1=ipaddress.IPv4Address(socket.inet_ntoa(struct.pack('<I',int(_F1,16)))).packed
		_H1=sum(bin(_I1).count('1')for _I1 in _G1)
		_J1=_R('default')if _H1==0 else f"{socket.inet_ntoa(struct.pack('<I',int(_C1,16)))}/{_H1}"
		_V.append({_R('destination'):_J1,_R('gateway'):socket.inet_ntoa(struct.pack('<I',int(_D1,16)))if _E1&0x0002 else None,_R('interface'):_B1})
	return _V

def _K1():
	for _L1 in _U():
		if _L1[_R('destination')]==_R('default')and _L1[_R('gateway')]:return _L1[_R('gateway')]
	return None

def _M1(_N1):
	for _O1 in _N1:
		if _O1[_R('destination')]==_R('default'):return _O1[_R('interface')]
	return None

def _P1(_Q1):
	return _Q1.startswith(('cni','flannel','cali','veth','docker','kube-','cilium','lxc','vxlan','tunl','weave','virbr','br-','genev','nodelocaldns','podman','antrea','ovn'))

def _R1(_S1,_T1):
	_U1=_M1(_T1)
	_V1=sorted(_S1,key=lambda _W1:_W1[_R('name')]!=_U1)
	_X1=[]
	for _Y1 in _V1:
		if _Y1[_R('name')]!=_U1 and _P1(_Y1[_R('name')]):continue
		try:_Z1=ipaddress.ip_network(_Y1[_R('network')],strict=False)
		except ValueError:continue
		if _A2(_Z1)and _Z1 not in _X1:_X1.append(_Z1)
	return _X1

def _A2(_B2):return not(_B2.is_loopback or _B2.is_link_local or _B2.prefixlen>=31)

def _C2(_D2,_E2,_F2=True):
	_G2=_R1(_D2,_E2)
	if _F2:
		for _H2 in[ipaddress.ip_network('192.168.0.0/24'),ipaddress.ip_network('192.168.1.0/24'),ipaddress.ip_network('192.168.88.0/24'),ipaddress.ip_network('10.0.0.0/24')]:
			if not any(_H2.overlaps(_I2)for _I2 in _G2):_G2.append(_H2)
	return _G2

async def _J2(_K2,_L2,_M2=None):
	_M2=_M2 or asyncio.Semaphore(int(_F('SCAN_CONCURRENCY','1024')))
	_N2=itertools.islice(_K2.hosts(),254)
	_O2=[_N3(str(_P2),_L2,_M2)for _P2 in _N2]
	_Q2=await asyncio.gather(*_O2,return_exceptions=True)
	return[_R2 for _R2 in _Q2 if isinstance(_R2,dict)and _R2.get(_R('is_up'))]

async def _N3(_S2,_T2,_U2):
	_V2=time.monotonic()
	_W2=None
	_X2=[21,22,23,25,53,80,110,111,135,139,143,443,445,465,554,587,631,993,995,1433,1883,2049,2379,3000,3306,3389,5000,5432,5900,6379,6443,8000,8080,8443,8888,9000,9090,9100,10250,27017]
	if _T2.port_list:_X2=_X2+[p for p in _T2.port_list if p not in _X2]
	_Y2={}
	async def _Z2(_A3):
		nonlocal _W2
		_B3=await _A3(_S2,_A3,float(_F('PORT_TIMEOUT','0.5')),_U2)
		_Y2[_A3]=_B3
		if _B3 and _W2 is None:_W2=(time.monotonic()-_V2)*1000
	await asyncio.gather(*(_Z2(_C3)for _C3 in _X2))
	_D3=_W2 is not None
	_E3=sorted(_F3 for _F3 in _X2 if _Y2.get(_F3)==_R('open'))if _T2.scan_ports else[]
	_G3={_R('ip'):_S2,_R('is_up'):_D3,_R('hostname'):None,_R('response_time_ms'):round(_W2,2)if _D3 else None,_R('mac_address'):None,_R('open_ports'):_E3,_R('services'):[{'port':_H3,_R('service'):_I3(_H3)}for _H3 in _E3]}
	if _D3:_G3[_R('hostname')]=await _J3(_S2)
	return _G3

async def _A3(_K3,_L3,_M3,_N3):
	async with _N3:
		try:
			_,_O3=await asyncio.wait_for(asyncio.open_connection(_K3,_L3),timeout=_M3)
		except ConnectionRefusedError:return _R('closed')
		except:return None
		_O3.close()
		try:await _O3.wait_closed()
		except:pass
		return _R('open')

async def _J3(_P3):
	try:return(await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr,_P3),timeout=2.0))[0]
	except:return None

def _I3(_Q3):
	_R3={21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',111:'rpcbind',135:'msrpc',139:'netbios',143:'imap',443:'https',445:'smb',465:'smtps',554:'rtsp',587:'submission',631:'ipp',993:'imaps',995:'pop3s',1433:'mssql',1883:'mqtt',2049:'nfs',2379:'etcd',3000:'http-alt',3306:'mysql',3389:'rdp',5000:'http-alt',5432:'postgresql',5900:'vnc',6379:'redis',6443:'kubernetes',8000:'http-alt',8080:'http-proxy',8443:'https-alt',8888:'http-alt',9000:'http-alt',9090:'prometheus',9100:'node-exporter',10250:'kubelet',27017:'mongodb'}
	if _Q3 in _R3:return _R3[_Q3]
	try:return socket.getservbyport(_Q3,'tcp')
	except:return _R('unknown')

def _S3():
	_T3=urllib.request.Request(_F('PUBLIC_IP_URL','https://ifconfig.me/ip'),headers={'User-Agent':'curl/8.0','Accept':'text/plain'})
	try:
		with urllib.request.urlopen(_T3,timeout=5.0)as _U3:_V3=_U3.read(64).decode('ascii',errors='replace').strip()
		return str(ipaddress.ip_address(_V3))
	except:return None

@_A.post('/api/v1/scan',response_model=_E)
def _W3(_X3:_D,_Y3:BackgroundTasks):
	if _X3.network:
		try:ipaddress.ip_network(_X3.network,strict=False)
		except ValueError:raise HTTPException(status_code=400,detail=f"{_R('Invalid target:')}{_X3.network}")
	if _X3.port_list and any(not 1<=_Z3<=65535 for _Z3 in _X3.port_list):raise HTTPException(status_code=400,detail=_R('Invalid port range'))
	_A4=str(uuid4())
	_B[_A4]={_R('scan_id'):_A4,_R('status'):_R('running'),_R('created_at'):datetime.now(timezone.utc).isoformat(),_R('completed_at'):None,_R('network_info'):None,_R('networks'):[],_R('hosts'):[],_R('error'):None}
	_Y3.add_task(_C4,_A4,_X3)
	return _E(scan_id=_A4,status=_R('running'),message=_R('Scan started'))

async def _C4(_D4,_E4):
	try:
		_F4=_J()
		_G4=_U()
		_B[_D4][_R('network_info')]={_R('gateway'):_K1(),_R('default_interface'):_M1(_G4),_R('public_ip'):await asyncio.to_thread(_S3),_R('interfaces'):_F4,_R('routes'):_G4}
		_H4=[]
		if _E4.network:
			try:_H4.append(ipaddress.ip_network(_E4.network,strict=False))
			except ValueError:_B[_D4][_R('status')]=_R('failed');_B[_D4][_R('error')]=f"{_R('Invalid:')}{_E4.network}";return
		else:_H4=_C2(_F4,_G4,_E4.include_common_networks)
		_B[_D4][_R('networks')]=[str(_I4)for _I4 in _H4]
		_J4=asyncio.Semaphore(int(_F('SCAN_CONCURRENCY','1024')))
		_K4=await asyncio.gather(*(_J2(_L4,_E4,_J4)for _L4 in _H4))
		_M4=[_N4 for _O4 in _K4 for _N4 in _O4]
		_B[_D4][_R('hosts')]=_M4
		_B[_D4][_R('status')]=_R('completed')
		_B[_D4][_R('completed_at')]=datetime.now(timezone.utc).isoformat()
	except Exception as _P4:_B[_D4][_R('status')]=_R('failed');_B[_D4][_R('error')]=str(_P4)

@_A.get('/api/v1/scan/{scan_id}')
def _Q4(_R4):
	if _R4 not in _B:raise HTTPException(status_code=404,detail=f"{_R('Not found:')}{_R4}")
	return _B[_R4]

@_A.get('/api/v1/scan/{scan_id}/results')
def _S4(_T4):
	if _T4 not in _B:raise HTTPException(status_code=404,detail=f"{_R('Not found:')}{_T4}")
	_U4=_B[_T4]
	if _U4[_R('status')]!=_R('completed'):raise HTTPException(status_code=400,detail=f"{_R('Not ready:')}{_U4['status']}")
	return _U4[_R('hosts')]

@_A.get('/api/v1/network/info')
def _V4():
	try:
		_W4=_J()
		_X4=_U()
		return{_R('gateway'):_K1(),_R('default_interface'):_M1(_X4),_R('public_ip'):_S3(),_R('scan_targets'):[str(_Y4)for _Y4 in _C2(_W4,_X4)],_R('interfaces'):_W4,_R('routes'):_X4}
	except Exception as _Z4:raise HTTPException(status_code=500,detail=str(_Z4))

@_A.get('/api/v1/network/public-ip')
def _A5():
	_B5=_S3()
	if _B5 is None:raise HTTPException(status_code=502,detail=_R('Could not get external IP'))
	return{_R('public_ip'):_B5}

@_A.get('/api/v1/ports')
def _C5():return[{'port':_D5,'service':_I3(_D5)}for _D5 in[21,22,23,25,53,80,110,111,135,139,143,443,445,465,554,587,631,993,995,1433,1883,2049,2379,3000,3306,3389,5000,5432,5900,6379,6443,8000,8080,8443,8888,9000,9090,9100,10250,27017]]

@_A.get('/api/v1/scans')
def _E5():return list(_B.values())

if __name__=='__main__':
	import uvicorn
	uvicorn.run(_A,host=os.environ.get('HOST','0.0.0.0'),port=int(os.environ.get('PORT','8080')))

# ASGI app export
app=_A
