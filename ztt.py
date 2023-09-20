#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from pysnmp.hlapi import *
import sys
import time
import threading

app = Flask(__name__)
app_running = False
monitoringRunning = False
app.secret_key = 'your secret here'
socketio = SocketIO(app, async_mode="threading")

onu_results = []

ip = '10.177.55.2'
community = 'ttamiozzo-vrn'
version = 2  # Or the SNMP version you are using
#port_name = sys.argv[1]

def get_port_oid_by_name(ip, community, version, port_name):
    port_oid = None
    port_name_to_find = f'GPON {port_name}'
    print(port_name_to_find)
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData(community, mpModel=version-1),
                              UdpTransportTarget((ip, 161)),
                              ContextData(),
                              ObjectType(ObjectIdentity('IF-MIB', 'ifName')),
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                if port_name_to_find == varBind[1].prettyPrint():
                    oid = str(varBind[0])
                    port_oid = '.'.join(oid.split('.')[-1:])
                    break
    return port_oid

def get_onu_status(ip, community, version, port_oid):
    onu_statuses = []
    oid_base = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9"
    oid_total = f'{oid_base}.{port_oid}'

    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in bulkCmd(SnmpEngine(),
                              CommunityData(community, mpModel=version-1),
                              UdpTransportTarget((ip, 161)),
                              ContextData(), 0, 25,
                              ObjectType(ObjectIdentity(oid_total)),
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                oid = str(varBind[0])
                onu_name = varBind[1].prettyPrint()
                if "_zone" in onu_name:
                    parts = onu_name.split("_zone")
                    onu_name = parts[0]
                index = '.'.join(oid.split('.')[-2:])
                onu_statuses.append((index, onu_name))

    return onu_statuses


def check_onu_status_periodically(socketio, ip, community, version, onu_statuses, port_oid):
    global app_running, monitoringRunning
    while app_running:
        print("=" * 50)
        offline_onus = []
        oid_status = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"
        onu_status_oid_base = f'{oid_status}.{port_oid}'
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in bulkCmd(SnmpEngine(),
                                  CommunityData(community, mpModel=version-1),
                                  UdpTransportTarget((ip, 161)),
                                  ContextData(), 0, 50,
                                  ObjectType(ObjectIdentity(onu_status_oid_base)),
                                  lexicographicMode=False):

            if errorIndication:
                print(errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break

            else:
                for varBind in varBinds:
                    if varBind[1] == 2:
                        oid = str(varBind[0])
                        index = '.'.join(oid.split('.')[-2:])
                        offline_onus.append(index)
        onu_results.clear()  # Limpa a lista global
        for offline_index in offline_onus:
            for onu_index, onu_name in onu_statuses:
                if offline_index == onu_index:
                    onu_results.append(f"ONU offline: {onu_name}")
        time.sleep(5)
        socketio.emit("onu_results", {"onu_results": onu_results}, namespace='/onu')
        print("Emitting onu_results:", onu_results)

    return onu_results


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@socketio.on('start_monitoring', namespace='/onu')
def start_monitoring(data):
    print('=oi=' * 30)
    print(data)
    global app_running
    port_name = data.get('portName')
    port_oid = get_port_oid_by_name(ip, community, version, port_name)
    if port_oid:
        onu_statuses = get_onu_status(ip, community, version, port_oid)
        if onu_statuses:
            app_running = True
            monitoringRunning = True
            threading.Thread(target=check_onu_status_periodically, args=(socketio, ip, community, version, onu_statuses, port_oid)).start()
            print('Final da função')
        else:
            emit('onu_results', {'onu_results': ["Falha ao obter status das ONU"]})
    else:
        emit('onu_results', {'onu_results': [f"Porta {port_name} não encontrada"]})

@socketio.on('stop_monitoring', namespace='/onu')
def stop_monitoring():
    print('=' * 100)
    print('Parou ai')
    global monitoringRunning, app_running
    monitoringRunning = False  # Defina como False quando o botão "Stop Monitoring" for pressionado
    app_running = False


@socketio.on("onu_results")
def handle_onu_results(data):
    print("Received onu_results on the server:", data['onu_results'])
    # Outras ações que você deseja realizar quando recebe o evento
    print('Amigo, estou aqui')  # Adicione esta linha para verificar

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8292, debug=True, allow_unsafe_werkzeug=True)
