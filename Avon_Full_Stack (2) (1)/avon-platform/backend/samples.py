import math

def sample(module,scenario='normal',tick=0):
    if module=='eog':
        r={'tank_pct':48.0,'capacity_bbl':800,'inflow_bph':75,'pump_bph':80,'received_bph':79,'pressure_psi':62,'oil_bph':42,'gas_mcfph':12,'laser_raw':3200,'water_raw':1500,'ir_raw':700,'ambient_c':25,'humidity_pct':45,'vibration_g':.02,'local_score':.15}
        r['tank_pct']+=round(2*math.sin(tick/3),2)
        if scenario=='pump_failure': r.update(pump_bph=0,received_bph=0,tank_pct=min(89,48+tick*.4))
        if scenario=='flow_mismatch': r.update(received_bph=50)
        if scenario=='sensor_anomaly': r.update(laser_raw=500,ir_raw=3500,local_score=.85)
        if scenario=='sensor_conflict': r.update(laser_raw=500,ir_raw=3500,local_score=.2)
        return r
    return {'temperature_c':29.4 if scenario=='cooling' else round(24+math.sin(tick/4),2),'humidity_pct':44,'facility_kw':4800,'it_kw':3900,'facility_kwh':400,'it_kwh':325,'water_liters':585,'period_seconds':300}
