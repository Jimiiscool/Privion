/* ESP32 DevKit (classic ESP32), USB serial JSONL at 115200 baud.
   This is a bench prototype. Outputs are raw or ambient readings, not oil identification.
   Install Adafruit DHT sensor library and its dependencies in Arduino IDE.
   Hardware voltage, pin availability, calibration and enclosure must be checked locally. */
#include <Wire.h>
#include <DHT.h>
#include <math.h>
const int LASER_ADC=34, WATER_ADC=35, IR_ADC=32, DHT_PIN=4;
const uint8_t MPU_ADDR=0x68;
DHT dht(DHT_PIN,DHT11);
bool mpu=false;
void writeMPU(uint8_t reg,uint8_t value){Wire.beginTransmission(MPU_ADDR);Wire.write(reg);Wire.write(value);Wire.endTransmission();}
void setup(){
  Serial.begin(115200);analogReadResolution(12);Wire.begin(21,22);dht.begin();
  Wire.beginTransmission(MPU_ADDR);mpu=Wire.endTransmission()==0;
  if(mpu){writeMPU(0x6B,0);writeMPU(0x1C,0);}
}
void loop(){
  int light=analogRead(LASER_ADC),water=analogRead(WATER_ADC),ir=analogRead(IR_ADC);
  float temperature=dht.readTemperature(),humidity=dht.readHumidity();
  Serial.printf("{\"laser_raw\":%d,\"water_raw\":%d,\"ir_raw\":%d",light,water,ir);
  if(isfinite(temperature))Serial.printf(",\"ambient_c\":%.2f",temperature);
  if(isfinite(humidity))Serial.printf(",\"humidity_pct\":%.2f",humidity);
  if(mpu){
    Wire.beginTransmission(MPU_ADDR);Wire.write(0x3B);Wire.endTransmission(false);
    if(Wire.requestFrom(MPU_ADDR,(uint8_t)6)==6){
      int16_t x=(Wire.read()<<8)|Wire.read(),y=(Wire.read()<<8)|Wire.read(),z=(Wire.read()<<8)|Wire.read();
      float gx=x/16384.0f,gy=y/16384.0f,gz=z/16384.0f;
      Serial.printf(",\"vibration_g\":%.4f",fabsf(sqrtf(gx*gx+gy*gy+gz*gz)-1.0f));
    }
  }
  Serial.println("}");delay(2500);
}
