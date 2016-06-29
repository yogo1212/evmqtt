# evmqtt

MQTT implementation based on libevent

the usual meow.

`mqtt_sub --host test.mosquitto.org --port 1883 --verbose -q 2 -t '/conspirancy/#' -q 0 -t "/another/way/to/get/hits/on/google/#"`

`mqtt_sub --host test.mosquitto.org --port 8883 --ssl --cafile mosquitto.org.crt -t '/sensor76/#'`
