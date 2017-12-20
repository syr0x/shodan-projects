import multiprocessing
import os
import requests
import time
import http.client
import shodan
import sys

shodanKey = ""

if len(sys.argv) != 1:
    print('Usage:' + sys.argv[0] + '<search query>')
    sys.exit(1)

def worker(server, port):
    try:
        global global_correct
        global global_disable
        conn = http.client.HTTPConnection(str(server), str(port), timeout=20)
        conn.request("GET", "/cgi-bin/c8fed00eb2e87f1cee8e90ebbe870c190ac3848c")
        if conn.getresponse().read().find(b"CGI process file does not exist") != -1:
            print("CGI scripting is enabled")
            print(str(server) + ":" + str(port))
            global_correct += 1
        else:
            print("CGI scripting is disabled")
            global_disable += 1
            conn.close()
    except http.client.HTTPException as e:
        global_disable += 1
        return print("HTTPException")
    except Exception as e:
        global_disable += 1
        return print(e)


if __name__ == "__main__":
    global_correct = 0
    global_disable = 0
    api = shodan.Shodan(shodanKey)
    results = api.search("server: GoAhead country:QA")
    startTime = time.time()
    for x in results['matches']:
        process = multiprocessing.Process(target=worker, args=(x['ip_str'],x['port'],))
        process.start()
        process.join()
    print('\n[+] FINISHED')
    print(f'[+] Finished in {round(time.time() - startTime, 3)} seconds')
    print('\n[+] RESULTS')
    print(f'[+] IPs parsed correctly: {global_correct}')
    print(f'[+] IPs incorrect: {global_disable}')





