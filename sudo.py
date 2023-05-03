__author__ = 'Fahad Al Summan'
# created by fahad at 1:53 AM 2/8/23
from subprocess import Popen, PIPE

sudo_password = 'F@A50h68ad85'
command = 'mount -t vboxsf myfolder /home/myuser/myfolder'.split()

p = Popen(['sudo', '-S'] + command, stdin=PIPE, stderr=PIPE,
          universal_newlines=True)
sudo_prompt = p.communicate(sudo_password + '\n')[1]