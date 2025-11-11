function generateTimestamp() {
    const now = new Date();
    const year = now.getFullYear();
    const month = (now.getMonth() + 1).toString().padStart(2, '0');
    const day = now.getDate().toString().padStart(2, '0');
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}`;
}

const defaultTimestamp = generateTimestamp();

const filesystem = {
    '/': {
        type: 'directory',
        owner: 'root',
        group: 'root',
        size: 4096, // Typical directory size
        lastModified: defaultTimestamp,
        contents: {
            'home': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'root': {
                        type: 'directory',
                        owner: 'root',
                        group: 'root',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            '.bash_history': { type: 'file', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: '' },
                            'Documents': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Downloads': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Music': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Pictures': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Videos': { type: 'directory', owner: 'root', group: 'root', size: 4096, lastModified: defaultTimestamp, contents: {} }
                        }
                    },
                    'user': {
                        type: 'directory',
                        owner: 'user',
                        group: 'user',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            '.bash_history': { type: 'file', owner: 'user', group: 'user', size: 0, lastModified: defaultTimestamp, content: '' },
                            'Documents': { type: 'directory', owner: 'user', group: 'user', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Downloads': { type: 'directory', owner: 'user', group: 'user', size: 4096, lastModified: defaultTimestamp, contents: {} }
                        }
                    },
                    'brainphreak': {
                        type: 'directory',
                        owner: 'brainphreak',
                        group: 'brainphreak',
                        size: 4096,
                        lastModified: defaultTimestamp,
                        contents: {
                            '.bash_history': { type: 'file', owner: 'brainphreak', group: 'brainphreak', size: 0, lastModified: defaultTimestamp, content: '' },
                            'Documents': { type: 'directory', owner: 'brainphreak', group: 'brainphreak', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Downloads': { type: 'directory', owner: 'brainphreak', group: 'brainphreak', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Music': { type: 'directory', owner: 'brainphreak', group: 'brainphreak', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Pictures': { type: 'directory', owner: 'brainphreak', group: 'brainphreak', size: 4096, lastModified: defaultTimestamp, contents: {} },
                            'Videos': { type: 'directory', owner: 'brainphreak', group: 'brainphreak', size: 4096, lastModified: defaultTimestamp, contents: {} }
                        }
                    }
                }
            },
            'etc': {
                type: 'directory',
                owner: 'root',
                group: 'root',
                size: 4096,
                lastModified: defaultTimestamp,
                contents: {
                    'hosts': { type: 'file', owner: 'root', group: 'root', size: 30, lastModified: defaultTimestamp, content: `127.0.0.1        localhost
::1              localhost
192.168.1.100    brainphreak` },
                    'passwd': { type: 'file', owner: 'root', group: 'root', size: 200, lastModified: defaultTimestamp, content: `root:x:0:0:root:/home/root:/bin/bash
user:x:1000:1000:User Account:/home/user:/bin/bash
brainphreak:x:1001:1001:Brainphreak:/home/brainphreak:/bin/bash` },
                    'shadow': { type: 'file', owner: 'root', group: 'shadow', size: 150, lastModified: defaultTimestamp, content: `root:$6$salt$5H0tMmUm7cxX8uQn3q9w1rY4vP2lK6jD8fE3gB9hN7sA4mT1vR0pL5kJ6hG8fD3s:19000:0:99999:7:::
user:$6$salt$2F8kLmPq3rT5nY9wX1vU7hJ4gD6sA8mB2cN1vM9rT4pL6hK8jF5gD3sA1nM7vR9p:19000:0:99999:7:::
brainphreak:$6$salt$3N9mPr2tY5wV8xU1hK7jL4gF6sD8aM2bC3nV1mR9tP4lH6kJ8fG5dS3aM7nV1rP9:19000:0:99999:7:::` },
                    'sudoers': { type: 'file', owner: 'root', group: 'root', size: 100, lastModified: defaultTimestamp, content: `# Sudoers file
root    ALL=(ALL:ALL) ALL
user    ALL=(ALL:ALL) ALL
brainphreak    ALL=(ALL:ALL) ALL` }
                    }
                },
                'bin': {
                    type: 'directory',
                    owner: 'root',
                    group: 'root',
                    size: 4096,
                    lastModified: defaultTimestamp,
                    contents: {
                        'ls': { type: 'file', owner: 'root', group: 'root', size: 154624, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'cd': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'pwd': { type: 'file', owner: 'root', group: 'root', size: 101296, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'cat': { type: 'file', owner: 'root', group: 'root', size: 118992, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'echo': { type: 'file', owner: 'root', group: 'root', size: 101136, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'clear': { type: 'file', owner: 'root', group: 'root', size: 10000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'whoami': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'date': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'uname': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'ping': { type: 'file', owner: 'root', group: 'root', size: 60000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'w': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'who': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'ps': { type: 'file', owner: 'root', group: 'root', size: 170816, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'chmod': { type: 'file', owner: 'root', group: 'root', size: 120656, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'chown': { type: 'file', owner: 'root', group: 'root', size: 100000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'grep': { type: 'file', owner: 'root', group: 'root', size: 150000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'more': { type: 'file', owner: 'root', group: 'root', size: 80000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'less': { type: 'file', owner: 'root', group: 'root', size: 120000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'hostname': { type: 'file', owner: 'root', group: 'root', size: 101184, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'bash': { type: 'file', owner: 'root', group: 'root', size: 100000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Added bash
                        'which': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'su': { type: 'file', owner: 'root', group: 'root', size: 60000, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'sudo': { type: 'file', owner: 'root', group: 'root', size: 160000, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'useradd': { type: 'file', owner: 'root', group: 'root', size: 120000, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'help': { type: 'file', owner: 'root', group: 'root', size: 12000, lastModified: defaultTimestamp, content: 'ELF executable' }
                    }
                },
                'usr': {
                    type: 'directory',
                    owner: 'root',
                    group: 'root',
                    size: 4096,
                    lastModified: defaultTimestamp,
                    contents: {
                        'bin': {
                            type: 'directory',
                            owner: 'root',
                            group: 'root',
                            size: 4096,
                            lastModified: defaultTimestamp,
                            contents: {
                                'nmap': { type: 'file', owner: 'root', group: 'root', size: 1000000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                                'top': { type: 'file', owner: 'root', group: 'root', size: 241184, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'ssh': { type: 'file', owner: 'root', group: 'root', size: 1557568, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'scp': { type: 'file', owner: 'root', group: 'root', size: 12, lastModified: defaultTimestamp, content: 'ELF executable' },// Approximation
                                'curl': { type: 'file', owner: 'root', group: 'root', size: 552624, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'wget': { type: 'file', owner: 'root', group: 'root', size: 300000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                                'find': { type: 'file', owner: 'root', group: 'root', size: 171280, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'tar': { type: 'file', owner: 'root', group: 'root', size: 274784, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'nc': { type: 'file', owner: 'root', group: 'root', size: 45000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'john': { type: 'file', owner: 'root', group: 'root', size: 890000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'hashcat': { type: 'file', owner: 'root', group: 'root', size: 1200000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'base64': { type: 'file', owner: 'root', group: 'root', size: 38000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'md5sum': { type: 'file', owner: 'root', group: 'root', size: 42000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'sha256sum': { type: 'file', owner: 'root', group: 'root', size: 46000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'strings': { type: 'file', owner: 'root', group: 'root', size: 52000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'dig': { type: 'file', owner: 'root', group: 'root', size: 186000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'host': { type: 'file', owner: 'root', group: 'root', size: 48000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'arp': { type: 'file', owner: 'root', group: 'root', size: 54000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'telnet': { type: 'file', owner: 'root', group: 'root', size: 92000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'openssl': { type: 'file', owner: 'root', group: 'root', size: 685000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'head': { type: 'file', owner: 'root', group: 'root', size: 42000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'tail': { type: 'file', owner: 'root', group: 'root', size: 44000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'gzip': { type: 'file', owner: 'root', group: 'root', size: 171728, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'apt': { type: 'file', owner: 'root', group: 'root', size: 500000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                                'dpkg': { type: 'file', owner: 'root', group: 'root', size: 800000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                                'history': { type: 'file', owner: 'root', group: 'root', size: 50000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                                'whois': { type: 'file', owner: 'root', group: 'root', size: 135312, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'nslookup': { type: 'file', owner: 'root', group: 'root', size: 4235872, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'touch': { type: 'file', owner: 'root', group: 'root', size: 101792, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'iwconfig': { type: 'file', owner: 'root', group: 'root', size: 128000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'airodump-ng': { type: 'file', owner: 'root', group: 'root', size: 256000, lastModified: defaultTimestamp, content: 'ELF executable' },
                                'aircrack-ng': { type: 'file', owner: 'root', group: 'root', size: 384000, lastModified: defaultTimestamp, content: 'ELF executable' }
                            }
                        },
                        'share': {
                            type: 'directory',
                            owner: 'root',
                            group: 'root',
                            size: 4096,
                            lastModified: defaultTimestamp,
                            contents: {
                                'wordlists': {
                                    type: 'directory',
                                    owner: 'root',
                                    group: 'root',
                                    size: 4096,
                                    lastModified: defaultTimestamp,
                                    contents: {
                                        'common.txt': {
                                            type: 'file',
                                            owner: 'root',
                                            group: 'root',
                                            size: 1500,
                                            lastModified: defaultTimestamp,
                                            content: `password
123456
12345678
qwerty
abc123
monkey
letmein
trustno1
dragon
baseball
iloveyou
master
sunshine
ashley
bailey
shadow
superman
password1
123123
football
welcome
jesus
ninja
mustang
password123
admin
root
toor
passw0rd
administrator
user
test
guest
demo
default
changeme
system
temp
temporary
secret
redhat
fedora
ubuntu
debian
centos
linux
windows
microsoft
oracle
cisco
juniper
admin123
root123
pass123
welcome123
login
signin
access
enter
unlock
open
start
begin
alpine
public
private
training
student
teacher
database
server
network
client
service
support
helpdesk
security
backup
recovery
restore
archive
config
configuration
settings
options
preferences
tools
utilities
applications
programs
software
hardware
firmware
bios
kernel
shell
terminal
console
command
script
execute
run
launch
install
setup
wizard
interface
panel
dashboard
monitor
viewer
editor
manager
controller
handler
processor
generator
converter
analyzer
scanner
detector
validator
authenticator
authorizer
verifier
checker
tester
debugger
optimizer
enhancer
booster
accelerator
improver
upgrader
updater
patcher
fixer
repairer
cleaner
organizer
sorter
filter
searcher
finder
locator
tracker
recorder
logger
reporter
exporter
importer
loader
saver
reader
writer
printer
publisher
creator
builder
maker
designer
developer
programmer
coder
hacker
cracker
breaker
attacker
defender
protector
guardian
keeper
watcher
observer
listener
responder
reactor
handler
processor
executor
runner
worker
agent
daemon
service
process
thread
task
job
operation
function
procedure
method
routine
algorithm
formula
equation
calculation
computation
evaluation
analysis
assessment
examination
inspection
investigation
research
study
survey
review
audit
check
test
trial
experiment
demonstration
presentation
display
exhibition
showcase
preview
overview
summary
abstract
outline
sketch
draft
blueprint
diagram
chart
graph
table
list
index
catalog
directory
registry
repository
archive
library
collection
compilation
anthology
compendium
encyclopedia
dictionary
glossary
lexicon
thesaurus
almanac
handbook
manual
guide
tutorial
reference
documentation
specification
standard
protocol
format
template
pattern
model
framework
structure
architecture
design
layout
schema
blueprint
roadmap
plan
strategy
approach
methodology
technique
procedure
process
workflow
pipeline
channel
pathway
route
course
track
trail
path
way
direction
orientation
alignment
position
location
placement
arrangement
organization
order
sequence
series
chain
link
connection
relation
association
affiliation
membership
partnership
collaboration
cooperation
coordination
integration
combination
merger
union
alliance
coalition
federation
confederation
consortium
syndicate
cartel
trust
monopoly
oligopoly
duopoly
market
industry
sector
segment
division
department
branch
office
bureau
agency
authority
commission
committee
council
board
panel
group
team
crew
squad
unit
force
corps
brigade
regiment
battalion
company
platoon
squadron
fleet
armada
navy
army
military
defense
security
protection
safety
guard
patrol
watch
surveillance
monitoring
observation
inspection
examination
investigation
inquiry
research
study
analysis
evaluation
assessment
review
audit
check
verification
validation
confirmation
approval
authorization
permission
clearance
access
entry
admission
acceptance
enrollment
registration
subscription
membership
participation
involvement
engagement
contribution
donation
gift
present
offering
tribute
payment
fee
charge
cost
price
rate
tariff
duty
tax
levy
toll
fare
rent
lease
hire
rental
charter
franchise
license
permit
certificate
credential
qualification
certification
accreditation
recognition
acknowledgment
appreciation
gratitude
thanks
acknowledgment
recognition
reward
prize
award
trophy
medal
badge
ribbon
plaque
certificate
diploma
degree
title
rank
grade
level
class
category
group
type
kind
sort
variety
species
genus
family
order
phylum
kingdom
domain
realm
sphere
field
area
region
zone
district
territory
province
state
country
nation
continent
hemisphere
world
globe
planet
earth
universe
cosmos
space
void
emptiness
nothingness
oblivion
infinity
eternity
perpetuity
immortality
permanence
stability
constancy
consistency
reliability
dependability
trustworthiness
credibility
authenticity
legitimacy
validity
soundness
correctness
accuracy
precision
exactness
perfection
excellence
superiority
supremacy
dominance
preeminence
ascendancy
mastery
expertise
proficiency
competence
capability
ability
skill
talent
gift
aptitude
faculty
capacity
potential
possibility
probability
likelihood
chance
opportunity
occasion
moment
instant
second
minute
hour
day
week
month
year
decade
century
millennium
epoch
era
age
period
time
duration
span
interval
stretch
length
extent
range
scope
reach
coverage
domain
territory
area
field
sphere
realm
kingdom
empire
dominion
sovereignty
supremacy
authority
power
control
command
leadership
governance
management
administration
supervision
oversight
direction
guidance
instruction
teaching
education
training
coaching
mentoring
tutoring
counseling
advising
consulting
recommending
suggesting
proposing
offering
presenting
submitting
introducing
initiating
starting
beginning
commencing
launching
opening
unveiling
revealing
disclosing
exposing
uncovering
discovering
finding
locating
identifying
recognizing
acknowledging
admitting
confessing
revealing
telling
informing
notifying
alerting
warning
cautioning
advising
recommending
suggesting
proposing
offering
securenet123
password123
coffeeshop
guestwifi`
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'sbin': {
                    type: 'directory',
                    owner: 'root',
                    group: 'root',
                    size: 4096,
                    lastModified: defaultTimestamp,
                    contents: {
                        'ifconfig': { type: 'file', owner: 'root', group: 'root', size: 253024, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'netstat': { type: 'file', owner: 'root', group: 'root', size: 400976, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'route': { type: 'file', owner: 'root', group: 'root', size: 169904, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'iptables': { type: 'file', owner: 'root', group: 'root', size: 200000, lastModified: defaultTimestamp, content: 'ELF executable' }, // Approximation
                        'traceroute': { type: 'file', owner: 'root', group: 'root', size: 172048, lastModified: defaultTimestamp, content: 'ELF executable' },
                        'tcpdump': { type: 'file', owner: 'root', group: 'root', size: 2350224, lastModified: defaultTimestamp, content: 'ELF executable' }
                    }
                },
                'proc': {
                    type: 'directory',
                    owner: 'root',
                    group: 'root',
                    size: 4096,
                    lastModified: defaultTimestamp,
                    contents: {
                        'version': {
                            type: 'file',
                            owner: 'root', group: 'root', size: 104, lastModified: defaultTimestamp,
                            content: 'Linux version 5.4.0-42-generic (buildd@lgw01-amd64-039) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020'
                        },
                        'cpuinfo': {
                            type: 'file',
                            owner: 'root', group: 'root', size: 247, lastModified: defaultTimestamp,
                            content: 'processor\t: 0\nvendor_id\t: GenuineIntel\ncpufamily\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz\nstepping\t: 12\nmi crocode\t: 0xea\ncpu MHz\t\t: 1992.002\ncache size\t: 8192 KB'
                        },
                        'meminfo': {
                            type: 'file',
                            owner: 'root', group: 'root', size: 133, lastModified: defaultTimestamp,
                            content: 'MemTotal:        8032452 kB\nMemFree:         5216548 kB\nMemAvailable:    6543210 kB\nBuffers:          123456 kB\nCached:          1543210 kB'
                        },
                        'loadavg': {
                            type: 'file',
                            owner: 'root', group: 'root', size: 23, lastModified: defaultTimestamp,
                            content: '0.12 0.15 0.18 1/456 12345'
                        }
                    }
                },
                'dev': {
                    type: 'directory',
                    owner: 'root',
                    group: 'root',
                    size: 4096,
                    lastModified: defaultTimestamp,
                    contents: {
                        'null': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Character special file' },
                        'zero': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Character special file' },
                        'random': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Character special file' },
                        'urandom': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Character special file' },
                        'tty': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Character special file' },
                        'console': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Character special file' },
                        'sda': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Block special file' },
                        'sda1': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Block special file' },
                        'sda2': { type: 'device', owner: 'root', group: 'root', size: 0, lastModified: defaultTimestamp, content: 'Block special file' }
                    }
                },
                'tmp': {
                    type: 'directory',
                    owner: 'root',
                    group: 'root',
                    size: 4096,
                    lastModified: defaultTimestamp,
                    contents: {}
                },
                'opt': {
                    type: 'directory',
                    owner: 'root',
                    group: 'root',
                    size: 4096,
                    lastModified: defaultTimestamp,
                    contents: {
                        'blackpacket': {
                            type: 'directory',
                            owner: 'root',
                            group: 'root',
                            size: 4096,
                            lastModified: defaultTimestamp,
                            contents: {
                                'tools': {
                                    type: 'directory',
                                    owner: 'root',
                                    group: 'root',
                                    size: 4096,
                                    lastModified: defaultTimestamp,
                                    contents: {
                                        'scanner.py': {
                                            type: 'file',
                                            owner: 'root', group: 'root', size: 101, lastModified: defaultTimestamp,
                                            content: '#!/usr/bin/env python3\n# Network scanner tool\nimport socket\nimport sys\n\nprint("Black Packet Network Scanner v1.0")'
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    function getDirectory(path) {
        if (path === '/') {
            return filesystem['/'];
        }

        const parts = path.split('/').filter(p => p !== '');
        let current = filesystem['/'];

        for (const part of parts) {
            if (current.contents && current.contents[part] && current.contents[part].type === 'directory') {
                current = current.contents[part];
            } else {
                return false;
            }
        }
        return current;
    }

    function getFile(path) {
        if (path === '/') {
            return false;
        }

        const parts = path.split('/').filter(p => p !== '');
        const fileName = parts.pop();
        let dirPath = '/' + parts.join('/');
        if (dirPath === '') dirPath = '/';

        const dir = getDirectory(dirPath);
        if (dir === false || !dir.contents || !dir.contents[fileName]) {
            return false;
        }

        return dir.contents[fileName];
    }

    function listDirectory(path, showHidden = false) {
        const dir = getDirectory(path);
        if (dir === false || dir.type !== 'directory') {
            return `ls: cannot access '${path}': No such file or directory`;
        }

        let contents = Object.keys(dir.contents || {});
        if (!showHidden) {
            contents = contents.filter(name => !name.startsWith('.'));
        }

        // Return an array of objects with detailed info
        return contents.map(name => {
            const item = dir.contents[name];
            return {
                name: name,
                type: item.type,
                owner: item.owner,
                group: item.group,
                size: item.size,
                lastModified: item.lastModified
            };
        });
    }

    function changeDirectory(path, currentDirectory) {
        let targetPath;

        if (path.startsWith('/')) {
            targetPath = path;
        } else if (path === '..') {
            const parts = currentDirectory.split('/').filter(p => p !== '');
            parts.pop();
            targetPath = '/' + parts.join('/');
            if (targetPath === '') targetPath = '/';
        } else if (path === '.') {
            targetPath = currentDirectory;
        } else if (path === '~') {
            targetPath = '/home/root';
        } else {
            targetPath = currentDirectory === '/' ? `/${path}` : `${currentDirectory}/${path}`;
        }

        targetPath = targetPath.replace(/\/+/g, '/').replace(/\/$/, '') || '/';

        const dir = getDirectory(targetPath);
        if (dir === false || dir.type !== 'directory') {
            return false;
        }

        return targetPath;
    }

    function readFile(path, currentDirectory) {
        let filePath;

        if (path.startsWith('/')) {
            filePath = path;
        } else if (path.startsWith('~')) {
            filePath = '/home/root' + path.substring(1);
        } else {
            filePath = currentDirectory === '/' ? `/${path}` : `${currentDirectory}/${path}`;
        }

        filePath = filePath.replace(/\/+/g, '/').replace(/\/$/, '') || '/';

        const file = getFile(filePath);
        if (file === false || file.type !== 'file') {
            return false;
        }

        return file.content;
    }

    function createFile(filename, content, append = false, currentDirectory, owner = 'root', group = 'root') {
        let filePath;

        if (filename.startsWith('/')) {
            filePath = filename;
        } else {
            filePath = currentDirectory === '/' ? `/${filename}` : `${currentDirectory}/${filename}`;
        }

        filePath = filePath.replace(/\/+/g, '/').replace(/\/$/, '');

        const parts = filePath.split('/').filter(p => p !== '');
        const fileName = parts.pop();
        let dirPath = '/' + parts.join('/');
        if (dirPath === '') dirPath = '/';

        const dir = getDirectory(dirPath);
        if (dir === false || dir.type !== 'directory') {
            return false;
        }

        if (append && dir.contents[fileName]) {
            dir.contents[fileName].content += content;
            dir.contents[fileName].size = dir.contents[fileName].content.length;
            dir.contents[fileName].lastModified = generateTimestamp();
        } else {
            dir.contents[fileName] = {
                type: 'file',
                owner: owner,
                group: group,
                size: content.length,
                lastModified: generateTimestamp(),
                content: content
            };
        }

        return true;
    }

    function resolvePath(path, currentDirectory) {
        // Handle . (current directory)
        if (path === '.') {
            return currentDirectory;
        }
        // Handle ./ prefix
        if (path.startsWith('./')) {
            path = path.substring(2);
            if (path === '') return currentDirectory;
        }

        if (path.startsWith('/')) {
            return path;
        } else if (path.startsWith('~')) {
            return '/home/root' + path.substring(1);
        } else {
            return currentDirectory === '/' ? `/${path}` : `${currentDirectory}/${path}`;
        }
    }

    function updateBashHistory(cmd) {
        const bashHistoryPath = '/home/root/.bash_history';
        const bashHistory = getFile(bashHistoryPath);
        if (bashHistory) {
            bashHistory.content += '\n' + cmd;
        }
    }

const environment = {
    PATH: '/bin:/usr/bin:/sbin', // Initial PATH
    USER: 'user', // Current user (starts as 'user')
    LOGNAME: 'user', // Login name
    UID: '1000', // User ID
    GID: '1000', // Group ID
    CWD: '/home/user', // Current Working Directory
    OLDPWD: '/', // Old/Previous Working Directory
    SHELL: '/bin/bash', // Default shell
    HOME: '/home/user', // Home directory
    HOSTNAME: 'brainphreak' // Default hostname
};

// User database (simulated from /etc/passwd and /etc/shadow)
const users = {
    root: { uid: '0', gid: '0', home: '/home/root', shell: '/bin/bash', password: 'password' },
    user: { uid: '1000', gid: '1000', home: '/home/user', shell: '/bin/bash', password: '123456' },
    brainphreak: { uid: '1001', gid: '1001', home: '/home/brainphreak', shell: '/bin/bash', password: 'letmein' }
};

// Sudoers list (users allowed to use sudo)
const sudoers = ['root', 'user', 'brainphreak'];

// User stack for exit command (tracks user switches)
let userStack = [];

// Current user's command history (in memory)
let currentHistory = [];

// Reset to initial user state (called when opening new terminal)
function resetToInitialUser() {
    // Clear user stack
    userStack = [];

    // Reset to default user
    const defaultUser = users['user'];
    environment.USER = 'user';
    environment.LOGNAME = 'user';
    environment.UID = defaultUser.uid;
    environment.GID = defaultUser.gid;
    environment.HOME = defaultUser.home;
    environment.CWD = defaultUser.home;
    environment.SHELL = defaultUser.shell;
    environment.HOSTNAME = 'brainphreak'; // Reset hostname to default

    // Load user's history
    const userHistory = loadUserHistory('user');
    currentHistory.length = 0;
    currentHistory.push(...userHistory);
}

// Load user's command history from .bash_history file
function loadUserHistory(username) {
    const userInfo = users[username];
    if (!userInfo) {
        return [];
    }

    const historyPath = `${userInfo.home}/.bash_history`;
    const historyFile = getFile(historyPath);

    if (historyFile && historyFile.content) {
        // Split by newlines and filter empty lines
        return historyFile.content.split('\n').filter(line => line.trim() !== '');
    }

    return [];
}

// Save user's command history to .bash_history file
function saveUserHistory(username, history) {
    const userInfo = users[username];
    if (!userInfo) {
        return false;
    }

    const historyPath = `${userInfo.home}/.bash_history`;
    const historyFile = getFile(historyPath);

    if (historyFile) {
        historyFile.content = history.join('\n');
        historyFile.size = historyFile.content.length;
        historyFile.lastModified = generateTimestamp();
        return true;
    }

    return false;
}

// Get current command history
function getCurrentHistory() {
    return currentHistory;
}

// Set current command history (modifies array in place to maintain reference)
function setCurrentHistory(history) {
    currentHistory.length = 0; // Clear array
    currentHistory.push(...history); // Add new items
}

// Add command to current history
function addToHistory(command) {
    if (command && command.trim() !== '') {
        currentHistory.unshift(command); // Add to beginning for recent-first access
        // Also save to .bash_history file
        saveUserHistory(environment.USER, currentHistory);
    }
}

// Switch user function
function switchUser(username, pushToStack = true) {
    if (!users[username]) {
        return false;
    }

    // Save current user's command history before switching
    saveUserHistory(environment.USER, currentHistory);

    // Push current user to stack before switching (for exit command)
    if (pushToStack) {
        userStack.push({
            user: environment.USER,
            uid: environment.UID,
            gid: environment.GID,
            home: environment.HOME,
            cwd: environment.CWD,
            shell: environment.SHELL
        });
    }

    const user = users[username];
    environment.USER = username;
    environment.LOGNAME = username;
    environment.UID = user.uid;
    environment.GID = user.gid;
    environment.HOME = user.home;
    environment.CWD = user.home;
    environment.SHELL = user.shell;

    // Load new user's command history (modify in place to maintain reference)
    const newHistory = loadUserHistory(username);
    currentHistory.length = 0;
    currentHistory.push(...newHistory);

    return true;
}

// Exit user (return to previous user from stack)
function exitUser() {
    if (userStack.length === 0) {
        return null; // No previous user, signal to close terminal
    }

    // Save current user's history before switching back
    saveUserHistory(environment.USER, currentHistory);

    const previousUser = userStack.pop();
    environment.USER = previousUser.user;
    environment.UID = previousUser.uid;
    environment.GID = previousUser.gid;
    environment.HOME = previousUser.home;
    environment.CWD = previousUser.cwd;
    environment.SHELL = previousUser.shell;

    // Load previous user's command history (modify in place to maintain reference)
    const prevHistory = loadUserHistory(previousUser.user);
    currentHistory.length = 0;
    currentHistory.push(...prevHistory);

    return previousUser.user;
}

// Add new user (useradd command)
function addUser(username, password = 'password') {
    if (users[username]) {
        return { success: false, message: `useradd: user '${username}' already exists` };
    }

    // Generate new UID (find next available)
    const existingUids = Object.values(users).map(u => parseInt(u.uid));
    const newUid = Math.max(...existingUids) + 1;

    // Add user to users object
    users[username] = {
        uid: newUid.toString(),
        gid: newUid.toString(),
        home: `/home/${username}`,
        shell: '/bin/bash',
        password: password
    };

    // Create home directory in filesystem
    const homeDir = getDirectory('/home');
    if (homeDir && homeDir.contents) {
        homeDir.contents[username] = {
            type: 'directory',
            owner: username,
            group: username,
            size: 4096,
            lastModified: generateTimestamp(),
            contents: {
                '.bash_history': {
                    type: 'file',
                    owner: username,
                    group: username,
                    size: 0,
                    lastModified: generateTimestamp(),
                    content: ''
                },
                'Documents': {
                    type: 'directory',
                    owner: username,
                    group: username,
                    size: 4096,
                    lastModified: generateTimestamp(),
                    contents: {}
                },
                'Downloads': {
                    type: 'directory',
                    owner: username,
                    group: username,
                    size: 4096,
                    lastModified: generateTimestamp(),
                    contents: {}
                }
            }
        };
    }

    // Update /etc/passwd
    const passwdFile = getFile('/etc/passwd');
    if (passwdFile) {
        passwdFile.content += `\n${username}:x:${newUid}:${newUid}:${username}:/home/${username}:/bin/bash`;
    }

    // Update /etc/shadow
    const shadowFile = getFile('/etc/shadow');
    if (shadowFile) {
        shadowFile.content += `\n${username}:$6$brainphreak$${password}:19000:0:99999:7:::`;
    }

    return { success: true, message: `useradd: user '${username}' created with UID ${newUid}` };
}

// Check if user can use sudo
function canUseSudo(username) {
    return sudoers.includes(username);
}

// Verify user password
function verifyPassword(username, password) {
    if (!users[username]) {
        return false;
    }
    return users[username].password === password;
}

// Get user info
function getUserInfo(username) {
    return users[username] || null;
}

export {
    filesystem,
    environment,
    getDirectory,
    getFile,
    listDirectory,
    changeDirectory,
    readFile,
    createFile,
    resolvePath,
    updateBashHistory,
    switchUser,
    exitUser,
    addUser,
    canUseSudo,
    verifyPassword,
    getUserInfo,
    loadUserHistory,
    saveUserHistory,
    getCurrentHistory,
    setCurrentHistory,
    addToHistory,
    resetToInitialUser
};