# pulp-planner
Gives minimum sizing estimate for Pulp based on Red Hat repos enabled; taking into account duplicate rpms in some repos

----------
Special thanks to [katello-disconnect](https://github.com/Katello/katello-utils/) where all the manifest handling code came from! :+1:


#### Red Hat Enterprise Linux 7

##### Setup Repositories

The **pulp-planner** utility requires the Red Hat Software Collections repository on RHEL7

~~~
subscription-manager repos  \
  --enable=rhel-7-server-rpms \
  --enable=rhel-server-rhscl-7-rpms
~~~

##### Installing dependencies
~~~
yum install rh-ror42-rubygem-nokogiri unzip git
~~~
##### Running on a RHEL system.

~~~
git clone https://github.com/RedHatSatellite/pulp-planner.git
cd pulp-planner/bin
scl enable rh-ror42 bash
./pulp-planner import -m ~/Downloads/manifest_66fdff61-a1ba-44ab-9d12-2c84a92e392d.zip
./pulp-planner disable -a
./pulp-planner enable -r rhel-6-server-rh-common-rpms-6Server-x86_64,rhel-6-server-rh-common-rpms-6_7-x86_64
./pulp-planner list
./pulp-planner run
~~~

#### Fedora

##### Installing dependencies

~~~
dnf install rubygem-more_core_extensions rubygem-nokogiri git
~~~

##### Running on a Fedora system.

~~~
git clone https://github.com/RedHatSatellite/pulp-planner.git
cd pulp-planner/bin
./pulp-planner import -m ~/Downloads/manifest_66fdff61-a1ba-44ab-9d12-2c84a92e392d.zip
./pulp-planner disable -a
./pulp-planner enable -r rhel-6-server-rh-common-rpms-6Server-x86_64,rhel-6-server-rh-common-rpms-6_7-x86_64
./pulp-planner list
./pulp-planner run
~~~
