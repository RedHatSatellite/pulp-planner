# pulp-planner
Gives minimum sizing estimate for Pulp based on Red Hat repos enabled; taking into account duplicate rpms in some repos

----------
Special thanks to [katello-disconnect](https://github.com/Katello/katello-utils/) where all the manifest handeling code came from! :+1:

##### Installing dependencies

    dnf install rubygem-more_core_extensions rubygem-nokogiri

##### Running

    git clone https://github.com/sean797/pulp-planner.git
    cd pulp-planner/bin
    ./pulp-planner import -m ~/Downloads/manifest_66fdff61-a1ba-44ab-9d12-2c84a92e392d.zip
    ./pulp-planner disable -a
    ./pulp-planner enable -r rhel-6-server-rh-common-rpms-6Server-x86_64,rhel-6-server-rh-common-rpms-6_7-x86_64
    ./pulp-planner list
    ./pulp-planner run
