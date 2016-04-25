# pulp-planner
Gives minimum sizing estimate for Pulp based on Red Hat repos enabled; taking into account duplicate rpms in some repos

----------
### Installing dependencies

    yum install rubygem-more_core_extensions rubygem-nokogiri
    dnf install rubygem-more_core_extensions rubygem-nokogiri

##### Running

    ./pulp-planner import -m ~/Downloads/manifest_66fdff61-a1ba-44ab-9d12-2c84a92e392d.zip
    ./pulp-planner disbale -a
    ./pulp-planner enable -r rhel-6-server-rh-common-rpms-6Server-x86_64,rhel-6-server-rh-common-rpms-6_7-x86_64
    ./pulp-planner list
    ./pulp-planner run
