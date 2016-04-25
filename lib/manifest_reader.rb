#
# Copyright 2016 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
# Manifest representation in Ruby
#

require 'pp'
require 'rubygems'
require 'json'
require 'fileutils'
require 'set'

# This class overrides the one from Katello core and it is responsible for
# fetching the CDN tree. It is similar to Resources::CDN:CdnResource but
# it is simplified (it does not load Katello settings and takes only few
# basic parameters).
#
class DisconnectedCdnResource
  attr_reader :url

  def initialize url, options = {}
    #options.reverse_merge!(:verify_ssl => 9)
    options.merge(:verify_ssl => 9)
    #options.assert_valid_keys(:ssl_client_key, :ssl_client_cert, :ssl_ca_file, :verify_ssl, :proxy_host, :proxy_port, :proxy_user, :proxy_password)

    @url = url
    @uri = URI.parse(@url)
    if options[:proxy_host]
      @net = ::Net::HTTP::Proxy(options[:proxy_host], options[:proxy_port], options[:proxy_user], options[:proxy_password]).new(@uri.host, @uri.port)
    else
      @net = ::Net::HTTP.new(@uri.host, @uri.port)
    end
    @net.use_ssl = @uri.is_a?(URI::HTTPS)

    @net.cert = options[:ssl_client_cert]
    @net.key = options[:ssl_client_key]
    @net.ca_file = options[:ssl_ca_file]

    if (options[:verify_ssl] == false) || (options[:verify_ssl] == OpenSSL::SSL::VERIFY_NONE)
      @net.verify_mode = OpenSSL::SSL::VERIFY_NONE
    elsif options[:verify_ssl].is_a? Integer
      @net.verify_mode = options[:verify_ssl]
      @net.verify_callback = lambda do |preverify_ok, ssl_context|
        if (!preverify_ok) || ssl_context.error != 0
          abort("SSL verification failed -- preverify: #{preverify_ok}, error: #{ssl_context.error_string} (#{ssl_context.error})")
        end
        true
      end
    end
  end

  def get(path, headers={})
    path = File.join(@uri.request_uri,path)
    LOG.debug "Fetching info from #{path}"
    req = Net::HTTP::Get.new(path)
    begin
      @net.start do |http|
        res = http.request(req, nil) { |http_response| http_response.read_body }
        code = res.code.to_i
        if code == 200
          return res.body
        elsif code == 404
          LOG.error "Resource %s not found" % File.join(url, path)
        elsif code == 403
          LOG.error "Access denied to %s" % File.join(url, path)
        else
          LOG.fatal "Server returned %s error" % code
          exit
        end
      end
    rescue EOFError
      abort"Server broke connection"
    rescue Timeout::Error
      abort"Server connection timeout"
    end
  end

  def log(error, message)
   #LOG.info(message)
   puts message
  end

  def product
    # NOOP in disconnected
  end
end

module ManifestReader

  module StringToBool
    def to_bool
      return true if self == true || self =~ (/(true|t|yes|y|1)$/i)
      return false if self == false || self =~ (/(false|f|no|n|0)$/i)
      raise ArgumentError.new("invalid value for boolean: \"#{self}\"")
    end
  end

  class Consumer
    attr_accessor :uuid

    def initialize json_file
      c     = JSON.parse(IO.read json_file)
      @uuid = c['uuid']
    end

    def print_info
      puts "Consumer UUID: #{@uuid}"
    end
  end

  class Repository
    attr_accessor :basearch, :releasever, :path
    attr_reader :enabled
    attr_accessor :content

    def initialize basearch, releasever, enabled, path
      @basearch   = basearch
      @releasever = releasever
      @enabled    = "#{enabled}".extend(StringToBool).to_bool
      @path       = path
    end

    def enabled= value
      @enabled = "#{value}".extend(StringToBool).to_bool
    end

    # Return repoid in Pulp V2 friendly format (only alphanum, underscore or dash)
    def repoid
      "#{content.label}-#{releasever}-#{basearch}".gsub(/[^-\w]/,"_")
    end

    def repoid_enabled_hash
      { repoid => enabled }
    end

    def key
      content.product.entitlements.first.key
    end

    def cert
      content.product.entitlements.first.cert
    end

    def url
      File.join(content.product.manifest.cdn_url, path)
    end
  end

  class Content
    attr_accessor :product, :id, :name, :type, :url, :label, :gpg_url, :enabled

    def initialize product, pc_json
      @product      = product
      c             = pc_json["content"]
      @id           = c["id"]
      @name         = c["name"]
      @type         = c["type"]
      @url          = c["contentUrl"]
      @label        = c["label"]
      @gpg_url      = c["gpgUrl"]
      @enabled      = pc_json["enabled"]
      # empty until populate_repositories is called
      @repositories = {} # repoid -> Repository
    end

    def repositories
      @repositories.values
    end

    def print_info
      puts " - content #{name} (#{id})"
      puts "   - type: #{type}"
      puts "   - url: #{url}"
      puts "   - label: #{label}"
      puts "   - gpg_url: #{gpg_url}"
      puts "   - enabled: #{enabled}"
    end

    # add or replace repository
    def add_repository repo
      repo.content               = self
      @repositories[repo.repoid] = repo
    end

    def repoid_list
      repositories.collect { |r| r.repoid_enabled_hash }
    end

    def <=>(o)
      return name.<=>(o.name)
    end
  end

  class Product
    attr_accessor :manifest, :id, :name, :multi_entitlement
    attr_accessor :content
    attr_accessor :entitlements # in which this product belongs

    def initialize manifest, json_file
      @manifest          = manifest
      @entitlements      = []
      p                  = JSON.parse(IO.read json_file)
      #puts JSON.pretty_generate(p)
      @id                = p["id"]
      @name              = p["name"]
      @multi_entitlement = false
      p['attributes'].each do |a|
        @multi_entitlement = true if a['name'] == 'multi-entitlement' and a['value'].downcase == 'yes'
      end rescue @multi_entitlement = false
      pc       = p["productContent"]
      @content = {}
      pc.each do |pc|
        c              = Content.new(self, pc)
        @content[c.id] = c
      end
    end

    def print_info
      puts "Product #{name} (#{id})"
      puts "- multi_entitlement: #{multi_entitlement}"
      puts "Content:"
      content.each_value(&:print_info) if content
    end

    def <=>(o)
      return name.<=>(o.name)
    end
  end

  class Entitlement
    attr_accessor :manifest, :pool_id, :quantity, :end_date
    attr_accessor :contract_number, :account_number
    attr_accessor :primary_product_name, :primary_product_id, :primary_product, :primary_product
    attr_accessor :provided_product_ids, :provided_products
    attr_accessor :serial, :key, :cert, :pem_file

    def initialize manifest, json_file
      @manifest             = manifest
      e                     = JSON.parse(IO.read json_file)
      p                     = e["pool"]
      c                     = e["certificates"][0]
      @pool_id              = p["id"]
      @primary_product_name = p["productName"]
      @primary_product_id   = p["productId"]
      @quantity             = p["quantity"]
      @contract_number      = p["contractNumber"]
      @account_number       = p["accountNumber"]
      @end_date             = p["endDate"]
      @provided_product_ids = p["providedProducts"].collect { |pp| pp["productId"] }
      @serial               = c["serial"]["serial"]
      @key                  = c["key"]
      @cert                 = c["cert"]
    end

    def print_info
      puts "Entitlement (#{pool_id}):"
      puts "- primary product: #{primary_product_name} (#{primary_product_id})"
      puts "- quantity: #{quantity}"
      puts "- contract: #{contract_number}"
      puts "- account: #{account_number}"
      puts "- ends: #{end_date}"
      puts "- serial: #{serial}"
      puts "- pem file: #{pem_file}"
      puts "Provided products:"
      provided_products.each(&:print_info) if provided_products
    end

    def <=>(o)
      return pool_id.<=>(o.pool_id)
    end
  end

  class CdnVarSubstitutor
    def initialize(cdn_resource)
        @resource = cdn_resource
        @substitutions = Thread.current[:cdn_var_substitutor_cache] || {}
        @good_listings = Set.new
        @bad_listings = Set.new
      end

      # using substitutor from whithin the block makes sure that every
      # request is made only once.
      def self.with_cache(&_block)
        Thread.current[:cdn_var_substitutor_cache] = {}
        yield
      ensure
        Thread.current[:cdn_var_substitutor_cache] = nil
      end

      # precalcuclate all paths at once - let's you discover errors and stop
      # before it causes more pain
      def precalculate(paths_with_vars)
        paths_with_vars.uniq.reduce({}) do |ret, path_with_vars|
          ret[path_with_vars] = substitute_vars(path_with_vars)
          ret
        end
      end

      # takes path e.g. "/rhel/server/5/$releasever/$basearch/os"
      # returns hash substituting variables:
      #
      #  { {"releasever" => "6Server", "basearch" => "i386"} =>  "/rhel/server/5/6Server/i386/os",
      #    {"releasever" => "6Server", "basearch" => "x86_64"} =>  "/rhel/server/5/6Server/x84_64/os"}
      #
      # values are loaded from CDN
      def substitute_vars(path_with_vars)
        if path_with_vars =~ /^(.*\$\w+)(.*)$/
          prefix_with_vars, suffix_without_vars =  Regexp.last_match[1], Regexp.last_match[2]
        else
          prefix_with_vars, suffix_without_vars = "", path_with_vars
        end

        prefixes_without_vars = substitute_vars_in_prefix(prefix_with_vars)
        paths_without_vars = prefixes_without_vars.reduce({}) do |h, (substitutions, prefix_without_vars)|
          h[substitutions] = prefix_without_vars + suffix_without_vars
          h
        end
        return paths_without_vars
      end

      # prefix_with_vars is the part of url containing some vars. We can cache
      # calcualted values for this parts. So for example for:
      #   "/a/$b/$c/d"
      #   "/a/$b/$c/e"
      # prefix_with_vars is "/a/$b/$c" and we store the result after resolving
      # for the first path.
      def substitute_vars_in_prefix(prefix_with_vars)
        paths_with_vars = { {} => prefix_with_vars}
        prefixes_without_vars = @substitutions[prefix_with_vars]

        unless prefixes_without_vars
          prefixes_without_vars = {}
          until paths_with_vars.empty?
            substitutions, path = paths_with_vars.shift

            if substituable? path
              for_each_substitute_of_next_var substitutions, path do |new_substitution, new_path|
                begin
                  paths_with_vars[new_substitution] = new_path
                rescue Errors::SecurityViolation
                  # Some paths may not be accessible
                  @resource.log :warn, "#{new_path} is not accessible, ignoring"
                end
              end
            else
              prefixes_without_vars[substitutions] = path
            end
          end
          @substitutions[prefix_with_vars] = prefixes_without_vars
        end
        return prefixes_without_vars
      end

      def substituable?(path)
        path.include?("$")
      end

      def valid_substitutions(content, substitutions)
        validate_all_substitutions_accepted(content, substitutions)
        content_url = content.contentUrl
        real_path = gsub_vars(content_url, substitutions)

        if substituable?(real_path)
          fail Errors::CdnSubstitutionError, _("Missing arguments %{substitutions} for %{content_url}") %
              { substitutions: substitutions_needed(real_path).join(', '),
                content_url: real_path }
        else
          is_valid = valid_path?(real_path, 'repodata/repomd.xml') || valid_path?(real_path, 'PULP_MANIFEST')
          unless is_valid
            @resource.log :error, "No valid metadata files found for #{real_path}"
            fail Errors::CdnSubstitutionError, _("%{substitutions} are not valid substitutions for %{content_url}."\
                   " No valid metadata files found for %{real_path}") %
              { substitutions: substitutions, content_url: content.contentUrl, real_path: real_path}
          end
        end
      end

      protected

      def substitutions_needed(content_url)
        # e.g. if content_url = "/content/dist/rhel/server/7/$releasever/$basearch/kickstart"
        #      return ['releasever', 'basearch']
        content_url.split('/').map { |word| word.start_with?('$') ? word[1..-1] : nil }.compact
      end

      def validate_all_substitutions_accepted(content, substitutions)
        unaccepted_substitutions = substitutions.keys.reject do |key|
          content.contentUrl.include?("$#{key}")
        end
        if unaccepted_substitutions.size > 0
          fail Errors::CdnSubstitutionError, _("%{unaccepted_substitutions} cannot be specified for %{content_name}"\
                 " as that information is not substituable in %{content_url} ") %
              { unaccepted_substitutions: unaccepted_substitutions, content_name: content.name, content_url: content.contentUrl }
        end
      end

      def valid_path?(path, postfix)
        @resource.get(File.join(path, postfix)).present?
      rescue RestClient::MovedPermanently
        return true
      rescue Errors::NotFound
        return false
      end

      def gsub_vars(content_url, substitutions)
        substitutions.reduce(content_url) do |url, (key, value)|
          url.gsub("$#{key}", value)
        end
      end

      def for_each_substitute_of_next_var(substitutions, path)
        if path =~ /^(.*?)\$([^\/]*)/
          base_path, var = Regexp.last_match[1], Regexp.last_match[2]
          get_substitutions_from(base_path).compact.each do |value|
            new_substitutions = substitutions.merge(var => value)
            new_path = path.sub("$#{var}", value)

            yield new_substitutions, new_path
          end
        end
      end

      def get_substitutions_from(base_path)
        ret = @resource.get(File.join(base_path, "listing")).split("\n")
        @good_listings << base_path
        ret
      #rescue Errors::NotFound => e # some of listing file points to not existing content
      rescue => e # some of listing file points to not existing content
        @bad_listings << base_path
        @resource.log :error, e.message
        [] # return no substitution for unreachable listings
      end
  end

  class ConsumerType
    attr_accessor :id, :label

    def initialize json_file
      c      = JSON.parse(IO.read json_file)
      @id    = c["id"]
      @label = c["label"]
    end

    def print_info
      puts "Consumer Type: #{label} (#{id})"
    end
  end

  class Manifest
    attr_accessor :cdn_url, :cdn_ca
    attr_accessor :basedir, :version, :created
    attr_accessor :consumer, :products, :entitlements, :consumer_types
    attr_accessor :proxy_host, :proxy_port, :proxy_user, :proxy_password

    def initialize manifest_file_or_directory, cdn_url = nil, cdn_ca = nil, proxy_host = nil, proxy_port = nil, proxy_user = nil, proxy_password = nil
      @cdn_url = cdn_url
      @cdn_ca  = cdn_ca
      @proxy_host = proxy_host
      @proxy_port = proxy_port
      @proxy_user = proxy_user
      @proxy_password = proxy_password

      if File.directory? manifest_file_or_directory
        basedir = manifest_file_or_directory
      else
        # prepare and unzip
        unless File.exist? manifest_file_or_directory
          LOG.fatal "Unable to read file #{manifest_file_or_directory}"
          exit 2
        end
        basedir = `mktemp -d`.chomp
        at_exit do
          `rm -rf #{basedir}`
        end
        `unzip #{manifest_file_or_directory} -d #{basedir}`
        `unzip #{basedir}/consumer_export.zip -d #{basedir}`
      end

      # basic metadata about the export
      m         = JSON.parse(IO.read "#{basedir}/export/meta.json")
      @version  = m['version']
      @created  = m['created']

      # create hiearchy - consumer
      @consumer = Consumer.new "#{basedir}/export/consumer.json"

                     # products
      @products = {} # indexed by id
      Dir.glob("#{basedir}/export/products/*.json").each do |file|
        product               = Product.new(self, file)
        @products[product.id] = product
      end

                         # entitlements
      @entitlements = {} # indexed by pool_id
      Dir.glob("#{basedir}/export/entitlements/*.json").each do |file|
        entitlement                        = Entitlement.new(self, file)
        @entitlements[entitlement.pool_id] = entitlement
      end

      # consumer types
      @consumer_types = []
      Dir.glob("#{basedir}/export/consumer_types/*.json").each do |file|
        @consumer_types << ConsumerType.new(file)
      end

      # cross-reference
      @entitlements.each_value do |e|
        e.primary_product   = @products[e.primary_product_id]
        e.provided_products = e.provided_product_ids.collect { |ppi| @products[ppi] }
        e.provided_products.each { |p| p.entitlements << e }
        e.pem_file = "#{basedir}/export/entitlement_certificates/#{e.serial}.pem"
      end
    end

    def populate_repositories
      repo_counter = 0
      @entitlements.each_value do |entitlement|

        LOG.debug "Processing entitlement #{entitlement.pool_id}"
        cdn_var_substitutor = CdnVarSubstitutor.new(
          DisconnectedCdnResource.new(
            cdn_url,
            :ssl_ca_file => cdn_ca,
            :ssl_client_cert => OpenSSL::X509::Certificate.new(entitlement.cert),
            :ssl_client_key => OpenSSL::PKey::RSA.new(entitlement.key),
            :proxy_host => proxy_host,
            :proxy_port => proxy_port,
            :proxy_user => proxy_user,
            :proxy_password => proxy_password))

        entitlement.provided_products.each do |product|
          LOG.debug "Processing product #{product.name}"

          product.content.each_value do |content|
            LOG.debug "Processing #{content.name} #{content.url}"
            cdn_var_substitutor.substitute_vars(content.url).each do |(substitutions, path)|
              arch = substitutions['basearch']
              ver  = substitutions['releasever']
              repo = Repository.new(arch, ver, content.enabled, path)
              content.add_repository repo
              repo_counter += 1
              LOG.debug "Repository found: #{repo.repoid}"
            end
          end
        end
      end
      repo_counter
    end

    # load manifest
    def self.load mf_filename, conf_filename = nil
      mf = File.open(mf_filename, "r") { |file| Marshal::load(file) }
      if conf_filename
        mf.load_repos_setting conf_filename
      end
      mf
    end

    def load_repos_setting filename
      repos = repositories
      IO.foreach(filename) do |line|
        begin
          if line !~ /^#.*/ and line =~ /^([^=]*)=(.*?)(\s*#.*)?$/
            #repos[$1.strip].set_enabled $2.strip.match(/(true|t|yes|y|1)$/i) if repos[$1.strip]
            repos[$1.strip].enabled= $2.strip.match(/(true|false|t|f|yes|no|y|n|1|0)$/i) if repos[$1.strip]
          end
        rescue Exception => e
          raise RuntimeError, "Error parsing #{$1}: #{e.message}"
        end
      end
    end

    # save manifest and create repos.conf template (with backup)
    def save mf_filename, conf_filename = nil
      File.open(mf_filename, "w") { |file| Marshal::dump(self, file) }
      if conf_filename
        save_repo_conf conf_filename, true
      end
    end

    def print_info
      puts "Manifest #{version} created #{created}"
      puts "\nPRODUCTS"
      @products.each_value(&:print_info)
      puts "\nENTITLEMENTS"
      @entitlements.each_value(&:print_info)
      puts "\nCONSUMER TYPES"
      @consumer_types.each(&:print_info)
      puts "\nCONSUMER"
      @consumer.print_info
      puts "\nREPOSITORIES"
      repositories.each_pair do |repoid, repo|
        puts "#{repoid} = #{repo.enabled} #{repo.object_id}"
      end
    end

    # hash of repoid => Repository
    def repositories
      return @repositories_hash if @repositories_hash
      @repositories_hash = {}
      @entitlements.each_value do |entitlement|
        entitlement.provided_products.each do |product|
          product.content.each_value do |content|
            content.repositories.each do |repo|
              @repositories_hash[repo.repoid] = repo
            end
          end
        end
      end
      @repositories_hash
    end

    def enable_repository repoid, enable = true
      repos = repositories
      if repos[repoid]
        repos[repoid].enabled = enable
      end
    end

    # list of enabled repoids
    def enabled_repositories
      repositories.reject { |k, v| !v.enabled }.keys.sort
    end

    def read_cdn_ca
      IO.read cdn_ca
    end

    def save_repo_conf filename, backup = nil
      if backup and File.exists? filename
        timestamp       = Time.now.strftime("%Y%m%d-%H%M%S")
        backup_filename = filename + "." + timestamp
        FileUtils.mv filename, backup_filename, :force => true
      end
      File.open(filename, "w") do |file|
        @entitlements.sort.each do |unused, entitlement|
          entitlement.provided_products.sort.each do |product|
            product.content.sort.each do |unused, content|
              file.puts "\n# #{content.name}"
              content.repositories.each do |repo|
                file.puts "#{repo.repoid}=#{repo.enabled}"
              end
            end
          end
        end
      end
    end
  end
end
