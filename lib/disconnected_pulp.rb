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

require 'uri'
require 'socket'
require 'nokogiri'
require 'zlib'
require 'tempfile'

class DisconnectedPulp
  attr_accessor :active_manifest, :manifest

  def initialize(active_manifest, options, log)
    @active_manifest = active_manifest
    @manifest = active_manifest.manifest
    @options = options
    @log = log
  end

  def LOG; @log; end

  def list(disabled = false)
    if disabled
      puts manifest.repositories.values.collect {|r| r.repoid }.sort
    else
      puts manifest.enabled_repositories
    end
  end

  def enable(value, repoids = nil, all = nil)
    allrepoids = manifest.repositories.keys
    if repoids
      repoids = repoids.split(/,\s*/).collect(&:strip)
      # Check all given repos are valid
      repoids.each do |repoid|
        unless allrepoids.include?(repoid)
          LOG.error ("%{repoid} isn't listed in the imported manifest, see katello-disconnected list --disabled") % {:repoid => repoid}
        end
      end
    else
      if all
        repoids = allrepoids
      else
        puts ('You need to provide some repoids')
        return
      end
    end
    repoids.each do |repoid|
      LOG.debug ("Setting enabled flag to %{value} for %{repoid}") % {:value => value, :repoid => repoid}
      manifest.enable_repository repoid, value
    end
    active_manifest.save_repo_conf
  end

  def run
    active_repos = manifest.repositories
    mfrepos = manifest.enabled_repositories
    LOG.debug "Enabled repos: #{mfrepos.inspect}"

    all_packages = Hash.new
    mfrepos.each do |repoid|
      repo = active_repos[repoid]
      if repo.content.type = "yum|kickstart"
        plist = YumRepo::PackageList.new repo.url, manifest.cdn_ca, repo.key, repo.cert, LOG
        plist.each do |p|
          package = "#{p.name}-#{p.version}-#{p.release}.#{p.arch}"
          all_packages.merge!({package => p.size})
        end
      else
        LOG.info "#{repoid} is not a yum repo; ignoring"
      end
    end
    puts Filesize.from("#{all_packages.to_a.flatten.inject{|sum, n| sum.to_i + n.to_i }} B").pretty
  end

private

  def get_relative_url(repo)
    # Find the yum_distributor so we can get the basedir
    repo_path = nil
    repo['distributors'].each do |d|
      repo_path = d['config']['relative_url'] if d['id'] == 'yum_distributor'
    end
    # if not found default to /
    repo_path ||= '/'
  end

end

module YumRepo

  def self.bench(msg)
    if defined? $yumrepo_perf_debug
      out = Benchmark.measure do
        yield
      end
      puts msg + out.to_s
    else
      yield
    end
  end

  class Repomd

    def initialize(url, ca_cert, key, cert, log)
      @url = url
      @ca_cert = ca_cert
      @key = key
      @cert = cert
      @log = log

      @url_digest = Digest::MD5.hexdigest(@url)
      @repomd_file = File.join(@url_digest, 'repomd.xml')

      LOG.debug "Fetching repomd.xml from #{@url}"

      uri = URI.parse("#{@url}/repodata/repomd.xml")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.ca_file = ca_cert
      http.cert = OpenSSL::X509::Certificate.new(cert)
      http.key = OpenSSL::PKey::RSA.new(key)
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER

      f = Net::HTTP::Get.new(uri.request_uri)
      response = http.request(f)

      @repomd = Nokogiri::XML(response.body)
    end

    def LOG; @log; end

    def primary
      pl = []
      @repomd.xpath("/xmlns:repomd/xmlns:data[@type=\"primary\"]/xmlns:location").each do |p|
        pl << File.join(@url, p['href'])
      end

      if not @primary_xml or @primary_xml.closed?
        @primary_xml = _open_file("primary.xml.gz", @url_digest, pl.first)
      end
      @primary_xml
    end

    private
    def _open_file(filename, cache_dir_name, data_url)

      f = Tempfile.new(filename)
      f.unlink 
      f.binmode

      LOG.debug "Downloading #{filename} for #{data_url}"
      uri = URI.parse(data_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.ca_file = @ca_cert
      http.cert = OpenSSL::X509::Certificate.new(@cert)
      http.key = OpenSSL::PKey::RSA.new(@key)
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      req = Net::HTTP::Get.new(uri.request_uri)
      response = http.request(req)     

      f.puts response.body
      f.pos = 0
      return f
    end

  end

  class PackageList

    def initialize(url, ca_cert = nil, key = nil , cert = nil, log)
      @url = url
      @ca_cert = ca_cert
      @key = key
      @cert = cert
      @log = log
      @packages = []
      xml_file = Repomd.new(url, ca_cert, key, cert, LOG).primary

      begin
        buf = ''
        YumRepo.bench("Zlib::GzipReader.read") do
          buf = Zlib::GzipReader.new(xml_file).read
        end

        YumRepo.bench("Building Package Objects") do
          d = Nokogiri::XML::Reader(buf)
          d.each do |n|
            if n.name == 'package' and not n.node_type == Nokogiri::XML::Reader::TYPE_END_ELEMENT
              @packages << Package.new(n.outer_xml)
            end
          end
        end

      ensure
        if xml_file.respond_to?(:close!)
          xml_file.close!
        else
          xml_file.close
        end
      end

    end

    def LOG; @log; end

    def each
      all.each do |p|
        yield p
      end
    end

    def all
      @packages
    end
  end

  class Package
    def initialize(xml)
      @xml = xml
    end

    def doc
      @doc ||= Nokogiri::XML(@xml)
    end

    def name
      doc.xpath('/xmlns:package/xmlns:name').text.strip
    end

    def arch
      doc.xpath('/xmlns:package/xmlns:arch').text.strip
    end

    def size
      doc.xpath('/xmlns:package/xmlns:size/@package').text.strip.to_i
    end

    def version
      doc.xpath('/xmlns:package/xmlns:version/@ver').text.strip
    end

    def release
      doc.xpath('/xmlns:package/xmlns:version/@rel').text.strip
    end

  end
end
