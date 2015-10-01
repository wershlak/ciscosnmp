require 'snmp'
require 'ciscosnmp/refinements/hexhelpers'
require 'ciscosnmp/helpers/helpers'

module Ciscosnmp

  class Base
    using Ciscosnmp::Refinements::Hexhelpers

    attr_reader :address
    attr_reader :community
    attr_accessor :tftp_server_directory
    attr_accessor :config_directory

    def initialize(config = {})
      @address = config[:address] || 'localhost'
      @community = config[:community] || 'private'
      @manager = SNMP::Manager.new(:host => @address, :Version => :SNMPv1, :Community => @community)
      @tftp_server_directory = config[:tftp_server_directory] || Ciscosnmp::Helpers.get_default_tftp_dir
      @config_directory = config[:config_directory] || "#{Dir.home}/Configs/"
    end

    def set_address(address)
      @address = address
      @manager = SNMP::Manager.new(:host => @address, :Version => :SNMPv1, :Community => @community)
    end

    def set_community(community)
      @community = community
      @manager = SNMP::Manager.new(:host => @address, :Version => :SNMPv1, :Community => @community)
    end

    def snmp_get(oid)
      begin
        response = @manager.get(oid)
      rescue => detail
        return Response.new(detail, false)
      end
      return Response.new(response.error_status, false) unless response.error_status == :noError
      Response.new(response.varbind_list.first.value.to_s, true)
    end

    def snmp_walk(oid)
      results = []
      begin
        @manager.walk(oid) do |vb|
          results << vb.value.to_s
        end
      rescue => detail
        return Response.new(detail, false)
      end
      Response.new(results, true)
    end

    def snmp_set(snmp_vb)
      begin
        response = @manager.set(snmp_vb)
      rescue => detail
        return Response.new(detail, false)
      end
      return Response.new(response.error_status, false) unless response.error_status == :noError
      Response.new(response.varbind_list.first.value.to_s, true)
    end

    def online?
      result = self.snmp_get 'sysName.0'
      result.success?
    end

    def writable?
      snmp_copy_protocol = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.2.117', SNMP::Integer.new(1))
      result = self.snmp_set snmp_copy_protocol
      result.success?
    end

    def get_neighbors
      result = self.snmp_walk '1.3.6.1.4.1.9.9.23.1.2.1.1.4'
      return result unless result.success?
      neighbors = []
      result.message.each do |nei|
        neighbors.push nei.to_s.to_hex.h2dd
      end
      Response.new(neighbors.uniq, true)
    end

    def sys_name
      snmp_get('sysName.0')
    end

    def sys_descr
      snmp_get('sysDescr.0')
    end

    def serial
      response = snmp_walk('1.3.6.1.4.1.9.3.6.3')
      if response.success?
        return Response.new(response.message[0].to_s.upcase, true)
      end
      response
    end

    def ios
      response = snmp_get('1.3.6.1.4.1.9.9.25.1.1.1.2.5')
      if response.success?
        return Response.new(response.message.to_s.split('$')[1].to_s.strip, true)
      end
      response
    end

    def ios_file
      snmp_get('1.3.6.1.2.1.16.19.6.0')
    end

    def model
      response = snmp_walk('1.3.6.1.2.1.47.1.1.1.1.13')
      if response.success?
        response.message.each do |item|
          if item != nil && item != ''
            return Response.new(item, true)
          end
        end
      end
      Response.new('Model not found', false)
    end

    def backup
      filename = "#{@address}.config"
      sourcefile = "#{@tftp_server_directory}#{filename}"
      response = create_tftp_file(sourcefile)
      return response if response.failure?
      response = verify_dir(@config_directory)
      return response if response.failure?
      unless self.online?
        delete_file(sourcefile)
        return Response.new("#{@address} is either offline or not configured with community \"#{@community}\"", false)
      end
      unless self.writable?
        delete_file(sourcefile)
        return Response.new("Failed to write to #{@address} - ensure that the SNMP community \"#{@community}\" is RW", false)
      end
      # incase we've failed before and stranded a copy process we'll cleanup first
      cleanup = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.14.113', SNMP::Integer.new(6))
      snmp_set(cleanup)
      # ccProtocol - copy protocol - 1 tftp - 3 rcp
      snmp_copy_protocol = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.2.113', SNMP::Integer.new(1))
      response = snmp_set(snmp_copy_protocol)
      return response if response.failure?
      # sourceType - source - 1 network - 3 startup - 4 running
      source_type = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.3.113', SNMP::Integer.new(4))
      response = snmp_set(source_type)
      return response if response.failure?
      # destinationType - 1 network - 3 startup - 4 running
      destination_type = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.4.113', SNMP::Integer.new(1))
      response = snmp_set(destination_type)
      return response if response.failure?
      # serverAddress
      server_ip = Ciscosnmp::Helpers.local_ip(@address)
      server_address = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.5.113', SNMP::IpAddress.new(server_ip))
      response = snmp_set(server_address)
      return response if response.failure?
      # copyFile -
      copy_file = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.6.113', SNMP::OctetString.new(filename))
      response = snmp_set(copy_file)
      return response if response.failure?
      # copyStatus
      copy_status = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.14.113', SNMP::Integer.new(1))
      response = snmp_set(copy_status)
      return response if response.failure?
      copystate = 2
      # Wait while the copy finishes
      begin
        begin
          copystate = @manager.get_value('1.3.6.1.4.1.9.9.96.1.1.1.1.10.113')
        rescue
          sleep(1)
          break
        end
        sleep(0.15)
      end while copystate == 2
      if copystate.to_i == 4 #failure
        begin
          failurereason = @manager.get_value('1.3.6.1.4.1.9.9.96.1.1.1.1.13.113')
        rescue
          failurereason = 8
        end
        message = case failurereason
                    when 1 then 'Copy failed: unknown'
                    when 2 then 'Copy failed: bad file name'
                    when 3 then 'Copy failed: Timeout'
                    when 4 then 'Copy failed: No MEM'
                    when 5 then 'Copy failed: No config'
                    when 6 then 'Copy failed: Unsupported Protocol'
                    when 7 then 'Copy failed: Some config apply failed'
                    else 'Copy failed: unknown'
                  end
        delete_file(sourcefile)
        return Response.new(message, false)
      elsif copystate.to_i == 3 #success
        begin
          FileUtils.move(sourcefile, @config_directory)
        rescue
          return Response.new("Could not move config file to #{@config_directory}", false)
        end
      else
        delete_file(sourcefile)
        return Response.new("Unknown Copy state: #{copystate.to_s}", false)
      end
      snmp_set(cleanup)      # try our best to cleanup the copy process
      Response.new("Config saved to #{@config_directory}#{filename}", true)
    end

    def update(filename='update.txt')
      sourcefile = "#{@tftp_server_directory}#{filename}"
      unless File.exists?(sourcefile)
        return Response.new("Config file #{sourcefile} does not exist", false)
      end
      unless self.online?
        return Response.new("#{@address} is either offline or not configured with community \"#{@community}\"", false)
      end
      unless self.writable?
        return Response.new("Failed to write to #{@address} - ensure that the SNMP community \"#{@community}\" is RW", false)
      end
      # incase we've failed before and stranded a copy process we'll cleanup first
      cleanup = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.14.113', SNMP::Integer.new(6))
      snmp_set(cleanup)
      # ccProtocol - copy protocol - 1 tftp - 3 rcp
      snmp_copy_protocol = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.2.113', SNMP::Integer.new(1))
      response = snmp_set(snmp_copy_protocol)
      return response if response.failure?
      # sourceType - source - 1 network - 3 startup - 4 running
      source_type = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.3.113', SNMP::Integer.new(1))
      response = snmp_set(source_type)
      return response if response.failure?
      # destinationType - 1 network - 3 startup - 4 running
      destination_type = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.4.113', SNMP::Integer.new(4))
      response = snmp_set(destination_type)
      return response if response.failure?
      # serverAddress
      server_ip = Ciscosnmp::Helpers.local_ip(@address)
      server_address = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.5.113', SNMP::IpAddress.new(server_ip))
      response = snmp_set(server_address)
      return response if response.failure?
      # copyFile -
      copy_file = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.6.113', SNMP::OctetString.new(filename))
      response = snmp_set(copy_file)
      return response if response.failure?
      # copyStatus
      copy_status = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.14.113', SNMP::Integer.new(1))
      response = snmp_set(copy_status)
      return response if response.failure?
      copystate = 2
      # Wait while the copy finishes
      begin
        begin
          copystate = @manager.get_value('1.3.6.1.4.1.9.9.96.1.1.1.1.10.113')
        rescue
          sleep(1)
          break
        end
        sleep(0.15)
      end while copystate == 2
      if copystate.to_i == 4 #failure
        begin
          failurereason = @manager.get_value('1.3.6.1.4.1.9.9.96.1.1.1.1.13.113')
        rescue
          failurereason = 8
        end
        message = case failurereason
                    when 1 then 'Copy failed: unknown'
                    when 2 then 'Copy failed: bad file name'
                    when 3 then 'Copy failed: Timeout'
                    when 4 then 'Copy failed: No MEM'
                    when 5 then 'Copy failed: No config'
                    when 6 then 'Copy failed: Unsupported Protocol'
                    when 7 then 'Copy failed: Some config apply failed'
                    else 'Copy failed: unknown'
                  end
        return Response.new(message, false)
      elsif copystate.to_i != 3 #success
        return Response.new("Unknown Copy state: #{copystate.to_s}", false)
      end
      snmp_set(cleanup)      # try our best to cleanup the copy process
      Response.new("Updated running config on #{@address}", true)
    end

    def save()
      unless self.online?
        return Response.new("#{@address} is either offline or not configured with community \"#{@community}\"", false)
      end
      unless self.writable?
        return Response.new("Failed to write to #{@address} - ensure that the SNMP community \"#{@community}\" is RW", false)
      end
      # incase we've failed before and stranded a copy process we'll cleanup first
      cleanup = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.14.113', SNMP::Integer.new(6))
      snmp_set(cleanup)
      # ccProtocol - copy protocol - 1 tftp - 3 rcp
      snmp_copy_protocol = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.2.113', SNMP::Integer.new(1))
      response = snmp_set(snmp_copy_protocol)
      return response if response.failure?
      # sourceType - source - 1 network - 3 startup - 4 running
      source_type = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.3.113', SNMP::Integer.new(4))
      response = snmp_set(source_type)
      return response if response.failure?
      # destinationType - 1 network - 3 startup - 4 running
      destination_type = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.4.113', SNMP::Integer.new(3))
      response = snmp_set(destination_type)
      return response if response.failure?
      # copyStatus
      copy_status = SNMP::VarBind.new('1.3.6.1.4.1.9.9.96.1.1.1.1.14.113', SNMP::Integer.new(1))
      response = snmp_set(copy_status)
      return response if response.failure?

      copystate = 2
      begin
        begin
          copystate = @manager.get_value("1.3.6.1.4.1.9.9.96.1.1.1.1.10.113")
        rescue
          sleep(1)
          break
        end
        sleep(0.15)
      end while copystate == 2

      if copystate.to_i == 4 #failure
        begin
          failurereason = @manager.get_value("1.3.6.1.4.1.9.9.96.1.1.1.1.13.113")
        rescue
          failurereason = 8
        end
        message = case failurereason
                    when 1 then 'Copy failed: unknown'
                    when 2 then 'Copy failed: bad file name'
                    when 3 then 'Copy failed: Timeout'
                    when 4 then 'Copy failed: No MEM'
                    when 5 then 'Copy failed: No config'
                    when 6 then 'Copy failed: Unsupported Protocol'
                    when 7 then 'Copy failed: Some config apply failed'
                    else 'Copy failed: unknown'
                  end
        return Response.new(message, false)
      elsif copystate.to_i != 3 #success
        return Response.new("Unknown Copy state: #{copystate.to_s}", false)
      end
      snmp_set(cleanup)      # try our best to cleanup the copy process
      Response.new("Saved running config to start on #{@address}", true)
    end

    # Private class helper functions
    #
    private

    def create_tftp_file(sourcefile)
      begin
        File.delete(sourcefile) if File.exists?(sourcefile)
        tftpfile = File.new(sourcefile, 'w')
        tftpfile.chmod(0666)
      rescue
        return Response.new("Unable to create or modify config file: #{sourcefile}", false)
      end
      Response.new("#{sourcefile} created", true)
    end

    def verify_dir(dir)
      unless File.directory?(dir)
        begin
          Dir::mkdir(dir)
        rescue
          return Response.new("Unable to create Config directory: #{dir}", false)
        end
        return Response.new("Created #{dir}", true)
      end
      Response.new('Exists', true)
    end

    def delete_file(file)
      begin
        File.delete(file)
      rescue
        return
      end
    end

  end
end