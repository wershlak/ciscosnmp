module Ciscosnmp
  module Helpers

    def Helpers.get_default_tftp_dir
      case RUBY_PLATFORM
        when /linux/i then '/var/lib/tftpboot/'
        when /darwin/i then '/private/tftpboot/'
        else '/private/tftpboot/'
      end
    end

    def Helpers.local_ip(ip='64.233.187.99')
      orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily
      UDPSocket.open do |s|
        s.connect ip, 1
        s.addr.last
      end
    ensure
      Socket.do_not_reverse_lookup = orig
    end

  end
end
