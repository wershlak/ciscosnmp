module Ciscosnmp
  module Refinements
    module Hexhelpers
      # Patch String to provide methods to convert decimal (string) to hex
      # and hex string to dotted decimal for dealing with SNMP OID creation
      #
      refine String do
        def to_hex
          h=""
          each_byte{ |b| h << "%02x" % b }
          h
        end

        def h2dd
          r=self.delete(".:")
          results = []
          stop_index = r.length - 2
          0.step(stop_index, 2) do |i|
            decimal_num = r[i,2].hex
            results << sprintf("%d", decimal_num)
          end
          out_str = results.join(".")
          return out_str
        end
      end
    end
  end
end
