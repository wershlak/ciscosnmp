module Ciscosnmp

  class Response
    attr_reader :message

    def initialize(message, success)
      @message = message
      @success = success
    end

    def success?
      @success
    end

    def failure?
      !success?
    end
  end

end
