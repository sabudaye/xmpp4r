# =XMPP4R - XMPP Library for Ruby
# License:: Ruby's license (see the LICENSE file) or GNU GPL, at your option.
# Website::http://xmpp4r.github.io

require 'rexml/parsers/sax2parser'
require 'rexml/source'
require 'xmpp4r/rexmladdons'
require 'ox'
require 'cgi'

module Jabber
  class SaxHandler < ::Ox::Sax

    def initialize(listener)
      @listener = listener
      @current = nil
    end

    def start_element(name)
       e = REXML::Element.new(name.to_s)
       @current = @current.nil? ? e : @current.add_element(e)

       # Handling <stream:stream> not only when it is being
       # received as a top-level tag but also as a child of the
       # top-level element itself. This way, we handle stream
       # restarts (ie. after SASL authentication).
       if (@current.name.to_s == 'stream' || @current.name.to_s == 'stream:stream') && !@current.parent.nil?
         @current = REXML::Element.new(name.to_s)
       end
    end

    def end_element(name)
      if (name.to_s == 'stream:stream' || name.to_s == 'stream') && @current.parent.nil?
        @listener.parser_end
      else
        @listener.receive(@current)
        @current = @current.parent
      end
    end

    def attr(name, str)
      @current.add_attribute(name.to_s, str) if @current
    end

    def attrs_done
      @listener.receive(@current) if @current.name.to_s == 'stream' || @current.name.to_s == 'stream:stream'
    end

    def text(str)
      @current.add(REXML::Text.new(CGI::escapeHTML(str), @current.whitespace, nil, true)) if @current
    end

    def cdata(str)
      @current.add(REXML::CData.new(str)) if @current
    end

    def abort(name)
      raise Jabber::ServerDisconnected, "Server Disconnected!"
    end

    def error(message, line, column)
      # FIXME
      # it looks loke we need to know name of error's class
      raise REXML::ParseException, message if message != "Start End Mismatch: element 'stream:stream' not closed"
    end
  end
  ##
  # The StreamParser uses REXML to parse the incoming XML stream
  # of the Jabber protocol and fires XMPPStanza at the Connection
  # instance.
  #
  class StreamParser
    # status if the parser is started
    attr_reader :started

    ##
    # Constructs a parser for the supplied stream (socket input)
    #
    # stream:: [IO] Socket input stream
    # listener:: [Object.receive(XMPPStanza)] The listener (usually a Jabber::Protocol::Connection instance)
    #
    def initialize(stream, listener)
      @stream = stream
      @listener = listener
      @current = nil
    end


    def parse
      handler = SaxHandler.new(@listener)
      begin
        Ox.sax_parse(handler, @stream)
      rescue Ox::ParseError, REXML::ParseException => e
        @listener.parse_failure(e)
      end
    end

    def parse_old
      @started = false
      begin
        parser = REXML::Parsers::SAX2Parser.new @stream

        parser.listen( :start_element ) do |uri, localname, qname, attributes|
          e = REXML::Element.new(qname)
          if attributes.kind_of? Hash
            unnormalized_attributes = {}
            attributes.each_pair do |key, value|
              unnormalized_attributes[key] = REXML::Text::unnormalize(value)
            end
          elsif attributes.kind_of? Array
            unnormalized_attributes = []
            attributes.each do |value|
              unnormalized_attributes << [value[0], REXML::Text::unnormalize(value[1])]
            end
          end

          e.add_attributes unnormalized_attributes
          @current = @current.nil? ? e : @current.add_element(e)

          # Handling <stream:stream> not only when it is being
          # received as a top-level tag but also as a child of the
          # top-level element itself. This way, we handle stream
          # restarts (ie. after SASL authentication).
          if @current.name == 'stream' and @current.parent.nil?
            @started = true
            @listener.receive(@current)
            @current = nil
          end
        end

        parser.listen( :end_element ) do  |uri, localname, qname|
          if qname == 'stream:stream' and @current.nil?
            @started = false
            @listener.parser_end
          else
            @listener.receive(@current) unless @current.parent
            @current = @current.parent
          end
        end

        parser.listen( :end_document ) do
          raise Jabber::ServerDisconnected, "Server Disconnected!"
        end

        parser.listen( :characters ) do | text |
          @current.add(REXML::Text.new(text.to_s, @current.whitespace, nil, true)) if @current
        end

        parser.listen( :cdata ) do | text |
          @current.add(REXML::CData.new(text)) if @current
        end

        parser.parse
      rescue REXML::ParseException => e
        @listener.parse_failure(e)
      end
    end
  end
end
