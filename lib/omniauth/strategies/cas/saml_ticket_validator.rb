require 'net/http'
require 'net/https'
require 'nokogiri'

module OmniAuth
  module Strategies
    class CAS
      class SamlTicketValidator
        VALIDATION_REQUEST_HEADERS = { 'Accept' => '*/*' }

        # Build a validator from a +configuration+, a
        # +return_to+ URL, and a +ticket+.
        #
        # @param [Hash] options the OmniAuth Strategy options
        # @param [String] return_to_url the URL of this CAS client service
        # @param [String] ticket the service ticket to validate
        def initialize(strategy, options, return_to_url, ticket)
          @options = options
          @uri = URI.parse(strategy.service_validate_url(return_to_url, ticket))
          @ticket = ticket
        end

        # Executes a network request to process the CAS Service Response
        def call
          @response_body = get_saml_response_body
          self
        end

        # Request validation of the ticket from the CAS server's
        # serviceValidate (CAS 2.0) function.
        #
        # Swallows all XML parsing errors (and returns +nil+ in those cases).
        #
        # @return [Hash, nil] a user information hash if the response is valid; +nil+ otherwise.
        #
        # @raise any connection errors encountered.
        def user_info
          begin
            doc = Nokogiri::XML(@response_body)
            doc.remove_namespaces!
            if success?(doc)
              attrs = extract_attributes(doc)
              attrs["nameIdentifier"] = extract_name_identifier(doc)
              { "user" => attrs["nameIdentifier"] }.merge(attrs)
            else
              OmniAuth.logger.warn "Received unsuccessful SAML response, will return nil user_info:\n#{@response_body}"
              nil
            end
          rescue Nokogiri::XML::XPath::SyntaxError
            OmniAuth.logger.warn "Could not parse SAML response, will return nil user_info:\n#{@response_body}"
            nil
          end
        end

        private

        def success?(doc)
          doc.css("StatusCode").attr("Value").text =~ /saml1?p:Success/
        end

        def extract_attributes(doc)
          doc.css("Attribute").inject({}) do |attrs, node|
            attrs[node.attr("AttributeName")] = node.css("AttributeValue").text
            attrs
          end
        end

        def extract_name_identifier(doc)
          doc.css("AuthenticationStatement Subject NameIdentifier").text
        end

        def saml_payload
          <<-SAML
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
    <samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1"
      MinorVersion="1" RequestID="#{SecureRandom.uuid}" IssueInstant="#{Time.now.to_s}">
      <samlp:AssertionArtifact>
        #{@ticket}
      </samlp:AssertionArtifact>
    </samlp:Request>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
          SAML
        end

        def get_saml_response_body
          result = ''

          http = Net::HTTP.new(@uri.host, @uri.port)
          http.use_ssl = @uri.port == 443 || @uri.instance_of?(URI::HTTPS)
          if http.use_ssl?
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @options.disable_ssl_verification?
            http.ca_path = @options.ca_path
          end

          http.start do |c|
            response = c.post("#{@uri.path}?#{@uri.query}", saml_payload, { "Content-Type" => "text/xml" })
            result = response.body
          end
          result
        end
      end
    end
  end
end
