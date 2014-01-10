require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy

      option :name_identifier_format, nil
      option :idp_sso_target_url_runtime_params, {}

      def request_phase
        options[:assertion_consumer_service_url] ||= callback_url
        runtime_request_parameters = options.delete(:idp_sso_target_url_runtime_params)

        additional_params = {}
        runtime_request_parameters.each_pair do |request_param_key, mapped_param_key|
          additional_params[mapped_param_key] = request.params[request_param_key.to_s] if request.params.has_key?(request_param_key.to_s)
        end if runtime_request_parameters

        authn_request = Onelogin::Saml::Authrequest.new
        settings = Onelogin::Saml::Settings.new(options)

        redirect(authn_request.create(settings, additional_params))
      end

      def callback_phase
        unless request.params['SAMLResponse']
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing")
        end

        _log "REQUEST [#{request.inspect}]"

        response = Onelogin::Saml::Response.new(request.params['SAMLResponse'], options)
        response.settings = Onelogin::Saml::Settings.new(options)

        _log "RESPONSE [#{response.inspect}]"

        @name_id = response.name_id
        @attributes = response.attributes

        _log "NAME_ID [#{@name_id}]"
        _log "ATTRIBUTES [#{@attributes.inspect if @attributes}]"

        if @name_id.nil? || @name_id.empty?
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing 'name_id'")
        end

        _log "CALLBACK 1"

        response.validate!

        _log "CALLBACK 2"
        super
      rescue OmniAuth::Strategies::SAML::ValidationError
        _log "CALLBACK 4"
        fail!(:invalid_ticket, $!)
      rescue Onelogin::Saml::ValidationError
        _log "CALLBACK 5"
        fail!(:invalid_ticket, $!)
      end

      def other_phase
        if on_path?("#{request_path}/metadata")
          # omniauth does not set the strategy on the other_phase
          @env['omniauth.strategy'] ||= self
          setup_phase

          response = Onelogin::Saml::Metadata.new
          settings = Onelogin::Saml::Settings.new(options)
          Rack::Response.new(response.generate(settings), 200, { "Content-Type" => "application/xml" }).finish
        else
          call_app!
        end
      end

      def _log(string)
        time = Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")
        File.open("log/saml.log", "a") do |file|
          if multiline?(string)
            file.write(time)
            file.write(string)
            file.write("\n")
            file.write("\n")
          else
            file.write("#{time} #{string}\n\n")
          end
        end
      end

      def multiline?(string)
        !!string.match(/\n/) if string
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes[:name],
          :email => @attributes[:email] || @attributes[:mail],
          :first_name => @attributes[:first_name] || @attributes[:firstname] || @attributes[:firstName],
          :last_name => @attributes[:last_name] || @attributes[:lastname] || @attributes[:lastName]
        }
      end

      extra { { :raw_info => @attributes } }
    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
