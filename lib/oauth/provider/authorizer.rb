require 'uri'

module OAuth
  module Provider
    class Authorizer
      attr_accessor :user, :params, :app

      def initialize(user, authorized, params = {})
        @user = user
        @params = params
        @authorized = authorized
      end

      def app
        #@app ||= ::ClientApplication.find_by_key!(params[:client_id])
        @app ||= ::ClientApplication.where(:oauth_key => params[:client_id]).first
      end

      def code
        @code ||= ::Oauth2Verifier.create! :client_application => app,
                                      :user => @user,
                                      :scope => @params[:scope],
                                      :callback_url => @params[:redirect_uri]
      end

      def token
        @token ||= ::Oauth2Token.create! :client_application => app,
                                      :user => @user,
                                      :scope => @params[:scope],
                                      :callback_url => @params[:redirect_uri]
      end

      # Is there already an authorized token still valid?
      def tokenExists?
        tokens = ::Oauth2Token.where(:client_application_id => app.id,
                                     :user_id => @user.id,
                                     :invalidated_at.exists => false,
                                     :expires_at.gt => Time.now ).desc(:expires_at)

        Rails.logger.debug "Number of valid access tokens found: #{tokens.length}"
        tokens.each do |token|
          Rails.logger.debug token.inspect
        end

        if tokens.length > 0
          Rails.logger.debug "Use the latest existing valid access token"
          @token = tokens[0]
        else
          return false
        end

        if tokens.length > 1
          Rails.logger.debug "Invalidate extra valid access tokens"
          tokens.each do |token|
            if token.id != @token.id
              Rails.logger.debug "Invalidate token: #{token.id}"
              token.invalidate!
            end
          end
        end

        true

      end


      def authorized?
        @authorized == true
      end

      def redirect_uri
        uri = base_uri
        if params[:response_type] == 'code'
          if uri.query
            uri.query << '&'
          else
            uri.query = ''
          end
          uri.query << encode_response
        else
          uri.fragment = encode_response
        end
        uri.to_s
      end

      def response
        r = {}
        if ['token','code'].include? params[:response_type]
          if authorized?
            if params[:response_type] == 'code'
              r[:code] = code.token
            else
              r[:access_token] = token.token
              r[:expires_in] = token.expires_in
              #r[:key] = app.apikey
            end
          else
            r[:error] = 'access_denied'
          end
        else
          r[:error] = 'unsupported_response_type'
        end
        r[:state] = params[:state] if (params[:state] && !params[:state].empty?)
        r
      end

      def encode_response
        response.map do |k, v|
          [URI.escape(k.to_s),URI.escape(v)] * "="
        end * "&"
      end



        def base_uri
          redirect_url = app.callback_url
          passed_in_uri = params[:redirect_uri]
          if passed_in_uri && !passed_in_uri.empty?
            redirect_url = passed_in_uri
          end
          URI.parse(redirect_url)
          #URI.parse(params[:redirect_uri] || app.callback_url)
        end
    end
  end
end