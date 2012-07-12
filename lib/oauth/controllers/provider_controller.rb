require 'oauth/provider/authorizer'
module OAuth
  module Controllers

    module ProviderController
      def self.included(controller)
        controller.class_eval do
          before_filter :login_required, :only => [:authorize,:revoke]
          oauthenticate :only => [:test_request]
          oauthenticate :strategies => :token, :interactive => false, :only => [:invalidate,:capabilities]
          oauthenticate :strategies => :two_legged, :interactive => false, :only => [:request_token]
          oauthenticate :strategies => :oauth10_request_token, :interactive => false, :only => [:access_token]
          skip_before_filter :verify_authenticity_token, :only=>[:request_token, :access_token, :invalidate, :test_request, :token]
        end
      end

      def request_token
        @token = current_client_application.create_request_token params
        if @token
          render :text => @token.to_query
        else
          render :nothing => true, :status => 401
        end
      end

      def access_token
        @token = current_token && current_token.exchange!
        if @token
          render :text => @token.to_query
        else
          render :nothing => true, :status => 401
        end
      end

      def token
        #@client_application = ClientApplication.find_by_key! params[:client_id]
        @client_application = ClientApplication.where(:oauth_key => params[:client_id]).first
        if @client_application.secret != params[:client_secret]
          oauth2_error "invalid_client"
          return
        end
        # older drafts used none for client_credentials
        params[:grant_type] = 'client_credentials' if params[:grant_type] == 'none'
        logger.info "grant_type=#{params[:grant_type]}"
        if ["authorization_code", "password", "client_credentials"].include?(params[:grant_type])
          send "oauth2_token_#{params[:grant_type].underscore}"
        else
          oauth2_error "unsupported_grant_type"
        end
      end

      def test_request
        render :text => params.collect{|k,v|"#{k}=#{v}"}.join("&")
      end

      def authorize
        if params[:oauth_token]
          #@token = ::RequestToken.find_by_token! params[:oauth_token]
          @token = ::RequestToken.where(:token => params[:oauth_token]).first
          oauth1_authorize
        else
          # Post will not happen now as we are skipping the authorization step (see the else branch)
          if request.post?
            @authorizer = OAuth::Provider::Authorizer.new current_user, user_authorizes_token?, params
            reset_session

            #Use fragment for inter-window communication
            if 'fragment' == params[:xd]
              if user_authorizes_token?
                render :template => "oauth/fragment", :locals => {:access_token => @authorizer.token.token,
                                                                  :expires_in => @authorizer.token.expires_in,
                                                                  :key => @authorizer.app.apikey,
                                                                  :base_uri => @authorizer.base_uri}
              else
                render :template => "oauth/fragment"
              end
              return
            end

            #Post message for inter-window communication
            if params[:cb]
              if user_authorizes_token?
                render :template => "oauth/post_message", :locals => {:access_token => @authorizer.token.token,
                                                                      :expires_in => @authorizer.token.expires_in,
                                                                      :key => @authorizer.app.apikey}
              else
                render :template => "oauth/post_message"
              end
              return
            end

            begin
              redirect_to @authorizer.redirect_uri
            rescue Exception => e
              render :status => 400, :json => { :meta => { :status => 'fail', :code => 400, :message => 'No redirect_uri provided!'}}
            end

          else
            #@client_application = ClientApplication.find_by_key! params[:client_id]
            @client_application = ClientApplication.where(:oauth_key => params[:client_id]).first

            #See if there is already an access token issued and it's still valid
            #If so just respond with the existing token
            @authorizer = OAuth::Provider::Authorizer.new current_user, true, params
            if @authorizer.tokenExists?
              reset_session

              #Use fragment for inter-window communication
              if 'fragment' == params[:xd]
                render :template => "oauth/fragment", :locals => {:access_token => @authorizer.token.token,
                                                                  :expires_in => @authorizer.token.expires_in,
                                                                  :key => @authorizer.app.apikey,
                                                                  :base_uri => @authorizer.base_uri}
                return
              end

              #Post Message for inter-window communication
              if params[:cb]
                  render :template => "oauth/post_message", :locals => {:access_token => @authorizer.token.token,
                                                                        :expires_in => @authorizer.token.expires_in,
                                                                        :key => @authorizer.app.apikey}
                return
              end

              begin
                redirect_to @authorizer.redirect_uri
              rescue Exception => e
                render :status => 400, :json => { :meta => { :status => 'fail', :code => 400, :message => 'No redirect_uri provided!'}}
              end

              return
            end

            # As we don't have many features to authorize the authorization step is really not necessary.
            # So we are skipping the authorization step
            #render :action => "oauth2_authorize"

            @authorizer = OAuth::Provider::Authorizer.new current_user, true, params
            reset_session

            #Use fragment for inter-window communication
            if 'fragment' == params[:xd]
                render :template => "oauth/fragment", :locals => {:access_token => @authorizer.token.token,
                                                                  :expires_in => @authorizer.token.expires_in,
                                                                  :key => @authorizer.app.apikey,
                                                                  :base_uri => @authorizer.base_uri}
              return
            end

            #Post message for inter-window communication
            if params[:cb]
                render :template => "oauth/post_message", :locals => {:access_token => @authorizer.token.token,
                                                                      :expires_in => @authorizer.token.expires_in,
                                                                      :key => @authorizer.app.apikey}
              return
            end

            begin
              redirect_to @authorizer.redirect_uri
            rescue Exception => e
              render :status => 400, :json => { :meta => { :status => 'fail', :code => 400, :message => 'No redirect_uri provided!'}}
            end

          end
        end
      end

      def revoke
        #@token = current_user.tokens.find_by_token! params[:token]
        @token = current_user.tokens.where(:token => params[:token]).first
        if @token
          @token.invalidate!
          flash[:notice] = "You've revoked the token for #{@token.client_application.name}"
        end
        redirect_to oauth_clients_url
      end

      # Invalidate current token
      def invalidate
        if current_token
          current_token.invalidate!
        else
          render :json=>{:success => 'false', :message => 'Invalid Token'}.to_json
          return
        end
        #head :status=>410

        passed_in_uri = params[:redirect_uri]
        if passed_in_uri && !passed_in_uri.empty?
          redirect_to URI.parse(passed_in_uri).to_s
        else
          #Post Message for inter-window communication
          if params[:cb]
            render :text=>"<script>parent.postMessage({'success':'true','cb':'" + params[:cb] + "'},'*');</script>"
          else
            render :json=>{:success => 'true'}.to_json
          end
        end
      end

      # Capabilities of current_token
      def capabilities
        if current_token.respond_to?(:capabilities)
          @capabilities=current_token.capabilities
        else
          @capabilities={:invalidate=>url_for(:action=>:invalidate)}
        end

        respond_to do |format|
          format.json {render :json=>@capabilities}
          format.xml {render :xml=>@capabilities}
        end
      end

      protected

      def oauth1_authorize
        unless @token
          render :action=>"authorize_failure"
          return
        end

        unless @token.invalidated?
          if request.post?
            if user_authorizes_token?
              @token.authorize!(current_user)
              callback_url  = @token.oob? ? @token.client_application.callback_url : @token.callback_url
              @redirect_url = URI.parse(callback_url) unless callback_url.blank?

              unless @redirect_url.to_s.blank?
                @redirect_url.query = @redirect_url.query.blank? ?
                                      "oauth_token=#{@token.token}&oauth_verifier=#{@token.verifier}" :
                                      @redirect_url.query + "&oauth_token=#{@token.token}&oauth_verifier=#{@token.verifier}"
                redirect_to @redirect_url.to_s
              else
                render :action => "authorize_success"
              end
            else
              @token.invalidate!
              render :action => "authorize_failure"
            end
          end
        else
          render :action => "authorize_failure"
        end
      end


      # http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.1.1
      def oauth2_token_authorization_code
        #@verification_code =  @client_application.oauth2_verifiers.find_by_token params[:code]
        @verification_code =  @client_application.oauth2_verifiers.where(:token => params[:code]).first
        unless @verification_code
          oauth2_error
          return
        end
        if @verification_code.redirect_url != params[:redirect_uri]
          oauth2_error
          return
        end
        @token = @verification_code.exchange!
        render :json=>@token
      end

      # http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.1.2
      def oauth2_token_password
        @user = authenticate_user( params[:username], params[:password])
        unless @user
          oauth2_error
          return
        end
        @token = Oauth2Token.create :client_application=>@client_application, :user=>@user, :scope=>params[:scope]
        render :json=>@token
      end

      # should authenticate and return a user if valid password. Override in your own controller
      def authenticate_user(username,password)
        User.authenticate(username,password)
      end

      # autonomous authorization which creates a token for client_applications user
      def oauth2_token_client_credentials
        @token = Oauth2Token.create :client_application=>@client_application, :user=>@client_application.user, :scope=>params[:scope]
        render :json=>@token
      end

      # Override this to match your authorization page form
      def user_authorizes_token?
        params[:authorize] == '1'
      end

      def oauth2_error(error="invalid_grant")
        render :json=>{:error=>error}.to_json
      end

    end
  end
end
