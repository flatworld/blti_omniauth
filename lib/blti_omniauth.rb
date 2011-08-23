require 'omniauth/core'
require 'oauth'
require 'oauth/request_proxy/rack_request'
require 'base64'

module OmniAuth
  module Strategies
    class Blti
      include OmniAuth::Strategy
      
      def initialize(app, id, token, options={})
        @key = id
        @secret = token
        super(app, :blti, options)
      end

      # redirect to OmniAuth's callback (request is already authenticated)
      def request_phase
        #r = Rack::Response.new
        #r.redirect callback_url # TODO falta pasar los parámetros
        #r.finish
        #session[:user_return_to] = full_host
        callback_call
      end
      
      def callback_phase
        # create consumer with key and secret
        consumer = ::OAuth::Consumer.new(@key, @secret)
        # create token with token and secret
        token = ::OAuth::Token.new('', '')

        puts "BLTI: verifying signature"
        if ::OAuth::Signature.verify(request, { :consumer => consumer, :token => token} )
          @uid = Base64.decode64(request.params['user_id'])
          @avatar = Base64.decode64(request.params['user_image'])
          @username = Base64.decode64(request.params['custom_username'])
          @nickname = Base64.decode64(request.params['custom_fullname'])
          puts "BLTI: valid! uid=#{@uid}, avatar=#{@avatar}, username=#{@username}, nickname=#{@nickname}"
          # OmniAuth takes care of the rest
          super
        else
          puts "BLTI: fail!"
          # OmniAuth takes care of the rest
          fail!(:invalid_credentials)
        end
      end
                
      # normalize user's data according to http://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
      def auth_hash
        OmniAuth::Utils.deep_merge(super(), {
          'uid' => @uid,
          'user_info' => {
            'name'     => @username,
            'nickname' => @nickname,
            'image'    => @avatar
          }
        })
      end
    end
  end  
end