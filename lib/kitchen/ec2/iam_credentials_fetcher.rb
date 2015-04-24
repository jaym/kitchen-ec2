# -*- encoding: utf-8 -*-
#
# Author:: Tyler Ball (<tball@chef.io>)
#
# Copyright (C) 2015, Fletcher Nichol
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "excon"
require "json"
require "net/http"
require "timeout"
require "time"
require "English"

module Kitchen
  module EC2
    # This class exists to fetch IAM credentials from the metadata service
    # when ran from within an existing EC2 host.  The use case is that
    # you have a CI system running test-kitchen and the CI exists
    # entirely within AWS.
    class IamCredentialsFetcher

      INSTANCE_METADATA_HOST = "http://169.254.169.254"
      INSTANCE_METADATA_PATH = "/latest/meta-data/iam/security-credentials/"

      attr_reader :logger

      def initialize(logger)
        @logger = logger
      end

      # First we check the existence of the metadata host.  Only fetch_credentials
      # if we can find the host.
      def iam_creds
        @iam_creds ||= begin
          timeout(5) do
            Net::HTTP.get(URI.parse(INSTANCE_METADATA_HOST))
          end
          fetch_credentials
        rescue Errno::EHOSTUNREACH, Errno::EHOSTDOWN, Timeout::Error,
               NoMethodError, ::StandardError
          logger.debug "iam_creds failed with exception #{$ERROR_INFO.message}:" \
            "#{$ERROR_POSITION.join("\n")}"
          {}
        end
      end

      private

      # fetch_credentials logic copied from Fog
      def fetch_credentials
        connection = Excon.new(INSTANCE_METADATA_HOST)
        role_name = connection.get(
          :path => INSTANCE_METADATA_PATH, :expects => 200
        ).body
        role_data = connection.get(
          :path => INSTANCE_METADATA_PATH + role_name, :expects => 200
        ).body

        session = JSON.parse(role_data)
        credentials = {}
        credentials[:aws_access_key_id] = session["AccessKeyId"]
        credentials[:aws_secret_access_key] = session["SecretAccessKey"]
        credentials[:aws_session_token] = session["Token"]
        credentials[:aws_credentials_expire_at] = Time.xmlschema session["Expiration"]
        # these indicate the metadata service is unavailable or has no profile setup
        credentials
      end
    end
  end
end
