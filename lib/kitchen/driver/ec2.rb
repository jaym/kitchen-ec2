# -*- encoding: utf-8 -*-
#
# Author:: Fletcher Nichol (<fnichol@nichol.ca>)
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

require "benchmark"
require "json"
require "aws"
require "retryable"
require "kitchen"
require "kitchen/driver/ec2_version"

module Kitchen

  module Driver

    # Amazon EC2 driver for Test Kitchen.
    #
    # @author Fletcher Nichol <fnichol@nichol.ca>
    class Ec2 < Kitchen::Driver::Base # rubocop:disable Metrics/ClassLength

      kitchen_driver_api_version 2

      plugin_version Kitchen::Driver::EC2_VERSION

      default_config :region,             "us-east-1"
      default_config :availability_zone,  nil
      default_config :flavor_id,          nil
      default_config :instance_type,      nil
      default_config :ebs_optimized,      false
      default_config :security_group_ids, nil
      default_config :tags,                "created-by" => "test-kitchen"
      default_config :user_data,          nil
      default_config :private_ip_address, nil
      default_config :iam_profile_name,   nil
      default_config :price,              nil
      default_config :retryable_tries,    60
      default_config :retryable_sleep,    5
      default_config :aws_access_key_id do |driver|
        ENV["AWS_ACCESS_KEY"] || ENV["AWS_ACCESS_KEY_ID"] ||
          driver.iam_creds[:aws_access_key_id]
      end
      default_config :aws_secret_access_key do |driver|
        ENV["AWS_SECRET_KEY"] || ENV["AWS_SECRET_ACCESS_KEY"] ||
          driver.iam_creds[:aws_secret_access_key]
      end
      default_config :aws_session_token do |driver|
        driver.default_aws_session_token
      end
      default_config :aws_ssh_key_id do |_driver|
        ENV["AWS_SSH_KEY_ID"]
      end
      default_config :image_id do |driver|
        driver.default_ami
      end
      default_config :username, nil

      default_config :interface, nil
      default_config :associate_public_ip do |driver|
        driver.default_public_ip_association
      end

      required_config :aws_access_key_id
      required_config :aws_secret_access_key
      required_config :aws_ssh_key_id
      required_config :image_id

      def self.validation_warn(driver, old_key, new_key)
        driver.warn "WARN: The driver[#{driver.class.name}] config key `#{old_key}` " \
          "is deprecated, please use `#{new_key}`"
      end

      # TODO: remove these in the next major version of TK
      deprecated_configs = [:ebs_volume_size, :ebs_delete_on_termination, :ebs_device_name]
      deprecated_configs.each do |d|
        validations[d] = lambda do |attr, val, driver|
          unless val.nil?
            validation_warn(driver, attr, "block_device_mappings")
          end
        end
      end
      validations[:ssh_key] = lambda do |attr, val, driver|
        unless val.nil?
          validation_warn(driver, attr, "transport.ssh_key")
        end
      end
      validations[:ssh_timeout] = lambda do |attr, val, driver|
        unless val.nil?
          validation_warn(driver, attr, "transport.connection_timeout")
        end
      end
      validations[:ssh_retries] = lambda do |attr, val, driver|
        unless val.nil?
          validation_warn(driver, attr, "transport.connection_retries")
        end
      end
      validations[:username] = lambda do |attr, val, driver|
        unless val.nil?
          validation_warn(driver, attr, "transport.username")
        end
      end
      validations[:flavor_id] = lambda do |attr, val, driver|
        unless val.nil?
          validation_warn(driver, attr, "instance_type")
        end
      end

      default_config :block_device_mappings, nil
      validations[:block_device_mappings] = lambda do |_attr, val, _driver|
        unless val.nil?
          val.each do |bdm|
            unless bdm.keys.include?(:ebs_volume_size) &&
                bdm.keys.include?(:ebs_delete_on_termination) &&
                bdm.keys.include?(:ebs_device_name)
              raise "Every :block_device_mapping must include the keys :ebs_volume_size, " \
                ":ebs_delete_on_termination and :ebs_device_name"
            end
          end
        end
      end

      # A lifecycle method that should be invoked when the object is about
      # ready to be used. A reference to an Instance is required as
      # configuration dependant data may be access through an Instance. This
      # also acts as a hook point where the object may wish to perform other
      # last minute checks, validations, or configuration expansions.
      #
      # @param instance [Instance] an associated instance
      # @return [self] itself, for use in chaining
      # @raise [ClientError] if instance parameter is nil
      def finalize_config!(instance)
        super

        if config[:availability_zone].nil?
          config[:availability_zone] = config[:region] + "b"
        end
        if config[:instance_type].nil?
          config[:instance_type] = config[:flavor_id] || "m1.small"
        end

        self
      end

      def create(state) # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
        copy_deprecated_configs(state)
        return if state[:server_id]

        info(Kitchen::Util.outdent!(<<-END))
          Creating <#{state[:server_id]}>...
          If you are not using an account that qualifies under the AWS
          free-tier, you may be charged to run these suites. The charge
          should be minimal, but neither Test Kitchen nor its maintainers
          are responsible for your incurred costs.
        END

        if config[:price]
          # Spot instance when a price is set
          server = submit_spot(state)
        else
          # On-demand instance
          server = submit_server
        end

        state[:server_id] = server.id
        info("EC2 instance <#{state[:server_id]}> created.")
        wait_for do |retries, _exception|
          c = retries * config[:retryable_sleep]
          t = config[:retryable_tries] * config[:retryable_sleep]
          info "Waited #{c}/#{t} for instance <#{state[:server_id]}> to become ready."
          hostname = hostname(server)
          # Euca instances often report ready before they have an IP
          ready = server.status == :running && !hostname.nil? && hostname != "0.0.0.0"
          unless ready
            raise TimeoutError
          end
        end

        info("EC2 instance <#{state[:server_id]}> ready.")
        state[:hostname] = hostname(server)
        instance.transport.connection(state).wait_until_ready
        debug("ec2:create '#{state[:hostname]}'")
      end

      def destroy(state)
        return if state[:server_id].nil?

        server = ec2.instances[state[:server_id]]
        unless server.nil?
          instance.transport.connection(state).close
          server.delete unless server.nil?
        end
        if state[:spot_request_id]
          debug("Deleting spot request <#{state[:server_id]}>")
          ec2.client.cancel_spot_instance_requests(
            :spot_instance_request_ids => [state[:spot_request_id]]
          )
        end
        info("EC2 instance <#{state[:server_id]}> destroyed.")
        state.delete(:server_id)
        state.delete(:hostname)
      end

      def default_ami
        region = amis["regions"][config[:region]]
        region && region[instance.platform.name]
      end

      def default_public_ip_association
        !!config[:subnet_id]
      end

      # If running on an EC2 node there are 3 possible scenarios:
      #  1) The user has supplied the session token as an environment variable
      #  2) The user has manually set access key/secret - don't use the session token from
      #    the metadata service, only auth with key/secret supplied
      #  3) The user has not set the access key/secret - because we default these values
      #    we cannot tell if these have not been set.  So we do our best guess by checking
      #    if the current value is the same as what is returned from the metadata service.
      #    If they are the same we assume no user values have been set and we use the
      #    metadata service values.
      def default_aws_session_token
        env = ENV["AWS_SESSION_TOKEN"] || ENV["AWS_TOKEN"]
        if config[:aws_secret_access_key] == iam_creds[:aws_secret_access_key] &&
            config[:aws_access_key_id] == iam_creds[:aws_access_key_id]
          env ||= iam_creds[:aws_session_token]
        end
        env
      end

      def iam_credentials_fetcher
        @fetcher ||= Kitchen::EC2::IamCredentialsFetcher.new(logger)
      end

      # Simple delegate to the iam credentials fetcher
      def iam_creds
        @fetcher.iam_creds
      end

      private

      # This copies transport config from the current config object into the
      # state.  This relies on logic in the transport that merges the transport
      # config with the current state object, so its a bad coupling.  But we
      # can get rid of this when we get rid of these deprecated configs!
      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def copy_deprecated_configs(state)
        if config[:ssh_timeout]
          state[:connection_timeout] = config[:ssh_timeout]
        end
        if config[:ssh_retries]
          state[:connection_retries] = config[:ssh_retries]
        end
        if config[:username]
          state[:username] = config[:username]
        elsif instance.transport[:username] == instance.transport.class.defaults[:username]
          # If the transport has the default username, copy it from amis.json
          # This duplicated old behavior but I hate amis.json
          ami_username = amis["usernames"][instance.platform.name]
          state[:username] = ami_username if ami_username
        end
        if config[:ssh_key]
          state[:ssh_key] = config[:ssh_key]
        end
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      def ec2
        @ec2 ||= AWS::EC2.new(
          :config => AWS.config(
            :access_key_id        => config[:aws_access_key_id],
            :secret_access_key    => config[:aws_secret_access_key],
            :region               => config[:region],
            :session_token        => config[:aws_session_token]
          )
        )
      end

      # Fog AWS helper for creating the instance
      def submit_server
        debug("Creating EC2 Instance..")
        instance_data = ec2_instance_data
        server = ec2.instances.create(instance_data)
        info("Instance <#{server.id}> requested.")
        tag_server(server)
      end

      def submit_spot(state) # rubocop:disable Metrics/AbcSize
        debug("Creating EC2 Spot Instance..")
        request_data = {}
        request_data[:spot_price] = config[:price].to_s

        request_data = transform_spot_request(request_data, ec2_instance_data)

        response = ec2.client.request_spot_instances(request_data)
        spot_request_id = response[:spot_instance_request_set][0][:spot_instance_request_id]
        # deleting the instance cancels the request, but deleting the request
        # does not affect the instance
        state[:spot_request_id] = spot_request_id
        server = nil
        wait_for do |retries, _exception|
          c = retries * config[:retryable_sleep]
          t = config[:retryable_tries] * config[:retryable_sleep]
          info "Waited #{c}/#{t} for spot request <#{spot_request_id}> to become fulfilled."
          server = ec2.instances.filter("spot-instance-request-id", spot_request_id).to_a[0]
          raise TimeoutError if server.nil?
        end
        info("Instance <#{server.id}> requested.")
        tag_server(server)
      end

      # the spot request has different keys than the instance request
      def transform_spot_request(request_data, instance_data)
        # availability_zone -> availability_zone_group
        request_data[:availability_zone_group] = instance_data.delete(:availability_zone)

        # subnet => subnet_id
        subnet = instance_data.delete(:subnet)
        instance_data[:subnet_id] = subnet if subnet

        # iam_instance_profile -> iam_instance_profile.name
        iam_profile = instance_data.delete(:iam_instance_profile)
        instance_data[:iam_instance_profile] = { :name => iam_profile } if iam_profile

        # associate_public_ip_address must be tagged to the
        unless instance_data[:associate_public_ip_address].nil?
          instance_data[:network_interfaces] = [{
            :device_index => 0,
            :associate_public_ip_address => instance_data.delete(:associate_public_ip_address)
          }]
        end

        # all this data goes into launch_specification instead of the root level
        request_data[:launch_specification] = instance_data
        request_data
      end

      def tag_server(server)
        config[:tags].each do |k, v|
          server.tag(k, :value => v)
        end
        server
      end

      # Transform the provided config into the hash to send to AWS.  Some fields
      # can be passed in null, others need to be ommitted if they are null
      def ec2_instance_data
        i = {
          :availability_zone            => config[:availability_zone],
          :instance_type                => config[:instance_type],
          :ebs_optimized                => config[:ebs_optimized],
          :image_id                     => config[:image_id],
          :key_name                     => config[:aws_ssh_key_id],
          :subnet                       => config[:subnet_id],
          :iam_instance_profile         => config[:iam_profile_name],
          :associate_public_ip_address  => config[:associate_public_ip]
        }
        i[:block_device_mappings] = block_device_mappings unless block_device_mappings.empty?
        i[:security_group_ids] = config[:security_group_ids] if config[:security_group_ids]
        i[:user_data] = prepared_user_data if prepared_user_data
        i
      end

      def amis
        @amis ||= begin
          json_file = File.join(File.dirname(__FILE__),
            %w[.. .. .. data amis.json])
          JSON.load(IO.read(json_file))
        end
      end

      #
      # Ordered mapping from config name to Fog name.  Ordered by preference
      # when looking up hostname.
      #
      INTERFACE_TYPES =
        {
          "dns" => "dns_name",
          "public" => "public_ip_address",
          "private" => "private_ip_address"
        }

      #
      # Lookup hostname of provided server.  If interface_type is provided use
      # that interface to lookup hostname.  Otherwise, try ordered list of
      # options.
      #
      def hostname(server, interface_type = nil)
        if interface_type
          interface_type = INTERFACE_TYPES.fetch(interface_type) do
            raise Kitchen::UserError, "Invalid interface [#{interface_type}]"
          end
          server.send(interface_type)
        else
          potential_hostname = nil
          INTERFACE_TYPES.values.each do |type|
            potential_hostname ||= server.send(type)
          end
          potential_hostname
        end
      end

      # Transforms the provided config into the appropriate hash for creating a BDM
      # in AWS
      def block_device_mappings # rubocop:disable all
        return @bdms if @bdms
        bdms = config[:block_device_mappings] || []
        if bdms.nil? || bdms.empty?
          if config[:ebs_volume_size] || config.fetch(:ebs_delete_on_termination, nil) ||
              config[:ebs_device_name] || config[:ebs_volume_type]
            # If the user didn't supply block_device_mappings but did supply
            # the old configs, copy them into the block_device_mappings array correctly
            bdms << {
              :ebs_volume_size => config[:ebs_volume_size] || 8,
              :ebs_delete_on_termination => config.fetch(:ebs_delete_on_termination, true),
              :ebs_device_name => config[:ebs_device_name] || "/dev/sda1",
              :ebs_volume_type => config[:ebs_volume_type] || "standard"
            }
          end
        end

        # Convert the provided keys to what AWS expects
        bdms = bdms.map do |bdm|
          b = {
            :ebs => {
              :volume_size           => bdm[:ebs_volume_size],
              :volume_type           => bdm[:ebs_volume_type],
              :delete_on_termination => bdm[:ebs_delete_on_termination]
            },
            :device_name             => bdm[:ebs_device_name]
          }
          b[:ebs][:snapshot_id] = bdm[:ebs_snapshot_id] if bdm[:ebs_snapshot_id]
          b[:virtual_name] = bdm[:ebs_virtual_name] if bdm[:ebs_virtual_name]
          b
        end

        debug_if_root_device(bdms)

        @bdms = bdms
      end

      # If the provided bdms match the root device in the AMI, emit log that
      # states this
      def debug_if_root_device(bdms)
        image_id = config[:image_id]
        image = ec2.images[image_id]
        if image.nil?
          # Not raising here because AWS will give a more meaningful message
          # when we try to create the instance
          return
        end
        root_device_name = image.root_device_name
        bdms.find { |bdm|
          if bdm[:device_name] == root_device_name
            info("Overriding root device [#{root_device_name}] from image [#{image_id}]")
          end
        }
      end

      def prepared_user_data
        # If user_data is a file reference, lets read it as such
        @user_data ||= unless config[:user_data].nil?
          if File.file?(config[:user_data])
            config[:user_data] = File.read(config[:user_data])
          end
        end
      end

      # Accepts a block with parameters |retries, exception| and sets it into a retryable block
      # The block should raise TimeoutError if it needs to continue waiting
      def wait_for(&block)
        Retryable.retryable(
          :tries => config[:retryable_tries],
          :sleep => config[:retryable_sleep],
          :on => TimeoutError,
          &block
        )
      end

    end
  end
end
