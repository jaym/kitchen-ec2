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

require "kitchen/ec2/iam_credentials_fetcher"

describe Kitchen::EC2::IamCredentialsFetcher do
  let(:logger) { double("logger").as_null_object }
  let(:fetcher) { Kitchen::EC2::IamCredentialsFetcher.new(logger) }

  before(:all) do
    Excon.defaults[:mock] = true
  end

  after(:each) do
    Excon.stubs.clear
  end

  it "returns an empty hash on timeout" do
    expect(Net::HTTP).to receive(:get).and_raise(Timeout::Error)
    expect(logger).to receive(:debug)
    expect(fetcher.iam_creds).to eq({})
  end

  it "parses the response correctly" do
    expect(Net::HTTP).to receive(:get).and_return("")
    Excon.stub(
      { :path => Kitchen::EC2::IamCredentialsFetcher::INSTANCE_METADATA_PATH },
      { :body => "role_name", :status => 200 }
    )
    json = <<-JSON
      {
        "AccessKeyId": "id",
        "SecretAccessKey": "key",
        "Token": "token",
        "Expiration": "2015-04-19T12:59:23Z"
      }
    JSON
    Excon.stub(
      { :path => Kitchen::EC2::IamCredentialsFetcher::INSTANCE_METADATA_PATH + "role_name" },
      { :body => json, :status => 200 }
    )
    expect(fetcher.iam_creds).to eq(
      :aws_access_key_id => "id",
      :aws_secret_access_key => "key",
      :aws_session_token => "token",
      :aws_credentials_expire_at => Time.parse("2015-04-19 12:59:23 UTC")
    )
  end
end
