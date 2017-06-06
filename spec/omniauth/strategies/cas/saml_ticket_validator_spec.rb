require 'spec_helper'

describe OmniAuth::Strategies::CAS::SamlTicketValidator do
  let(:strategy) do
    double('strategy',
      service_validate_url: 'https://example.org/samlValidate'
    )
  end

  let(:provider_options) do
    double('provider_options',
      disable_ssl_verification?: false,
      ca_path: '/etc/ssl/certsZOMG'
    )
  end

  let(:validator) do
    OmniAuth::Strategies::CAS::SamlTicketValidator.new( strategy, provider_options, '/foo', nil )
  end

  describe '#call' do
    before do
      stub_request(:post, 'https://example.org/samlValidate?')
        .to_return(status: 200, body: '')
    end

    subject { validator.call }

    it 'returns itself' do
      expect(subject).to eq validator
    end

    it 'uses the configured CA path' do
      subject
      expect(provider_options).to have_received :ca_path
    end
  end

  describe '#user_info' do
    let(:ok_fixture) do
      File.expand_path(File.join(File.dirname(__FILE__), '../../../fixtures/saml_success.xml'))
    end
    let(:response_body) { File.read(ok_fixture) }

    before do
      stub_request(:post, 'https://example.org/samlValidate?')
        .to_return(status: 200, body:response_body)
      validator.call
    end

    subject { validator.user_info }

    it 'parses user info from the response' do
      expect(subject).to include 'user' => 'psegel'
    end
  end
end
