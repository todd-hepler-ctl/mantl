# the security-setup script

The `security-setup` script is located in the root of the project. It
will set up authentication and authorization for you, as described in
the component
documentation \<../components/index\>. When components are updated, you
can run it again, as many times as you want. It will only set the
variables it needs to.

After you've set up security with the script, you can include it in your
playbook runs by specifying the `-e` or `--extra-vars` option, like so:

    ansible-playbook --extra-vars=@security.yml your_playbook.yml

## Certificates

If not present, `security-setup` will create a root CA to generate
certificates from. If you want to use your own CA, add the key in
`ssl/private/cakey.pem` and the cert in `ssl/cacert.pem`.

If you have your own (self)signed certificates, you can put them in
`ssl/private/your.key.pem` and `ssl/certs/your.cert.pem`. Just override
the locations the script generates (for example the consul key and cert
would be `ssl/private/consul.key.pem` and `ssl/certs/consul.cert.pem`,
respectively) and they'll be used instead of the generated files, and
not overridden.

In the event that you need to regenerate a certificate, rename or delete
the appropriate CSR and certificate from the `certs` folder and the
private component in `private` and re-run `security-setup`.

## Boolean Options

Options like `--mesos` take a boolean argument. You can use the
following values in these options:

<table>
<thead>
<tr class="header">
<th>Value</th>
<th>Interpreted as</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>t</td>
<td>True</td>
</tr>
<tr class="even">
<td>T</td>
<td>True</td>
</tr>
<tr class="odd">
<td>1</td>
<td>True</td>
</tr>
<tr class="even">
<td>True</td>
<td>True</td>
</tr>
<tr class="odd">
<td>true</td>
<td>True</td>
</tr>
<tr class="even">
<td>f</td>
<td>False</td>
</tr>
<tr class="odd">
<td>F</td>
<td>False</td>
</tr>
<tr class="even">
<td>0</td>
<td>False</td>
</tr>
<tr class="odd">
<td>False</td>
<td>False</td>
</tr>
<tr class="even">
<td>false</td>
<td>False</td>
</tr>
</tbody>
</table>

## Options

### security-setup

  - \-h, --help  
    Show the help message and exit

  - \--no-verify-certificates  
    By default `security-setup` will verify certificates when it runs,
    to make sure they're still valid. However, do the way OpenSSL
    handles verification errors this check may be somewhat brittle. If
    this gives you trouble, disable it by specifying this flag.

  - \--change-admin-password  
    `security-setup` will normally ask for an admin password only if it
    doesn't already have one. Setting this option will cause
    `security-setup` to re-prompt for the admin password.

  - \--enable  
    Enable (or disable, if False) all security. This overrides all other
    options.
    
    Default: `True`

  - \--use-private-docker-registry  
    Provide (or skip, if False) credentials for a private Docker
    registry.
    
    Default: `False`

  - \--consul  
    Enable Consul security. This overrides all other Consul options.
    
    Default: `True`

  - \--mesos  
    Enable Mesos security. This overrides all other Mesos options.
    
    Default: `True`

  - \--marathon  
    Enable Marathon security. This overrides all other Marathon options.
    
    Default: `True`

  - \--iptables  
    Use iptables rules. This overrides all other options related to
    iptables.
    
    Default: `True`

  - \--cert-country  
    Country to be used for certificates
    
    default: `US`

  - \--cert-state  
    State/region to be used for certificates
    
    default: `New York`

  - \--cert-locality  
    Locality to be used for certificates
    
    default: `Anytown`

  - \--cert-organization  
    Organization to be used for certificates
    
    default: `Example Company Inc`

  - \--cert-unit  
    Operational unit to be used for certificates
    
    default: `Operations`

  - \--cert-email  
    Contact email to use for certificates
    
    default: `operations@example.com`

  - \--consul-location  
    Location Consul will be accessed at. This will be used as the common
    name in the Consul certificate.
    
    default: `consul.example.com`

  - \--nginx-location  
    Location nginx will be accessed at. This will be used as the common
    name in the nginx certificate.
    
    default: `nginx.example.com`

  - \--consul-auth  
    enable Consul authentication
    
    default: `True`

  - \--consul-ssl  
    enable Consul SSL
    
    default: `True`

  - \--consul-acl  
    enable Consul ACLs
    
    default: `True`

  - \--mesos-ssl  
    enable Mesos SSL
    
    default: `True`

  - \--mesos-auth  
    enable Mesos authentication
    
    default: `True`

  - \--mesos-framework-auth  
    enable Mesos framework authentication
    
    default: `True`

  - \--mesos-follower-auth  
    enable Mesos follower authentication
    
    default: `True`

  - \--mesos-iptables  
    enable Mesos iptables rules to restrict access
    
    default: `True`

  - \--marathon-ssl  
    enable Marathon SSL
    
    default: `True`

  - \--marathon-auth  
    enable Marathon authentication
    
    default: `True`

  - \--marathon-iptables  
    enable Marathon iptables rules to restrict access
    
    default: `True`

  - \--mantl-api-auth  
    enable Mantl API Mesos credentials
    
    default: `True`
