require 'base64'

# VULNERABLE: request parameter data reaches Ruby native object deserialization.
blob = Base64.decode64(params[:profile_blob].to_s)
profile = Marshal.load(blob)

puts profile[:display_name]
