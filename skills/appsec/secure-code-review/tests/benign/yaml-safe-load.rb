require 'yaml'

# BENIGN: safe_load returns plain data and disables aliases.
raw_settings = params[:settings].to_s
settings = YAML.safe_load(
  raw_settings,
  permitted_classes: [],
  permitted_symbols: [],
  aliases: false
)

puts settings.fetch('theme', 'light')
