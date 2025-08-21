#!/bin/bash

# Use $HOME for proper expansion
PluginDir="${HOME}/.idapro/plugins"

if [ ! -d "${PluginDir}" ]; then
    echo "Creating plugins directory for IDA at ${PluginDir}"
    mkdir -p "${PluginDir}"
fi

echo "Copying plugins to ${PluginDir}"
# copy the plugins
cp -r plugins/* "${PluginDir}/"


echo "Installation complete!"

