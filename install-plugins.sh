#!/bin/bash

PluginDir = "~/.idapro/plugins"
if [[ ! -d ${PluginDir} ]]; then
    echo "Creating plugins directory for IDA at ${PluginDir}"
    mkdir -p ${PluginDir}
fi

# copy the plugins
cp -r plugins/* ${PluginDir}

# copy supporting files
mkdir -p ${PluginDir}/ida-swift 2>/dev/null
cp -r dwarf tools ${PluginDir}/ida-swift

