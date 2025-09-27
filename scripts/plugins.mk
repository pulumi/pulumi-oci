# Install Pulumi and plugins required at build time.
install_plugins: .make/install_plugins
.make/install_plugins: export PULUMI_HOME := $(WORKING_DIR)/.pulumi
.make/install_plugins:
	pulumi plugin install resource std 1.6.2
	pulumi plugin install converter terraform 1.0.16
	pulumi plugin install resource tls 4.1.0
	pulumi plugin install resource github 4.10.0
	pulumi plugin install resource kubernetes 3.17.0
	pulumi plugin install resource random 4.4.1
	@touch $@
.PHONY: install_plugins
