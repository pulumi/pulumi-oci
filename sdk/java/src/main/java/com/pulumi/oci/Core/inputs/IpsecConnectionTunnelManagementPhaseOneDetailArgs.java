// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class IpsecConnectionTunnelManagementPhaseOneDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final IpsecConnectionTunnelManagementPhaseOneDetailArgs Empty = new IpsecConnectionTunnelManagementPhaseOneDetailArgs();

    @Import(name="customAuthenticationAlgorithm")
    private @Nullable Output<String> customAuthenticationAlgorithm;

    public Optional<Output<String>> customAuthenticationAlgorithm() {
        return Optional.ofNullable(this.customAuthenticationAlgorithm);
    }

    @Import(name="customDhGroup")
    private @Nullable Output<String> customDhGroup;

    public Optional<Output<String>> customDhGroup() {
        return Optional.ofNullable(this.customDhGroup);
    }

    @Import(name="customEncryptionAlgorithm")
    private @Nullable Output<String> customEncryptionAlgorithm;

    public Optional<Output<String>> customEncryptionAlgorithm() {
        return Optional.ofNullable(this.customEncryptionAlgorithm);
    }

    @Import(name="isCustomPhaseOneConfig")
    private @Nullable Output<Boolean> isCustomPhaseOneConfig;

    public Optional<Output<Boolean>> isCustomPhaseOneConfig() {
        return Optional.ofNullable(this.isCustomPhaseOneConfig);
    }

    @Import(name="isIkeEstablished")
    private @Nullable Output<Boolean> isIkeEstablished;

    public Optional<Output<Boolean>> isIkeEstablished() {
        return Optional.ofNullable(this.isIkeEstablished);
    }

    @Import(name="lifetime")
    private @Nullable Output<String> lifetime;

    public Optional<Output<String>> lifetime() {
        return Optional.ofNullable(this.lifetime);
    }

    @Import(name="negotiatedAuthenticationAlgorithm")
    private @Nullable Output<String> negotiatedAuthenticationAlgorithm;

    public Optional<Output<String>> negotiatedAuthenticationAlgorithm() {
        return Optional.ofNullable(this.negotiatedAuthenticationAlgorithm);
    }

    @Import(name="negotiatedDhGroup")
    private @Nullable Output<String> negotiatedDhGroup;

    public Optional<Output<String>> negotiatedDhGroup() {
        return Optional.ofNullable(this.negotiatedDhGroup);
    }

    @Import(name="negotiatedEncryptionAlgorithm")
    private @Nullable Output<String> negotiatedEncryptionAlgorithm;

    public Optional<Output<String>> negotiatedEncryptionAlgorithm() {
        return Optional.ofNullable(this.negotiatedEncryptionAlgorithm);
    }

    @Import(name="remainingLifetime")
    private @Nullable Output<String> remainingLifetime;

    public Optional<Output<String>> remainingLifetime() {
        return Optional.ofNullable(this.remainingLifetime);
    }

    @Import(name="remainingLifetimeLastRetrieved")
    private @Nullable Output<String> remainingLifetimeLastRetrieved;

    public Optional<Output<String>> remainingLifetimeLastRetrieved() {
        return Optional.ofNullable(this.remainingLifetimeLastRetrieved);
    }

    private IpsecConnectionTunnelManagementPhaseOneDetailArgs() {}

    private IpsecConnectionTunnelManagementPhaseOneDetailArgs(IpsecConnectionTunnelManagementPhaseOneDetailArgs $) {
        this.customAuthenticationAlgorithm = $.customAuthenticationAlgorithm;
        this.customDhGroup = $.customDhGroup;
        this.customEncryptionAlgorithm = $.customEncryptionAlgorithm;
        this.isCustomPhaseOneConfig = $.isCustomPhaseOneConfig;
        this.isIkeEstablished = $.isIkeEstablished;
        this.lifetime = $.lifetime;
        this.negotiatedAuthenticationAlgorithm = $.negotiatedAuthenticationAlgorithm;
        this.negotiatedDhGroup = $.negotiatedDhGroup;
        this.negotiatedEncryptionAlgorithm = $.negotiatedEncryptionAlgorithm;
        this.remainingLifetime = $.remainingLifetime;
        this.remainingLifetimeLastRetrieved = $.remainingLifetimeLastRetrieved;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IpsecConnectionTunnelManagementPhaseOneDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IpsecConnectionTunnelManagementPhaseOneDetailArgs $;

        public Builder() {
            $ = new IpsecConnectionTunnelManagementPhaseOneDetailArgs();
        }

        public Builder(IpsecConnectionTunnelManagementPhaseOneDetailArgs defaults) {
            $ = new IpsecConnectionTunnelManagementPhaseOneDetailArgs(Objects.requireNonNull(defaults));
        }

        public Builder customAuthenticationAlgorithm(@Nullable Output<String> customAuthenticationAlgorithm) {
            $.customAuthenticationAlgorithm = customAuthenticationAlgorithm;
            return this;
        }

        public Builder customAuthenticationAlgorithm(String customAuthenticationAlgorithm) {
            return customAuthenticationAlgorithm(Output.of(customAuthenticationAlgorithm));
        }

        public Builder customDhGroup(@Nullable Output<String> customDhGroup) {
            $.customDhGroup = customDhGroup;
            return this;
        }

        public Builder customDhGroup(String customDhGroup) {
            return customDhGroup(Output.of(customDhGroup));
        }

        public Builder customEncryptionAlgorithm(@Nullable Output<String> customEncryptionAlgorithm) {
            $.customEncryptionAlgorithm = customEncryptionAlgorithm;
            return this;
        }

        public Builder customEncryptionAlgorithm(String customEncryptionAlgorithm) {
            return customEncryptionAlgorithm(Output.of(customEncryptionAlgorithm));
        }

        public Builder isCustomPhaseOneConfig(@Nullable Output<Boolean> isCustomPhaseOneConfig) {
            $.isCustomPhaseOneConfig = isCustomPhaseOneConfig;
            return this;
        }

        public Builder isCustomPhaseOneConfig(Boolean isCustomPhaseOneConfig) {
            return isCustomPhaseOneConfig(Output.of(isCustomPhaseOneConfig));
        }

        public Builder isIkeEstablished(@Nullable Output<Boolean> isIkeEstablished) {
            $.isIkeEstablished = isIkeEstablished;
            return this;
        }

        public Builder isIkeEstablished(Boolean isIkeEstablished) {
            return isIkeEstablished(Output.of(isIkeEstablished));
        }

        public Builder lifetime(@Nullable Output<String> lifetime) {
            $.lifetime = lifetime;
            return this;
        }

        public Builder lifetime(String lifetime) {
            return lifetime(Output.of(lifetime));
        }

        public Builder negotiatedAuthenticationAlgorithm(@Nullable Output<String> negotiatedAuthenticationAlgorithm) {
            $.negotiatedAuthenticationAlgorithm = negotiatedAuthenticationAlgorithm;
            return this;
        }

        public Builder negotiatedAuthenticationAlgorithm(String negotiatedAuthenticationAlgorithm) {
            return negotiatedAuthenticationAlgorithm(Output.of(negotiatedAuthenticationAlgorithm));
        }

        public Builder negotiatedDhGroup(@Nullable Output<String> negotiatedDhGroup) {
            $.negotiatedDhGroup = negotiatedDhGroup;
            return this;
        }

        public Builder negotiatedDhGroup(String negotiatedDhGroup) {
            return negotiatedDhGroup(Output.of(negotiatedDhGroup));
        }

        public Builder negotiatedEncryptionAlgorithm(@Nullable Output<String> negotiatedEncryptionAlgorithm) {
            $.negotiatedEncryptionAlgorithm = negotiatedEncryptionAlgorithm;
            return this;
        }

        public Builder negotiatedEncryptionAlgorithm(String negotiatedEncryptionAlgorithm) {
            return negotiatedEncryptionAlgorithm(Output.of(negotiatedEncryptionAlgorithm));
        }

        public Builder remainingLifetime(@Nullable Output<String> remainingLifetime) {
            $.remainingLifetime = remainingLifetime;
            return this;
        }

        public Builder remainingLifetime(String remainingLifetime) {
            return remainingLifetime(Output.of(remainingLifetime));
        }

        public Builder remainingLifetimeLastRetrieved(@Nullable Output<String> remainingLifetimeLastRetrieved) {
            $.remainingLifetimeLastRetrieved = remainingLifetimeLastRetrieved;
            return this;
        }

        public Builder remainingLifetimeLastRetrieved(String remainingLifetimeLastRetrieved) {
            return remainingLifetimeLastRetrieved(Output.of(remainingLifetimeLastRetrieved));
        }

        public IpsecConnectionTunnelManagementPhaseOneDetailArgs build() {
            return $;
        }
    }

}
