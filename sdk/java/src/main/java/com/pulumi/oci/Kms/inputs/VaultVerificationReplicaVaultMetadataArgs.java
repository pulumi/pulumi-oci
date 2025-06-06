// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class VaultVerificationReplicaVaultMetadataArgs extends com.pulumi.resources.ResourceArgs {

    public static final VaultVerificationReplicaVaultMetadataArgs Empty = new VaultVerificationReplicaVaultMetadataArgs();

    @Import(name="idcsAccountNameUrl", required=true)
    private Output<String> idcsAccountNameUrl;

    public Output<String> idcsAccountNameUrl() {
        return this.idcsAccountNameUrl;
    }

    @Import(name="privateEndpointId", required=true)
    private Output<String> privateEndpointId;

    public Output<String> privateEndpointId() {
        return this.privateEndpointId;
    }

    @Import(name="vaultType", required=true)
    private Output<String> vaultType;

    public Output<String> vaultType() {
        return this.vaultType;
    }

    private VaultVerificationReplicaVaultMetadataArgs() {}

    private VaultVerificationReplicaVaultMetadataArgs(VaultVerificationReplicaVaultMetadataArgs $) {
        this.idcsAccountNameUrl = $.idcsAccountNameUrl;
        this.privateEndpointId = $.privateEndpointId;
        this.vaultType = $.vaultType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VaultVerificationReplicaVaultMetadataArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VaultVerificationReplicaVaultMetadataArgs $;

        public Builder() {
            $ = new VaultVerificationReplicaVaultMetadataArgs();
        }

        public Builder(VaultVerificationReplicaVaultMetadataArgs defaults) {
            $ = new VaultVerificationReplicaVaultMetadataArgs(Objects.requireNonNull(defaults));
        }

        public Builder idcsAccountNameUrl(Output<String> idcsAccountNameUrl) {
            $.idcsAccountNameUrl = idcsAccountNameUrl;
            return this;
        }

        public Builder idcsAccountNameUrl(String idcsAccountNameUrl) {
            return idcsAccountNameUrl(Output.of(idcsAccountNameUrl));
        }

        public Builder privateEndpointId(Output<String> privateEndpointId) {
            $.privateEndpointId = privateEndpointId;
            return this;
        }

        public Builder privateEndpointId(String privateEndpointId) {
            return privateEndpointId(Output.of(privateEndpointId));
        }

        public Builder vaultType(Output<String> vaultType) {
            $.vaultType = vaultType;
            return this;
        }

        public Builder vaultType(String vaultType) {
            return vaultType(Output.of(vaultType));
        }

        public VaultVerificationReplicaVaultMetadataArgs build() {
            if ($.idcsAccountNameUrl == null) {
                throw new MissingRequiredPropertyException("VaultVerificationReplicaVaultMetadataArgs", "idcsAccountNameUrl");
            }
            if ($.privateEndpointId == null) {
                throw new MissingRequiredPropertyException("VaultVerificationReplicaVaultMetadataArgs", "privateEndpointId");
            }
            if ($.vaultType == null) {
                throw new MissingRequiredPropertyException("VaultVerificationReplicaVaultMetadataArgs", "vaultType");
            }
            return $;
        }
    }

}
