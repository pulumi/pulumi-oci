// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Kms.inputs.KeyVersionReplicaDetailArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class KeyVersionState extends com.pulumi.resources.ResourceArgs {

    public static final KeyVersionState Empty = new KeyVersionState();

    /**
     * The OCID of the compartment that contains this key version.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment that contains this key version.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A boolean that will be true when key version is primary, and will be false when key version is a replica from a primary key version.
     * 
     */
    @Import(name="isPrimary")
    private @Nullable Output<Boolean> isPrimary;

    /**
     * @return A boolean that will be true when key version is primary, and will be false when key version is a replica from a primary key version.
     * 
     */
    public Optional<Output<Boolean>> isPrimary() {
        return Optional.ofNullable(this.isPrimary);
    }

    /**
     * The OCID of the key.
     * 
     */
    @Import(name="keyId")
    private @Nullable Output<String> keyId;

    /**
     * @return The OCID of the key.
     * 
     */
    public Optional<Output<String>> keyId() {
        return Optional.ofNullable(this.keyId);
    }

    @Import(name="keyVersionId")
    private @Nullable Output<String> keyVersionId;

    public Optional<Output<String>> keyVersionId() {
        return Optional.ofNullable(this.keyVersionId);
    }

    /**
     * The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
     * 
     */
    @Import(name="managementEndpoint")
    private @Nullable Output<String> managementEndpoint;

    /**
     * @return The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
     * 
     */
    public Optional<Output<String>> managementEndpoint() {
        return Optional.ofNullable(this.managementEndpoint);
    }

    /**
     * The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
     * 
     */
    @Import(name="publicKey")
    private @Nullable Output<String> publicKey;

    /**
     * @return The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
     * 
     */
    public Optional<Output<String>> publicKey() {
        return Optional.ofNullable(this.publicKey);
    }

    /**
     * KeyVersion replica details
     * 
     */
    @Import(name="replicaDetails")
    private @Nullable Output<List<KeyVersionReplicaDetailArgs>> replicaDetails;

    /**
     * @return KeyVersion replica details
     * 
     */
    public Optional<Output<List<KeyVersionReplicaDetailArgs>>> replicaDetails() {
        return Optional.ofNullable(this.replicaDetails);
    }

    @Import(name="restoredFromKeyId")
    private @Nullable Output<String> restoredFromKeyId;

    public Optional<Output<String>> restoredFromKeyId() {
        return Optional.ofNullable(this.restoredFromKeyId);
    }

    /**
     * The OCID of the key version from which this key version was restored.
     * 
     */
    @Import(name="restoredFromKeyVersionId")
    private @Nullable Output<String> restoredFromKeyVersionId;

    /**
     * @return The OCID of the key version from which this key version was restored.
     * 
     */
    public Optional<Output<String>> restoredFromKeyVersionId() {
        return Optional.ofNullable(this.restoredFromKeyVersionId);
    }

    /**
     * The key version&#39;s current lifecycle state.  Example: `ENABLED`
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The key version&#39;s current lifecycle state.  Example: `ENABLED`
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: &#34;2018-04-03T21:10:29.600Z&#34;
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: &#34;2018-04-03T21:10:29.600Z&#34;
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    @Import(name="timeOfDeletion")
    private @Nullable Output<String> timeOfDeletion;

    /**
     * @return (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeOfDeletion() {
        return Optional.ofNullable(this.timeOfDeletion);
    }

    /**
     * The OCID of the vault that contains this key version.
     * 
     */
    @Import(name="vaultId")
    private @Nullable Output<String> vaultId;

    /**
     * @return The OCID of the vault that contains this key version.
     * 
     */
    public Optional<Output<String>> vaultId() {
        return Optional.ofNullable(this.vaultId);
    }

    private KeyVersionState() {}

    private KeyVersionState(KeyVersionState $) {
        this.compartmentId = $.compartmentId;
        this.isPrimary = $.isPrimary;
        this.keyId = $.keyId;
        this.keyVersionId = $.keyVersionId;
        this.managementEndpoint = $.managementEndpoint;
        this.publicKey = $.publicKey;
        this.replicaDetails = $.replicaDetails;
        this.restoredFromKeyId = $.restoredFromKeyId;
        this.restoredFromKeyVersionId = $.restoredFromKeyVersionId;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeOfDeletion = $.timeOfDeletion;
        this.vaultId = $.vaultId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(KeyVersionState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private KeyVersionState $;

        public Builder() {
            $ = new KeyVersionState();
        }

        public Builder(KeyVersionState defaults) {
            $ = new KeyVersionState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment that contains this key version.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment that contains this key version.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param isPrimary A boolean that will be true when key version is primary, and will be false when key version is a replica from a primary key version.
         * 
         * @return builder
         * 
         */
        public Builder isPrimary(@Nullable Output<Boolean> isPrimary) {
            $.isPrimary = isPrimary;
            return this;
        }

        /**
         * @param isPrimary A boolean that will be true when key version is primary, and will be false when key version is a replica from a primary key version.
         * 
         * @return builder
         * 
         */
        public Builder isPrimary(Boolean isPrimary) {
            return isPrimary(Output.of(isPrimary));
        }

        /**
         * @param keyId The OCID of the key.
         * 
         * @return builder
         * 
         */
        public Builder keyId(@Nullable Output<String> keyId) {
            $.keyId = keyId;
            return this;
        }

        /**
         * @param keyId The OCID of the key.
         * 
         * @return builder
         * 
         */
        public Builder keyId(String keyId) {
            return keyId(Output.of(keyId));
        }

        public Builder keyVersionId(@Nullable Output<String> keyVersionId) {
            $.keyVersionId = keyVersionId;
            return this;
        }

        public Builder keyVersionId(String keyVersionId) {
            return keyVersionId(Output.of(keyVersionId));
        }

        /**
         * @param managementEndpoint The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
         * 
         * @return builder
         * 
         */
        public Builder managementEndpoint(@Nullable Output<String> managementEndpoint) {
            $.managementEndpoint = managementEndpoint;
            return this;
        }

        /**
         * @param managementEndpoint The service endpoint to perform management operations against. Management operations include &#39;Create,&#39; &#39;Update,&#39; &#39;List,&#39; &#39;Get,&#39; and &#39;Delete&#39; operations. See Vault Management endpoint.
         * 
         * @return builder
         * 
         */
        public Builder managementEndpoint(String managementEndpoint) {
            return managementEndpoint(Output.of(managementEndpoint));
        }

        /**
         * @param publicKey The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
         * 
         * @return builder
         * 
         */
        public Builder publicKey(@Nullable Output<String> publicKey) {
            $.publicKey = publicKey;
            return this;
        }

        /**
         * @param publicKey The public key in PEM format. (This value pertains only to RSA and ECDSA keys.)
         * 
         * @return builder
         * 
         */
        public Builder publicKey(String publicKey) {
            return publicKey(Output.of(publicKey));
        }

        /**
         * @param replicaDetails KeyVersion replica details
         * 
         * @return builder
         * 
         */
        public Builder replicaDetails(@Nullable Output<List<KeyVersionReplicaDetailArgs>> replicaDetails) {
            $.replicaDetails = replicaDetails;
            return this;
        }

        /**
         * @param replicaDetails KeyVersion replica details
         * 
         * @return builder
         * 
         */
        public Builder replicaDetails(List<KeyVersionReplicaDetailArgs> replicaDetails) {
            return replicaDetails(Output.of(replicaDetails));
        }

        /**
         * @param replicaDetails KeyVersion replica details
         * 
         * @return builder
         * 
         */
        public Builder replicaDetails(KeyVersionReplicaDetailArgs... replicaDetails) {
            return replicaDetails(List.of(replicaDetails));
        }

        public Builder restoredFromKeyId(@Nullable Output<String> restoredFromKeyId) {
            $.restoredFromKeyId = restoredFromKeyId;
            return this;
        }

        public Builder restoredFromKeyId(String restoredFromKeyId) {
            return restoredFromKeyId(Output.of(restoredFromKeyId));
        }

        /**
         * @param restoredFromKeyVersionId The OCID of the key version from which this key version was restored.
         * 
         * @return builder
         * 
         */
        public Builder restoredFromKeyVersionId(@Nullable Output<String> restoredFromKeyVersionId) {
            $.restoredFromKeyVersionId = restoredFromKeyVersionId;
            return this;
        }

        /**
         * @param restoredFromKeyVersionId The OCID of the key version from which this key version was restored.
         * 
         * @return builder
         * 
         */
        public Builder restoredFromKeyVersionId(String restoredFromKeyVersionId) {
            return restoredFromKeyVersionId(Output.of(restoredFromKeyVersionId));
        }

        /**
         * @param state The key version&#39;s current lifecycle state.  Example: `ENABLED`
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The key version&#39;s current lifecycle state.  Example: `ENABLED`
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: &#34;2018-04-03T21:10:29.600Z&#34;
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time this key version was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: &#34;2018-04-03T21:10:29.600Z&#34;
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeOfDeletion (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfDeletion(@Nullable Output<String> timeOfDeletion) {
            $.timeOfDeletion = timeOfDeletion;
            return this;
        }

        /**
         * @param timeOfDeletion (Updatable) An optional property for the deletion time of the key version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfDeletion(String timeOfDeletion) {
            return timeOfDeletion(Output.of(timeOfDeletion));
        }

        /**
         * @param vaultId The OCID of the vault that contains this key version.
         * 
         * @return builder
         * 
         */
        public Builder vaultId(@Nullable Output<String> vaultId) {
            $.vaultId = vaultId;
            return this;
        }

        /**
         * @param vaultId The OCID of the vault that contains this key version.
         * 
         * @return builder
         * 
         */
        public Builder vaultId(String vaultId) {
            return vaultId(Output.of(vaultId));
        }

        public KeyVersionState build() {
            return $;
        }
    }

}